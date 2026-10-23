/* UDP relay: one session per app source endpoint (address:port; lwIP's pretend pcb
 * accepts any destination) with lazily created IPv4/IPv6 sockets;
 * datagrams are forwarded as they come, sessions expire when idle (shorter for DNS). */
#define _GNU_SOURCE
#include "engine_internal.h"

void relay_udp_release(mpc_session *s, udp_sess *u)
{
    if (u->closed)
        return;
    u->closed = 1;
    if (u->fd4 >= 0) {
        epoll_ctl(s->epfd, EPOLL_CTL_DEL, u->fd4, NULL);
        close(u->fd4);
        u->fd4 = -1;
    }
    if (u->fd6 >= 0) {
        epoll_ctl(s->epfd, EPOLL_CTL_DEL, u->fd6, NULL);
        close(u->fd6);
        u->fd6 = -1;
    }
    if (u->pcb) {
        udp_recv(u->pcb, NULL, NULL);
        udp_remove(u->pcb);
        u->pcb = NULL;
    }
    if (u->prev)
        u->prev->next = u->next;
    else
        s->sessions = u->next;
    if (u->next)
        u->next->prev = u->prev;
    s->n_sessions--;
    MPC_CSET(&s->cap->cnt, udp_sessions_active, s->n_sessions);
    u->next_free = s->free_sessions;
    s->free_sessions = u;
}

static int sess_fd(mpc_session *s, udp_sess *u, int v6)
{
    int *fdp = v6 ? &u->fd6 : &u->fd4;
    if (*fdp >= 0)
        return *fdp;
    int fd = socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0)
        return -1;
    /* Wi-Fi/driver bursts briefly fill the default (~320 KB) send buffer; the relay
     * must not block, so a larger buffer avoids dropping app datagrams (measured:
     * 4169 udp_send_errors at 5k pps with defaults). */
    int sz = 1 << 20;
    setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &sz, sizeof(sz));
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &sz, sizeof(sz));
    ev_tag *tag = v6 ? &u->tag6 : &u->tag4;
    tag->type = EV_UDP;
    tag->ptr = u;
    ep_add(s, fd, EPOLLIN, tag);
    *fdp = fd;
    return fd;
}

static void sess_send(mpc_session *s, udp_sess *u, struct pbuf *p, const ip_addr_t *dst,
                      u16_t dport)
{
    if (dport != 53)
        u->dns_only = 0;
    u->last_active = sys_now();
    int fd = sess_fd(s, u, IP_IS_V6(dst));
    if (fd < 0) {
        MPC_CINC(&s->cap->cnt, udp_send_errors, 1);
        pbuf_free(p);
        return;
    }
    struct sockaddr_storage ss;
    socklen_t sl = to_sockaddr(dst, dport, &ss);
    const void *data = p->payload;
    size_t len = p->tot_len;
    if (p->next) {
        len = pbuf_copy_partial(p, s->relay_buf, (u16_t)(len > RELAY_BUF ? RELAY_BUF : len), 0);
        data = s->relay_buf;
    }
    if (sendto(fd, data, len, MSG_DONTWAIT | MSG_NOSIGNAL, (struct sockaddr *)&ss, sl) < 0)
        MPC_CINC(&s->cap->cnt, udp_send_errors, 1);
    pbuf_free(p);
}

static void on_sess_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p, const ip_addr_t *addr,
                         u16_t port)
{
    udp_sess *u = arg;
    (void)addr;
    (void)port;
    if (!u || u->closed) {
        pbuf_free(p);
        return;
    }
    /* For established pretend sessions lwIP stores the destination in local_ip/port. */
    sess_send(engine_current, u, p, &pcb->local_ip, pcb->local_port);
}

static void on_udp_drop_recv(void *arg, struct udp_pcb *pcb, struct pbuf *p,
                             const ip_addr_t *addr, u16_t port)
{
    (void)arg;
    (void)addr;
    (void)port;
    pbuf_free(p);
    udp_remove(pcb);
}

/* Called by the pretend listener with a new connected pcb for a new app socket.
 * lwIP re-dispatches the same datagram to npcb afterwards ("goto again"), so this
 * callback must not consume p; it only installs the session handler. */
void relay_udp_listen_recv(void *arg, struct udp_pcb *npcb, struct pbuf *p, const ip_addr_t *addr, u16_t port)
{
    mpc_session *s = arg;
    (void)p;
    (void)addr;
    (void)port;
    udp_sess *u = NULL;
    if (s->n_sessions < MAX_UDP_SESSIONS && !atomic_load(&s->stopping))
        u = calloc(1, sizeof(*u));
    if (!u) {
        udp_recv(npcb, on_udp_drop_recv, NULL);
        return;
    }
    u->pcb = npcb;
    u->fd4 = u->fd6 = -1;
    u->dns_only = 1;
    u->last_active = sys_now();
    u->next = s->sessions;
    if (s->sessions)
        s->sessions->prev = u;
    s->sessions = u;
    s->n_sessions++;
    MPC_CINC(&s->cap->cnt, udp_sessions_total, 1);
    MPC_CSET(&s->cap->cnt, udp_sessions_active, s->n_sessions);
    udp_recv(npcb, on_sess_recv, u);
}

void relay_udp_event(mpc_session *s, udp_sess *u, ev_tag *tag)
{
    if (u->closed)
        return;
    int fd = tag == &u->tag6 ? u->fd6 : u->fd4;
    for (int i = 0; i < 64 && fd >= 0 && !u->closed; i++) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        ssize_t n = recvfrom(fd, s->relay_buf, sizeof(s->relay_buf), MSG_DONTWAIT,
                             (struct sockaddr *)&ss, &sl);
        if (n < 0)
            break;
        u->last_active = sys_now();
        struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, (u16_t)n, PBUF_RAM);
        if (!p) {
            MPC_CINC(&s->cap->cnt, forward_alloc_failures, 1);
            continue;
        }
        memcpy(p->payload, s->relay_buf, (size_t)n);
        ip_addr_t src;
        u16_t sport;
        from_sockaddr(&ss, &src, &sport);
        if (udp_sendfrom(u->pcb, p, &src, sport) != ERR_OK)
            MPC_CINC(&s->cap->cnt, forwarding_errors, 1);
        pbuf_free(p);
    }
}

void relay_udp_sweep(mpc_session *s)
{
    uint32_t now = sys_now();
    for (udp_sess *u = s->sessions, *nx; u; u = nx) {
        nx = u->next;
        uint32_t idle = now - u->last_active;
        if (idle > (u->dns_only ? UDP_DNS_IDLE_MS : UDP_IDLE_MS))
            relay_udp_release(s, u);
    }
}

