/* Forwarding engine. All lwIP calls happen on the single engine thread
 * (lwIP NO_SYS=1). Outbound sockets bypass the VPN because the app excludes its
 * own UID from the VPN (see docs/DECISIONS.md ADR-006), so no per-flow JNI
 * protect() call is needed. */
#define _GNU_SOURCE
#include "mpc/engine.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#undef TCP_MSS /* glibc/bionic define it; lwIP config defines its own */
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/timerfd.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

#include "lwip/init.h"
#include "lwip/ip.h"
#include "lwip/ip4_frag.h"
#include "lwip/ip6_frag.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/priv/tcp_priv.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"

#define MAX_EVENTS 128
#define TUN_READ_BATCH 128
#define SOCK_READ_BUDGET (256 * 1024)
#define RELAY_BUF (64 * 1024)
#define MAX_TCP_CONNS 8192
#define MAX_UDP_SESSIONS 4096
#define UDP_IDLE_MS 60000u
#define UDP_DNS_IDLE_MS 15000u

/* ------------------------------------------------------------------ lwIP port */

u32_t sys_now(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (u32_t)((uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u);
}

unsigned int lwip_port_rand(void)
{
    static unsigned int s;
    if (!s)
        s = (unsigned int)mpc_now_boottime_ns() | 1u;
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    return s;
}

/* ------------------------------------------------------------------ types */

enum { EV_TUN = 1, EV_TIMER, EV_CTL, EV_UIDRESP, EV_TCP, EV_UDP };

typedef struct {
    int type;
    void *ptr;
} ev_tag;

typedef struct tcp_conn {
    ev_tag tag;
    struct tcp_pcb *pcb;
    int fd;
    uint32_t ev_mask;
    uint8_t connected, closed, aborted, app_eof, sock_eof, sock_wr_shut, want_in, want_out;
    struct pbuf *q; /* app -> socket data not yet written (not yet tcp_recved) */
    struct tcp_conn *prev, *next;
    struct tcp_conn *next_free;
} tcp_conn;

typedef struct udp_sess {
    ev_tag tag4, tag6;
    struct udp_pcb *pcb;
    int fd4, fd6;
    uint32_t last_active;
    uint8_t closed, dns_only;
    struct udp_sess *prev, *next;
    struct udp_sess *next_free;
} udp_sess;

struct mpc_session {
    mpc_capture *cap;
    int tun_fd;
    uint32_t mtu;
    int epfd, timer_fd, ctl_fd;
    pthread_t thread;
    int thread_started;
    _Atomic int stopping;
    int stopped;
    int tap; /* engine-thread copy of cap->tap_enabled, cleared at stop */
    struct netif netif;
    struct tcp_pcb *tcp_listener;
    struct udp_pcb *udp_listener;
    tcp_conn *conns;
    udp_sess *sessions;
    tcp_conn *free_conns;
    udp_sess *free_sessions;
    uint32_t n_conns, n_sessions;
    struct pbuf *spare; /* pre-allocated pbuf for the next TUN read */
    uint8_t relay_buf[RELAY_BUF];
    ev_tag tun_tag, timer_tag, ctl_tag, uid_tag;
    uint32_t ticks;
    pthread_mutex_t stop_lock;
};

static _Atomic int g_engine_active; /* lwIP has global state: one engine per process */

/* ------------------------------------------------------------------ helpers */

static int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL);
    return fl < 0 ? -1 : fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static void ep_add(mpc_session *s, int fd, uint32_t events, ev_tag *tag)
{
    struct epoll_event ev = {.events = events, .data.ptr = tag};
    epoll_ctl(s->epfd, EPOLL_CTL_ADD, fd, &ev);
}

static void ep_mod(mpc_session *s, int fd, uint32_t events, ev_tag *tag)
{
    struct epoll_event ev = {.events = events, .data.ptr = tag};
    epoll_ctl(s->epfd, EPOLL_CTL_MOD, fd, &ev);
}

static socklen_t to_sockaddr(const ip_addr_t *ip, u16_t port, struct sockaddr_storage *ss)
{
    memset(ss, 0, sizeof(*ss));
    if (IP_IS_V6(ip)) {
        struct sockaddr_in6 *a = (struct sockaddr_in6 *)ss;
        a->sin6_family = AF_INET6;
        a->sin6_port = htons(port);
        memcpy(&a->sin6_addr, ip_2_ip6(ip)->addr, 16);
        return sizeof(*a);
    }
    struct sockaddr_in *a = (struct sockaddr_in *)ss;
    a->sin_family = AF_INET;
    a->sin_port = htons(port);
    a->sin_addr.s_addr = ip_2_ip4(ip)->addr;
    return sizeof(*a);
}

static void from_sockaddr(const struct sockaddr_storage *ss, ip_addr_t *ip, u16_t *port)
{
    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *a = (const struct sockaddr_in6 *)ss;
        IP_SET_TYPE(ip, IPADDR_TYPE_V6);
        memcpy(ip_2_ip6(ip)->addr, &a->sin6_addr, 16);
        ip6_addr_clear_zone(ip_2_ip6(ip));
        *port = ntohs(a->sin6_port);
    } else {
        const struct sockaddr_in *a = (const struct sockaddr_in *)ss;
        IP_SET_TYPE(ip, IPADDR_TYPE_V4);
        ip_2_ip4(ip)->addr = a->sin_addr.s_addr;
        *port = ntohs(a->sin_port);
    }
}

/* ------------------------------------------------------------------ TUN I/O + tap */

static err_t tun_output(struct netif *netif, struct pbuf *p)
{
    mpc_session *s = netif->state;
    if (s->tap) {
        uint32_t cl;
        uint8_t *slot = mpc_capture_begin(s->cap, MPC_DIR_DOWNLINK, mpc_now_boottime_ns(),
                                          p->payload, p->len, p->tot_len, &cl);
        if (slot) {
            pbuf_copy_partial(p, slot, (u16_t)cl, 0);
            mpc_capture_commit(s->cap);
        }
    }
    ssize_t w;
    if (p->next == NULL) {
        w = write(s->tun_fd, p->payload, p->len);
    } else {
        struct iovec iov[32];
        int n = 0;
        for (struct pbuf *q = p; q && n < 32; q = q->next)
            iov[n++] = (struct iovec){q->payload, q->len};
        w = writev(s->tun_fd, iov, n);
    }
    if (w < 0)
        MPC_CINC(&s->cap->cnt, tun_write_errors, 1);
    return ERR_OK;
}

static err_t tun_output4(struct netif *n, struct pbuf *p, const ip4_addr_t *a)
{
    (void)a;
    return tun_output(n, p);
}

static err_t tun_output6(struct netif *n, struct pbuf *p, const ip6_addr_t *a)
{
    (void)a;
    return tun_output(n, p);
}

static err_t netif_init_cb(struct netif *n)
{
    n->output = tun_output4;
    n->output_ip6 = tun_output6;
    return ERR_OK;
}

static void handle_tun_readable(mpc_session *s)
{
    MPC_CINC(&s->cap->cnt, tun_read_batches, 1);
    for (int i = 0; i < TUN_READ_BATCH; i++) {
        struct pbuf *p = s->spare;
        if (!p) {
            p = pbuf_alloc(PBUF_RAW, (u16_t)s->mtu, PBUF_RAM);
            if (!p) {
                MPC_CINC(&s->cap->cnt, forward_alloc_failures, 1);
                return;
            }
        }
        s->spare = NULL;
        ssize_t n = read(s->tun_fd, p->payload, s->mtu);
        if (n <= 0) {
            s->spare = p;
            if (n < 0 && errno != EAGAIN && errno != EINTR)
                MPC_CINC(&s->cap->cnt, tun_read_errors, 1);
            return;
        }
        MPC_CINC(&s->cap->cnt, tun_read_packets, 1);
        if (s->tap) {
            uint32_t cl;
            uint8_t *slot = mpc_capture_begin(s->cap, MPC_DIR_UPLINK, mpc_now_boottime_ns(),
                                              p->payload, (size_t)n, (uint32_t)n, &cl);
            if (slot) {
                memcpy(slot, p->payload, cl);
                mpc_capture_commit(s->cap);
            }
        }
        pbuf_realloc(p, (u16_t)n);
        if (s->netif.input(p, &s->netif) != ERR_OK)
            pbuf_free(p);
    }
}

/* ------------------------------------------------------------------ TCP relay */

static void conn_update_events(mpc_session *s, tcp_conn *c)
{
    if (c->closed || c->fd < 0)
        return;
    uint32_t m = EPOLLRDHUP;
    if (!c->connected || c->want_out)
        m |= EPOLLOUT;
    if (c->connected && c->want_in)
        m |= EPOLLIN;
    if (m != c->ev_mask) {
        c->ev_mask = m;
        ep_mod(s, c->fd, m, &c->tag);
    }
}

static void conn_release(mpc_session *s, tcp_conn *c)
{
    if (c->closed)
        return;
    c->closed = 1;
    if (c->fd >= 0) {
        epoll_ctl(s->epfd, EPOLL_CTL_DEL, c->fd, NULL);
        close(c->fd);
        c->fd = -1;
    }
    if (c->q) {
        pbuf_free(c->q);
        c->q = NULL;
    }
    if (c->prev)
        c->prev->next = c->next;
    else
        s->conns = c->next;
    if (c->next)
        c->next->prev = c->prev;
    s->n_conns--;
    MPC_CSET(&s->cap->cnt, tcp_conns_active, s->n_conns);
    c->next_free = s->free_conns; /* freed after the current event batch */
    s->free_conns = c;
}

static void detach_pcb(tcp_conn *c)
{
    if (!c->pcb)
        return;
    tcp_arg(c->pcb, NULL);
    tcp_recv(c->pcb, NULL);
    tcp_sent(c->pcb, NULL);
    tcp_err(c->pcb, NULL);
}

static void conn_abort(mpc_session *s, tcp_conn *c)
{
    if (c->pcb) {
        detach_pcb(c);
        tcp_abort(c->pcb);
        c->pcb = NULL;
        c->aborted = 1; /* callbacks must return ERR_ABRT */
    }
    conn_release(s, c);
}

static void conn_maybe_close(mpc_session *s, tcp_conn *c)
{
    if (c->closed || !c->app_eof || !c->sock_eof || c->q)
        return;
    if (c->pcb && (c->pcb->unsent || c->pcb->unacked))
        return;
    if (c->pcb) {
        detach_pcb(c);
        if (tcp_close(c->pcb) != ERR_OK) {
            tcp_abort(c->pcb);
            c->aborted = 1;
        }
        c->pcb = NULL;
    }
    conn_release(s, c);
}

/* Returns -1 if the connection was aborted. */
static int conn_flush_to_sock(mpc_session *s, tcp_conn *c)
{
    while (c->q) {
        struct iovec iov[32];
        int n = 0;
        for (struct pbuf *q = c->q; q && n < 32; q = q->next)
            if (q->len)
                iov[n++] = (struct iovec){q->payload, q->len};
        if (n == 0) {
            pbuf_free(c->q);
            c->q = NULL;
            break;
        }
        struct msghdr mh = {.msg_iov = iov, .msg_iovlen = (size_t)n};
        ssize_t w = sendmsg(c->fd, &mh, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                c->want_out = 1;
                conn_update_events(s, c);
                return 0;
            }
            if (errno == EINTR)
                continue;
            MPC_CINC(&s->cap->cnt, forwarding_errors, 1);
            conn_abort(s, c);
            return -1;
        }
        size_t left = (size_t)w;
        while (left) {
            u16_t chunk = left > 0xffff ? 0xffff : (u16_t)left;
            c->q = pbuf_free_header(c->q, chunk);
            if (c->pcb)
                tcp_recved(c->pcb, chunk);
            left -= chunk;
        }
    }
    c->want_out = 0;
    if (c->app_eof && !c->sock_wr_shut) {
        shutdown(c->fd, SHUT_WR);
        c->sock_wr_shut = 1;
    }
    conn_update_events(s, c);
    conn_maybe_close(s, c);
    return 0;
}

/* The session pointer is needed in lwIP callbacks; keep it in a thread-local. */
static __thread mpc_session *t_sess;

static err_t on_tcp_recv_impl(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    tcp_conn *c = arg;
    mpc_session *s = t_sess;
    (void)err;
    if (!c || c->closed) {
        if (p) {
            tcp_recved(pcb, p->tot_len);
            pbuf_free(p);
        }
        return ERR_OK;
    }
    if (!p) {
        c->app_eof = 1;
        if (c->connected && !c->q && !c->sock_wr_shut) {
            shutdown(c->fd, SHUT_WR);
            c->sock_wr_shut = 1;
        }
        conn_maybe_close(s, c);
        return c->aborted ? ERR_ABRT : ERR_OK;
    }
    if (c->q)
        pbuf_cat(c->q, p);
    else
        c->q = p;
    if (c->connected)
        conn_flush_to_sock(s, c);
    return c->aborted ? ERR_ABRT : ERR_OK;
}

static err_t on_tcp_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
    tcp_conn *c = arg;
    mpc_session *s = t_sess;
    (void)pcb;
    (void)len;
    if (!c || c->closed)
        return ERR_OK;
    if (c->connected && !c->sock_eof && !c->want_in) {
        c->want_in = 1;
        conn_update_events(s, c);
    }
    conn_maybe_close(s, c);
    return c->aborted ? ERR_ABRT : ERR_OK;
}

static void on_tcp_err(void *arg, err_t err)
{
    tcp_conn *c = arg;
    (void)err;
    if (!c)
        return;
    c->pcb = NULL; /* already freed by lwIP */
    conn_release(t_sess, c);
}

static err_t on_tcp_accept(void *arg, struct tcp_pcb *pcb, err_t err)
{
    mpc_session *s = arg;
    if (err != ERR_OK || !pcb)
        return ERR_VAL;
    if (s->n_conns >= MAX_TCP_CONNS || atomic_load(&s->stopping)) {
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    struct sockaddr_storage ss;
    socklen_t sl = to_sockaddr(&pcb->local_ip, pcb->local_port, &ss);
    int fd = socket(ss.ss_family, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        MPC_CINC(&s->cap->cnt, tcp_connect_failures, 1);
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (connect(fd, (struct sockaddr *)&ss, sl) != 0 && errno != EINPROGRESS) {
        close(fd);
        MPC_CINC(&s->cap->cnt, tcp_connect_failures, 1);
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    tcp_conn *c = calloc(1, sizeof(*c));
    if (!c) {
        close(fd);
        tcp_abort(pcb);
        return ERR_ABRT;
    }
    c->tag.type = EV_TCP;
    c->tag.ptr = c;
    c->pcb = pcb;
    c->fd = fd;
    c->want_in = 1;
    c->ev_mask = EPOLLOUT | EPOLLRDHUP;
    ep_add(s, fd, c->ev_mask, &c->tag);
    c->next = s->conns;
    if (s->conns)
        s->conns->prev = c;
    s->conns = c;
    s->n_conns++;
    MPC_CINC(&s->cap->cnt, tcp_conns_total, 1);
    MPC_CSET(&s->cap->cnt, tcp_conns_active, s->n_conns);
    tcp_arg(pcb, c);
    tcp_recv(pcb, on_tcp_recv_impl);
    tcp_sent(pcb, on_tcp_sent);
    tcp_err(pcb, on_tcp_err);
    tcp_nagle_disable(pcb);
    return ERR_OK;
}

static void conn_sock_readable(mpc_session *s, tcp_conn *c)
{
    size_t budget = SOCK_READ_BUDGET;
    while (!c->closed && c->pcb && !c->sock_eof && budget) {
        size_t avail = tcp_sndbuf(c->pcb);
        if (tcp_sndqueuelen(c->pcb) >= TCP_SND_QUEUELEN - 4)
            avail = 0;
        if (avail == 0) {
            c->want_in = 0; /* resumed from on_tcp_sent */
            break;
        }
        if (avail > sizeof(s->relay_buf))
            avail = sizeof(s->relay_buf);
        if (avail > budget)
            avail = budget;
        ssize_t n = recv(c->fd, s->relay_buf, avail, MSG_DONTWAIT);
        if (n > 0) {
            if (tcp_write(c->pcb, s->relay_buf, (u16_t)n, TCP_WRITE_FLAG_COPY) != ERR_OK) {
                MPC_CINC(&s->cap->cnt, forward_alloc_failures, 1);
                conn_abort(s, c);
                return;
            }
            budget -= (size_t)n;
            continue;
        }
        if (n == 0) {
            c->sock_eof = 1;
            c->want_in = 0;
            tcp_shutdown(c->pcb, 0, 1);
            break;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK)
            break;
        if (errno == EINTR)
            continue;
        MPC_CINC(&s->cap->cnt, forwarding_errors, 1);
        conn_abort(s, c);
        return;
    }
    if (!c->closed && c->pcb)
        tcp_output(c->pcb);
    conn_update_events(s, c);
    conn_maybe_close(s, c);
}

static void handle_tcp_event(mpc_session *s, tcp_conn *c, uint32_t ev)
{
    if (c->closed)
        return;
    if (!c->connected) {
        if (!(ev & (EPOLLOUT | EPOLLERR | EPOLLHUP)))
            return;
        int soerr = 0;
        socklen_t sl = sizeof(soerr);
        getsockopt(c->fd, SOL_SOCKET, SO_ERROR, &soerr, &sl);
        if (soerr != 0 || (ev & EPOLLERR)) {
            MPC_CINC(&s->cap->cnt, tcp_connect_failures, 1);
            conn_abort(s, c); /* RST to the app, like a refused connection */
            return;
        }
        c->connected = 1;
        if (c->app_eof && !c->q) {
            shutdown(c->fd, SHUT_WR);
            c->sock_wr_shut = 1;
        }
        if (c->q && conn_flush_to_sock(s, c) < 0)
            return;
        conn_update_events(s, c);
        return;
    }
    if ((ev & EPOLLOUT) && c->want_out) {
        if (conn_flush_to_sock(s, c) < 0)
            return;
    }
    if (ev & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR)) {
        if (c->want_in || (ev & (EPOLLERR)))
            conn_sock_readable(s, c);
    }
}

/* ------------------------------------------------------------------ UDP relay */

static void sess_release(mpc_session *s, udp_sess *u)
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
    sess_send(t_sess, u, p, &pcb->local_ip, pcb->local_port);
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
static void on_udp_listen_recv(void *arg, struct udp_pcb *npcb, struct pbuf *p,
                               const ip_addr_t *dst, u16_t dport)
{
    mpc_session *s = arg;
    (void)p;
    (void)dst;
    (void)dport;
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

static void handle_udp_event(mpc_session *s, udp_sess *u, ev_tag *tag)
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

static void udp_sweep(mpc_session *s)
{
    uint32_t now = sys_now();
    for (udp_sess *u = s->sessions, *nx; u; u = nx) {
        nx = u->next;
        uint32_t idle = now - u->last_active;
        if (idle > (u->dns_only ? UDP_DNS_IDLE_MS : UDP_IDLE_MS))
            sess_release(s, u);
    }
}

/* ------------------------------------------------------------------ main loop */

static void free_deferred(mpc_session *s)
{
    while (s->free_conns) {
        tcp_conn *c = s->free_conns;
        s->free_conns = c->next_free;
        free(c);
    }
    while (s->free_sessions) {
        udp_sess *u = s->free_sessions;
        s->free_sessions = u->next_free;
        free(u);
    }
}

static int gateway_init(mpc_session *s)
{
    lwip_init();
    ip4_addr_t addr4, mask, gw;
    ip6_addr_t addr6;
    if (!netif_add_noaddr(&s->netif, s, netif_init_cb, ip_input))
        return -1;
    ip4_addr_set_loopback(&addr4);
    ip4_addr_set_any(&mask);
    ip4_addr_set_any(&gw);
    netif_set_addr(&s->netif, &addr4, &mask, &gw);
    ip6_addr_set_loopback(&addr6);
    netif_add_ip6_address(&s->netif, &addr6, NULL);
    s->netif.mtu = (u16_t)s->mtu;
#if LWIP_ND6_ALLOW_RA_UPDATES
    s->netif.mtu6 = (u16_t)s->mtu;
#endif
    netif_set_up(&s->netif);
    netif_set_link_up(&s->netif);
    netif_set_default(&s->netif);
    netif_set_flags(&s->netif, NETIF_FLAG_PRETEND_TCP);
    netif_set_flags(&s->netif, NETIF_FLAG_PRETEND_UDP);

    struct tcp_pcb *t = tcp_new_ip_type(IPADDR_TYPE_ANY);
    if (!t)
        return -1;
    tcp_bind_netif(t, &s->netif);
    tcp_bind(t, NULL, 0);
    s->tcp_listener = tcp_listen(t);
    if (!s->tcp_listener)
        return -1;
    tcp_arg(s->tcp_listener, s);
    tcp_accept(s->tcp_listener, on_tcp_accept);

    s->udp_listener = udp_new_ip_type(IPADDR_TYPE_ANY);
    if (!s->udp_listener)
        return -1;
    udp_bind_netif(s->udp_listener, &s->netif);
    udp_bind(s->udp_listener, NULL, 0);
    udp_recv(s->udp_listener, on_udp_listen_recv, s);
    return 0;
}

static void gateway_fini(mpc_session *s)
{
    while (s->conns)
        conn_abort(s, s->conns);
    while (s->sessions)
        sess_release(s, s->sessions);
    free_deferred(s);
    if (s->udp_listener) {
        udp_remove(s->udp_listener);
        s->udp_listener = NULL;
    }
    if (s->tcp_listener) {
        tcp_close(s->tcp_listener);
        s->tcp_listener = NULL;
    }
    /* Let lwIP release remaining pcbs (TIME_WAIT etc.). */
    for (struct tcp_pcb *p = tcp_active_pcbs; p;) {
        struct tcp_pcb *n = p->next;
        tcp_arg(p, NULL);
        tcp_err(p, NULL);
        tcp_abort(p);
        p = n;
    }
    while (tcp_tw_pcbs)
        tcp_abort(tcp_tw_pcbs);
    netif_remove(&s->netif);
    if (s->spare) {
        pbuf_free(s->spare);
        s->spare = NULL;
    }
    lwip_fini();
}

static void on_timer(mpc_session *s)
{
    uint64_t exp;
    ssize_t r = read(s->timer_fd, &exp, sizeof(exp));
    (void)r;
    tcp_tmr();
    s->ticks++;
    if ((s->ticks & 3) == 0) {
        ip_reass_tmr();
        ip6_reass_tmr();
        udp_sweep(s);
        mpc_capture_housekeeping(s->cap, mpc_now_boottime_ns());
    }
}

static void *engine_main(void *arg)
{
    mpc_session *s = arg;
    t_sess = s;
    pthread_setname_np(pthread_self(), "mpc-engine");
    struct epoll_event evs[MAX_EVENTS];
    MPC_CSET(&s->cap->cnt, engine_running, 1);
    while (!atomic_load_explicit(&s->stopping, memory_order_acquire)) {
        int n = epoll_wait(s->epfd, evs, MAX_EVENTS, 1000);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            break;
        }
        for (int i = 0; i < n; i++) {
            ev_tag *tag = evs[i].data.ptr;
            switch (tag->type) {
            case EV_TUN:
                handle_tun_readable(s);
                break;
            case EV_TIMER:
                on_timer(s);
                break;
            case EV_CTL:
                break;
            case EV_UIDRESP:
                mpc_capture_apply_uids(s->cap);
                break;
            case EV_TCP:
                handle_tcp_event(s, tag->ptr, evs[i].events);
                break;
            case EV_UDP:
                handle_udp_event(s, tag->ptr, tag);
                break;
            }
        }
        free_deferred(s);
        if (s->tap)
            mpc_capture_batch_done(s->cap);
    }
    /* Quiesce the capture point first: no more records after Stop. */
    s->tap = 0;
    mpc_capture_housekeeping(s->cap, mpc_now_boottime_ns()); /* final flow counters */
    gateway_fini(s);
    close(s->tun_fd);
    s->tun_fd = -1;
    MPC_CSET(&s->cap->cnt, engine_running, 0);
    return NULL;
}

mpc_session *mpc_session_start(int tun_fd, const mpc_capture_config *cfg, int *err)
{
    *err = 0;
    int expected = 0;
    if (!atomic_compare_exchange_strong(&g_engine_active, &expected, 1)) {
        *err = EBUSY;
        close(tun_fd);
        return NULL;
    }
    mpc_session *s = calloc(1, sizeof(*s));
    if (!s) {
        *err = ENOMEM;
        goto fail_early;
    }
    pthread_mutex_init(&s->stop_lock, NULL);
    s->tun_fd = tun_fd;
    s->mtu = cfg->mtu ? cfg->mtu : 1500;
    s->epfd = s->timer_fd = s->ctl_fd = -1;
    s->cap = mpc_capture_create(cfg, err);
    if (!s->cap)
        goto fail;
    s->tap = s->cap->tap_enabled;
    if (set_nonblock(tun_fd) != 0)
        goto fail_errno;
    s->epfd = epoll_create1(EPOLL_CLOEXEC);
    s->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
    s->ctl_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (s->epfd < 0 || s->timer_fd < 0 || s->ctl_fd < 0)
        goto fail_errno;
    struct itimerspec its = {.it_interval = {0, TCP_TMR_INTERVAL * 1000000L},
                             .it_value = {0, TCP_TMR_INTERVAL * 1000000L}};
    timerfd_settime(s->timer_fd, 0, &its, NULL);
    s->tun_tag = (ev_tag){EV_TUN, s};
    s->timer_tag = (ev_tag){EV_TIMER, s};
    s->ctl_tag = (ev_tag){EV_CTL, s};
    s->uid_tag = (ev_tag){EV_UIDRESP, s};
    ep_add(s, tun_fd, EPOLLIN, &s->tun_tag);
    ep_add(s, s->timer_fd, EPOLLIN, &s->timer_tag);
    ep_add(s, s->ctl_fd, EPOLLIN, &s->ctl_tag);
    ep_add(s, s->cap->uid_resp_efd, EPOLLIN, &s->uid_tag);
    if (gateway_init(s) != 0) {
        *err = ENOMEM;
        goto fail;
    }
    if (mpc_capture_start_writer(s->cap) != 0)
        goto fail_errno;
    if (pthread_create(&s->thread, NULL, engine_main, s) != 0)
        goto fail_errno;
    s->thread_started = 1;
    return s;
fail_errno:
    *err = errno ? errno : EIO;
fail:
    if (s->tcp_listener || s->udp_listener)
        gateway_fini(s);
    if (s->cap) {
        mpc_capture_finish(s->cap);
        mpc_capture_destroy(s->cap);
    }
    if (s->epfd >= 0)
        close(s->epfd);
    if (s->timer_fd >= 0)
        close(s->timer_fd);
    if (s->ctl_fd >= 0)
        close(s->ctl_fd);
    free(s);
fail_early:
    close(tun_fd);
    atomic_store(&g_engine_active, 0);
    return NULL;
}

int mpc_session_stop(mpc_session *s)
{
    pthread_mutex_lock(&s->stop_lock);
    if (s->stopped) {
        pthread_mutex_unlock(&s->stop_lock);
        return atomic_load(&s->cap->cnt.storage_errors) ? -1 : 0;
    }
    atomic_store_explicit(&s->stopping, 1, memory_order_release);
    uint64_t one = 1;
    ssize_t r = write(s->ctl_fd, &one, sizeof(one));
    (void)r;
    if (s->thread_started)
        pthread_join(s->thread, NULL);
    int rc = mpc_capture_finish(s->cap);
    mpc_capture_close_uid(s->cap);
    s->stopped = 1;
    atomic_store(&g_engine_active, 0);
    pthread_mutex_unlock(&s->stop_lock);
    return rc;
}

void mpc_session_destroy(mpc_session *s)
{
    if (!s)
        return;
    mpc_session_stop(s);
    mpc_capture_destroy(s->cap);
    close(s->epfd);
    close(s->timer_fd);
    close(s->ctl_fd);
    pthread_mutex_destroy(&s->stop_lock);
    free(s);
}

mpc_capture *mpc_session_capture(mpc_session *s) { return s->cap; }
