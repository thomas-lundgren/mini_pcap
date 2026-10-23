/* TCP relay: each connection is terminated by lwIP towards the app and mirrored by a
 * non-blocking socket towards the network (the app's own traffic bypasses the VPN, see
 * docs/DECISIONS.md ADR-006). Back-pressure both ways: the app's receive window is
 * reopened (tcp_recved) only once its data was written to the socket; socket reads stop
 * while lwIP's send buffer is full. The socket is registered with epoll only while the
 * relay wants to read or write it, so level-triggered HUP/ERR cannot spin the loop. */
#define _GNU_SOURCE
#include "engine_internal.h"

/* Interest = what the relay can act on now. With nothing wanted the fd leaves the epoll
 * set: EPOLLHUP/EPOLLERR cannot be masked, and a peer FIN stays readable, so keeping an
 * idle fd registered would wake the loop continuously (e.g. while the app drains a
 * finished download). EOF is seen as recv() == 0 once reading resumes. */
static void conn_update_events(mpc_session *s, tcp_conn *c)
{
    if (c->closed || c->fd < 0)
        return;
    uint32_t m = 0;
    if (!c->connected || c->want_out)
        m |= EPOLLOUT;
    if (c->connected && c->want_in)
        m |= EPOLLIN;
    if (m == c->ev_mask)
        return;
    if (m == 0)
        epoll_ctl(s->epfd, EPOLL_CTL_DEL, c->fd, NULL);
    else if (c->ev_mask == 0)
        ep_add(s, c->fd, m, &c->tag);
    else
        ep_mod(s, c->fd, m, &c->tag);
    c->ev_mask = m;
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

void relay_tcp_abort(mpc_session *s, tcp_conn *c)
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
            relay_tcp_abort(s, c);
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

/* lwIP callbacks carry the connection, not the session: use engine_current. */

static err_t on_tcp_recv_impl(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    tcp_conn *c = arg;
    mpc_session *s = engine_current;
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
    mpc_session *s = engine_current;
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
    conn_release(engine_current, c);
}

err_t relay_tcp_accept(void *arg, struct tcp_pcb *pcb, err_t err)
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
    c->ev_mask = EPOLLOUT; /* connect completion */
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
        if (avail > 0xFFFF) /* tcp_write takes a u16 length (tcp_sndbuf already clamps; keep it explicit) */
            avail = 0xFFFF;
        if (avail > budget)
            avail = budget;
        ssize_t n = recv(c->fd, s->relay_buf, avail, MSG_DONTWAIT);
        if (n > 0) {
            /* Fits by construction (avail <= tcp_sndbuf, queue length checked); a failure here is
             * lwIP heap exhaustion after the bytes left the socket: abort rather than lose them. */
            if (tcp_write(c->pcb, s->relay_buf, (u16_t)n, TCP_WRITE_FLAG_COPY) != ERR_OK) {
                MPC_CINC(&s->cap->cnt, forward_alloc_failures, 1);
                relay_tcp_abort(s, c);
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
        relay_tcp_abort(s, c);
        return;
    }
    if (!c->closed && c->pcb)
        tcp_output(c->pcb);
    conn_update_events(s, c);
    conn_maybe_close(s, c);
}

void relay_tcp_event(mpc_session *s, tcp_conn *c, uint32_t ev)
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
            relay_tcp_abort(s, c); /* RST to the app, like a refused connection */
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
    if (ev & EPOLLERR) { /* reset or other socket error: nothing more can be relayed */
        MPC_CINC(&s->cap->cnt, forwarding_errors, 1);
        relay_tcp_abort(s, c);
        return;
    }
    if ((ev & (EPOLLOUT | EPOLLHUP)) && c->want_out) {
        if (conn_flush_to_sock(s, c) < 0)
            return;
    }
    if ((ev & (EPOLLIN | EPOLLHUP)) && c->want_in)
        conn_sock_readable(s, c);
}

