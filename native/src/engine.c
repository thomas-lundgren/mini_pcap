/* Forwarding engine: the single engine thread (lwIP NO_SYS=1) with its epoll loop, TUN
 * I/O and the capture tap at the TUN boundary, the lwIP gateway (netif + listeners), and
 * the session lifecycle that orders start/stop of forwarding and the capture writer.
 * The relays are relay_tcp.c and relay_udp.c. Outbound sockets bypass the VPN because the
 * app excludes its own UID from the VPN (see docs/DECISIONS.md ADR-006), so no per-flow
 * JNI protect() call is needed. */
#define _GNU_SOURCE
#include "engine_internal.h"
#include "lwip/priv/tcp_priv.h" /* tcp_active_pcbs, tcp_tw_pcbs, tcp_tmr */

static _Atomic int g_engine_active; /* lwIP has global state: one engine per process */
__thread mpc_session *engine_current;

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

/* ------------------------------------------------------------------ TUN I/O + tap */

static err_t tun_output(struct netif *netif, struct pbuf *p)
{
    mpc_session *s = netif->state;
    if (s->tap) {
        /* The parser needs the headers contiguous. lwIP may put only the IP header in the
         * first pbuf (e.g. IP fragmentation), so copy up to MPC_HDR_MAX bytes if needed. */
        const uint8_t *hdr = p->payload;
        size_t hdr_len = p->len;
        uint8_t flat[MPC_HDR_MAX];
        if (p->next && p->len < MPC_HDR_MAX && p->len < p->tot_len) {
            hdr_len = pbuf_copy_partial(p, flat, (u16_t)(p->tot_len < MPC_HDR_MAX ? p->tot_len : MPC_HDR_MAX), 0);
            hdr = flat;
        }
        uint32_t cl;
        uint8_t *slot = mpc_capture_begin(s->cap, MPC_DIR_DOWNLINK, mpc_now_boottime_ns(), hdr, hdr_len,
                                          p->tot_len, &cl);
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
        struct pbuf *q = p;
        for (; q && n < 32; q = q->next)
            iov[n++] = (struct iovec){q->payload, q->len};
        if (q == NULL) {
            w = writev(s->tun_fd, iov, n);
        } else { /* more than 32 segments: one copy instead of a truncated packet */
            u16_t len = pbuf_copy_partial(p, s->tx_buf, p->tot_len, 0);
            w = write(s->tun_fd, s->tx_buf, len);
        }
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

/* ------------------------------------------------------------------ gateway */

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
    s->gateway_started = 1;
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
    tcp_accept(s->tcp_listener, relay_tcp_accept);

    s->udp_listener = udp_new_ip_type(IPADDR_TYPE_ANY);
    if (!s->udp_listener)
        return -1;
    udp_bind_netif(s->udp_listener, &s->netif);
    udp_bind(s->udp_listener, NULL, 0);
    udp_recv(s->udp_listener, relay_udp_listen_recv, s);
    return 0;
}

static void gateway_fini(mpc_session *s)
{
    while (s->conns)
        relay_tcp_abort(s, s->conns);
    while (s->sessions)
        relay_udp_release(s, s->sessions);
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

/* ------------------------------------------------------------------ main loop */

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
        relay_udp_sweep(s);
        mpc_capture_housekeeping(s->cap, mpc_now_boottime_ns());
    }
}

static void *engine_main(void *arg)
{
    mpc_session *s = arg;
    engine_current = s;
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
            case EV_TCP:
                relay_tcp_event(s, tag->ptr, evs[i].events);
                break;
            case EV_UDP:
                relay_udp_event(s, tag->ptr, tag);
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
    ep_add(s, tun_fd, EPOLLIN, &s->tun_tag);
    ep_add(s, s->timer_fd, EPOLLIN, &s->timer_tag);
    ep_add(s, s->ctl_fd, EPOLLIN, &s->ctl_tag);
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
    if (s->gateway_started)
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
