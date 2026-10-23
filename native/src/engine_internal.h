/* Engine internals shared by engine.c (event loop, TUN I/O + capture tap, lwIP gateway,
 * session lifecycle), relay_tcp.c and relay_udp.c. Everything here runs on the single
 * engine thread (lwIP NO_SYS=1); nothing is part of the public API (mpc/engine.h). */
#ifndef MPC_ENGINE_INTERNAL_H
#define MPC_ENGINE_INTERNAL_H

#ifndef _GNU_SOURCE
#error "define _GNU_SOURCE before including engine_internal.h"
#endif

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
#include "lwip/sys.h"
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

/* ------------------------------------------------------------------ types */

enum { EV_TUN = 1, EV_TIMER, EV_CTL, EV_TCP, EV_UDP };

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
    uint8_t tx_buf[65536]; /* flattens pbuf chains too long for one writev (rare) */
    ev_tag tun_tag, timer_tag, ctl_tag;
    uint32_t ticks;
    int gateway_started; /* lwip_init() ran: gateway_fini() must undo it, even after a partial init */
    pthread_mutex_t stop_lock;
};

/* The session whose engine thread is running (lwIP callbacks carry no session pointer). */
extern __thread mpc_session *engine_current;

/* ------------------------------------------------------------------ helpers */

static inline int set_nonblock(int fd)
{
    int fl = fcntl(fd, F_GETFL);
    return fl < 0 ? -1 : fcntl(fd, F_SETFL, fl | O_NONBLOCK);
}

static inline void ep_add(mpc_session *s, int fd, uint32_t events, ev_tag *tag)
{
    struct epoll_event ev = {.events = events, .data.ptr = tag};
    epoll_ctl(s->epfd, EPOLL_CTL_ADD, fd, &ev);
}

static inline void ep_mod(mpc_session *s, int fd, uint32_t events, ev_tag *tag)
{
    struct epoll_event ev = {.events = events, .data.ptr = tag};
    epoll_ctl(s->epfd, EPOLL_CTL_MOD, fd, &ev);
}

static inline socklen_t to_sockaddr(const ip_addr_t *ip, u16_t port, struct sockaddr_storage *ss)
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

static inline void from_sockaddr(const struct sockaddr_storage *ss, ip_addr_t *ip, u16_t *port)
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

/* ------------------------------------------------------------------ relays */

/* TCP (relay_tcp.c): lwIP-terminated connections relayed over ordinary sockets. */
err_t relay_tcp_accept(void *arg, struct tcp_pcb *pcb, err_t err);
void relay_tcp_event(mpc_session *s, tcp_conn *c, uint32_t ev);
void relay_tcp_abort(mpc_session *s, tcp_conn *c); /* RST to the app, socket closed */

/* UDP (relay_udp.c): per app-source-endpoint sessions relayed over ordinary sockets. */
void relay_udp_listen_recv(void *arg, struct udp_pcb *npcb, struct pbuf *p, const ip_addr_t *addr, u16_t port);
void relay_udp_event(mpc_session *s, udp_sess *u, ev_tag *tag);
void relay_udp_sweep(mpc_session *s); /* idle expiry, ~1 Hz */
void relay_udp_release(mpc_session *s, udp_sess *u);

#endif
