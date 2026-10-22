/* nettool: reproducible network workload for P0/P1/P2 benchmarks.
 *
 * Server (host):  nettool server <port>            UDP echo + TCP up/down/connect service
 * Clients (phone, emits one JSON line on stdout):
 *   nettool udp   <host> <port> <pps> <size> <seconds>   paced UDP echo: loss, RTT pctl
 *   nettool tcpup <host> <port> <seconds>                 TCP uplink goodput
 *   nettool tcpdown <host> <port> <seconds>               TCP downlink goodput
 *   nettool churn <host> <port> <count>                   short TCP connections: connect+RR time
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static uint64_t now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static double cpu_ms(void)
{
    struct rusage ru;
    getrusage(RUSAGE_SELF, &ru);
    return (ru.ru_utime.tv_sec + ru.ru_stime.tv_sec) * 1e3 +
           (ru.ru_utime.tv_usec + ru.ru_stime.tv_usec) / 1e3;
}

static int resolve(const char *host, const char *port, int type, struct sockaddr_storage *ss,
                   socklen_t *sl)
{
    struct addrinfo hints = {.ai_socktype = type}, *res;
    if (getaddrinfo(host, port, &hints, &res) != 0)
        return -1;
    memcpy(ss, res->ai_addr, res->ai_addrlen);
    *sl = res->ai_addrlen;
    freeaddrinfo(res);
    return 0;
}

/* ------------------------------------------------------------------ server */

static void *tcp_conn_thread(void *arg)
{
    int c = (int)(intptr_t)arg;
    char cmd[8];
    if (recv(c, cmd, 5, MSG_WAITALL) != 5)
        goto out;
    uint32_t secs;
    memcpy(&secs, cmd + 1, 4);
    secs = ntohl(secs);
    static char buf[256 * 1024];
    if (cmd[0] == 'U') {
        while (recv(c, buf, sizeof(buf), 0) > 0)
            ;
    } else if (cmd[0] == 'D') {
        uint64_t end = now_ns() + (uint64_t)secs * 1000000000ULL;
        while (now_ns() < end)
            if (send(c, buf, sizeof(buf), MSG_NOSIGNAL) <= 0)
                break;
    } else if (cmd[0] == 'R') { /* request/response: echo 64-byte messages */
        char m[64];
        while (recv(c, m, sizeof(m), MSG_WAITALL) == (ssize_t)sizeof(m))
            send(c, m, sizeof(m), MSG_NOSIGNAL);
    }
out:
    close(c);
    return NULL;
}

static void *udp_server_thread(void *arg)
{
    int fd = (int)(intptr_t)arg;
    char buf[65536];
    for (;;) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&ss, &sl);
        if (n > 0)
            sendto(fd, buf, (size_t)n, 0, (struct sockaddr *)&ss, sl);
    }
    return NULL;
}

static int server(int port)
{
    struct sockaddr_in6 a = {.sin6_family = AF_INET6, .sin6_port = htons((uint16_t)port),
                             .sin6_addr = IN6ADDR_ANY_INIT};
    int zero = 0, one = 1;
    int u = socket(AF_INET6, SOCK_DGRAM, 0);
    setsockopt(u, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
    int rb = 8 << 20;
    setsockopt(u, SOL_SOCKET, SO_RCVBUF, &rb, sizeof(rb));
    setsockopt(u, SOL_SOCKET, SO_SNDBUF, &rb, sizeof(rb));
    if (bind(u, (struct sockaddr *)&a, sizeof(a)) != 0) {
        perror("bind udp");
        return 1;
    }
    int t = socket(AF_INET6, SOCK_STREAM, 0);
    setsockopt(t, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof(zero));
    setsockopt(t, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if (bind(t, (struct sockaddr *)&a, sizeof(a)) != 0 || listen(t, 128) != 0) {
        perror("bind tcp");
        return 1;
    }
    pthread_t th;
    pthread_create(&th, NULL, udp_server_thread, (void *)(intptr_t)u);
    fprintf(stderr, "nettool server on port %d (udp echo + tcp)\n", port);
    for (;;) {
        int c = accept(t, NULL, NULL);
        if (c < 0)
            continue;
        setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        pthread_create(&th, NULL, tcp_conn_thread, (void *)(intptr_t)c);
        pthread_detach(th);
    }
}

/* ------------------------------------------------------------------ udp client */

typedef struct {
    int fd;
    uint64_t sent_target;
    volatile int done;
    uint64_t recv;
    uint32_t *rtt_us; /* indexed by sequence */
    uint64_t max_seq;
} udp_ctx;

static void *udp_rx(void *arg)
{
    udp_ctx *x = arg;
    char buf[65536];
    while (!x->done) {
        struct pollfd p = {.fd = x->fd, .events = POLLIN};
        if (poll(&p, 1, 200) <= 0)
            continue;
        ssize_t n;
        while ((n = recv(x->fd, buf, sizeof(buf), MSG_DONTWAIT)) >= 16) {
            uint64_t seq, ts;
            memcpy(&seq, buf, 8);
            memcpy(&ts, buf + 8, 8);
            if (seq < x->max_seq && x->rtt_us[seq] == 0) {
                uint64_t r = (now_ns() - ts) / 1000;
                x->rtt_us[seq] = r ? (uint32_t)r : 1;
                x->recv++;
            }
        }
    }
    return NULL;
}

static int cmp_u32(const void *a, const void *b)
{
    uint32_t x = *(const uint32_t *)a, y = *(const uint32_t *)b;
    return x < y ? -1 : x > y;
}

static int udp_client(const char *host, const char *port, double pps, int size, double secs)
{
    struct sockaddr_storage ss;
    socklen_t sl;
    if (resolve(host, port, SOCK_DGRAM, &ss, &sl) != 0)
        return 1;
    if (size < 16)
        size = 16;
    int fd = socket(ss.ss_family, SOCK_DGRAM, 0);
    int rb = 4 << 20;
    setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rb, sizeof(rb));
    if (connect(fd, (struct sockaddr *)&ss, sl) != 0) {
        perror("connect");
        return 1;
    }
    udp_ctx x = {.fd = fd};
    x.max_seq = (uint64_t)(pps * secs) + 16;
    x.rtt_us = calloc(x.max_seq, sizeof(uint32_t));
    pthread_t th;
    pthread_create(&th, NULL, udp_rx, &x);
    char *buf = calloc(1, (size_t)size);
    double c0 = cpu_ms();
    uint64_t start = now_ns(), interval = (uint64_t)(1e9 / pps), sent = 0, send_err = 0;
    uint64_t end = start + (uint64_t)(secs * 1e9);
    for (;;) {
        uint64_t t = now_ns();
        if (t >= end || sent >= x.max_seq)
            break;
        uint64_t due = (t - start) / interval + 1;
        while (sent < due && sent < x.max_seq) {
            uint64_t ts = now_ns();
            memcpy(buf, &sent, 8);
            memcpy(buf + 8, &ts, 8);
            if (send(fd, buf, (size_t)size, 0) < 0)
                send_err++;
            sent++;
        }
        uint64_t next = start + sent * interval;
        uint64_t now = now_ns();
        if (next > now + 50000) {
            struct timespec ts = {0, (long)(next - now - 20000)};
            nanosleep(&ts, NULL);
        }
    }
    uint64_t elapsed = now_ns() - start;
    usleep(1000 * 1000); /* allow in-flight echoes */
    x.done = 1;
    pthread_join(th, NULL);
    double cpu = cpu_ms() - c0;
    uint32_t *r = malloc(sizeof(uint32_t) * (x.recv + 1));
    uint64_t k = 0;
    for (uint64_t i = 0; i < sent; i++)
        if (x.rtt_us[i])
            r[k++] = x.rtt_us[i];
    qsort(r, k, sizeof(uint32_t), cmp_u32);
#define PCT(p) (k ? r[(size_t)((k - 1) * (p))] : 0)
    printf("{\"test\":\"udp\",\"target_pps\":%.0f,\"size\":%d,\"seconds\":%.3f,\"sent\":%llu,"
           "\"send_errors\":%llu,\"received\":%llu,\"loss_pct\":%.4f,\"achieved_pps\":%.1f,"
           "\"rtt_us_p50\":%u,\"rtt_us_p95\":%u,\"rtt_us_p99\":%u,\"rtt_us_max\":%u,"
           "\"client_cpu_ms\":%.1f}\n",
           pps, size, elapsed / 1e9, (unsigned long long)sent, (unsigned long long)send_err,
           (unsigned long long)k, sent ? 100.0 * (double)(sent - k) / (double)sent : 0.0,
           sent / (elapsed / 1e9), PCT(0.50), PCT(0.95), PCT(0.99), k ? r[k - 1] : 0, cpu);
    return 0;
}

/* ------------------------------------------------------------------ tcp clients */

static int tcp_connect(const char *host, const char *port)
{
    struct sockaddr_storage ss;
    socklen_t sl;
    if (resolve(host, port, SOCK_STREAM, &ss, &sl) != 0)
        return -1;
    int fd = socket(ss.ss_family, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (connect(fd, (struct sockaddr *)&ss, sl) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int tcp_bulk(const char *host, const char *port, int up, double secs)
{
    int fd = tcp_connect(host, port);
    if (fd < 0) {
        perror("connect");
        return 1;
    }
    char cmd[5] = {up ? 'U' : 'D'};
    uint32_t s = htonl((uint32_t)secs);
    memcpy(cmd + 1, &s, 4);
    send(fd, cmd, 5, 0);
    static char buf[256 * 1024];
    double c0 = cpu_ms();
    uint64_t start = now_ns(), bytes = 0, end = start + (uint64_t)(secs * 1e9);
    if (up) {
        while (now_ns() < end) {
            ssize_t n = send(fd, buf, sizeof(buf), MSG_NOSIGNAL);
            if (n <= 0)
                break;
            bytes += (uint64_t)n;
        }
    } else {
        ssize_t n;
        while ((n = recv(fd, buf, sizeof(buf), 0)) > 0)
            bytes += (uint64_t)n;
    }
    uint64_t el = now_ns() - start;
    close(fd);
    printf("{\"test\":\"%s\",\"seconds\":%.3f,\"bytes\":%llu,\"mbit_s\":%.2f,\"client_cpu_ms\":%.1f}\n",
           up ? "tcpup" : "tcpdown", el / 1e9, (unsigned long long)bytes, bytes * 8.0 / (el / 1e9) / 1e6,
           cpu_ms() - c0);
    return 0;
}

static int churn(const char *host, const char *port, int count)
{
    uint32_t *t = calloc((size_t)count, sizeof(uint32_t));
    int ok = 0, fail = 0;
    double c0 = cpu_ms();
    uint64_t start = now_ns();
    for (int i = 0; i < count; i++) {
        uint64_t t0 = now_ns();
        int fd = tcp_connect(host, port);
        if (fd < 0) {
            fail++;
            continue;
        }
        char cmd[5] = {'R'}, m[64] = {0};
        send(fd, cmd, 5, 0);
        send(fd, m, sizeof(m), 0);
        if (recv(fd, m, sizeof(m), MSG_WAITALL) == (ssize_t)sizeof(m))
            t[ok++] = (uint32_t)((now_ns() - t0) / 1000);
        else
            fail++;
        close(fd);
    }
    uint64_t el = now_ns() - start;
    qsort(t, (size_t)ok, sizeof(uint32_t), cmp_u32);
    size_t k = (size_t)ok;
    uint32_t *r = t;
    printf("{\"test\":\"churn\",\"count\":%d,\"ok\":%d,\"failed\":%d,\"seconds\":%.3f,"
           "\"conn_rr_us_p50\":%u,\"conn_rr_us_p95\":%u,\"conn_rr_us_p99\":%u,\"client_cpu_ms\":%.1f}\n",
           count, ok, fail, el / 1e9, PCT(0.5), PCT(0.95), PCT(0.99), cpu_ms() - c0);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc >= 3 && !strcmp(argv[1], "server"))
        return server(atoi(argv[2]));
    if (argc >= 7 && !strcmp(argv[1], "udp"))
        return udp_client(argv[2], argv[3], atof(argv[4]), atoi(argv[5]), atof(argv[6]));
    if (argc >= 5 && !strcmp(argv[1], "tcpup"))
        return tcp_bulk(argv[2], argv[3], 1, atof(argv[4]));
    if (argc >= 5 && !strcmp(argv[1], "tcpdown"))
        return tcp_bulk(argv[2], argv[3], 0, atof(argv[4]));
    if (argc >= 5 && !strcmp(argv[1], "churn"))
        return churn(argv[2], argv[3], atoi(argv[4]));
    fprintf(stderr, "usage: see source header\n");
    return 2;
}
