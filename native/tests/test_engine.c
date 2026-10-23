/* Engine integration test on the host. A SOCK_SEQPACKET socketpair stands in
 * for the TUN device (packet boundaries preserved). The test plays the "app":
 * it injects raw IPv4 packets and checks the relayed replies from real local
 * UDP/TCP echo servers, then verifies capture counters and the PCAP output. */
#include <dirent.h>
#include <errno.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>

#include "mpc/engine.h"
#include "testutil.h"

static const uint8_t APP4[4] = {10, 111, 0, 2};
static uint16_t big_port, small_port; /* download servers: 1 MiB and 100 KB, then FIN */
#define BIG_BYTES (1u << 20)
#define SMALL_BYTES (100u * 1024)
static uint8_t HOST4[4];
static int tun_app; /* test side of the fake TUN */
static uint16_t udp_port, tcp_port;

static int host_ipv4(uint8_t out[4])
{
    struct ifaddrs *ifa, *i;
    if (getifaddrs(&ifa) != 0)
        return -1;
    int found = -1;
    for (i = ifa; i; i = i->ifa_next) {
        if (!i->ifa_addr || i->ifa_addr->sa_family != AF_INET)
            continue;
        struct sockaddr_in *a = (struct sockaddr_in *)i->ifa_addr;
        uint32_t ip = ntohl(a->sin_addr.s_addr);
        if ((ip >> 24) == 127)
            continue;
        memcpy(out, &a->sin_addr.s_addr, 4);
        found = 0;
        break;
    }
    freeifaddrs(ifa);
    return found;
}

static void *udp_echo(void *arg)
{
    int fd = *(int *)arg;
    char buf[2048];
    for (;;) {
        struct sockaddr_storage ss;
        socklen_t sl = sizeof(ss);
        ssize_t n = recvfrom(fd, buf, sizeof(buf), 0, (struct sockaddr *)&ss, &sl);
        if (n <= 0)
            break;
        sendto(fd, buf, (size_t)n, 0, (struct sockaddr *)&ss, sl);
    }
    return NULL;
}

static void *tcp_echo(void *arg)
{
    int lfd = *(int *)arg;
    int c = accept(lfd, NULL, NULL);
    if (c < 0)
        return NULL;
    char buf[4096];
    ssize_t n;
    while ((n = recv(c, buf, sizeof(buf), 0)) > 0)
        send(c, buf, (size_t)n, 0);
    close(c);
    return NULL;
}

/* Position-dependent pattern: a dropped or duplicated block is detected at its offset. */
static uint8_t pattern(uint32_t i) { return (uint8_t)(i * 131u + (i >> 16) * 7u + 1u); }

typedef struct {
    int lfd;
    uint32_t bytes;
} blast_arg;

/* Sends the pattern as fast as the socket accepts it, in large writes, then closes (FIN). */
static void *blast(void *arg)
{
    blast_arg *a = arg;
    int c = accept(a->lfd, NULL, NULL);
    if (c < 0)
        return NULL;
    static uint8_t buf[256 * 1024];
    uint32_t off = 0;
    while (off < a->bytes) {
        uint32_t n = a->bytes - off < sizeof(buf) ? a->bytes - off : (uint32_t)sizeof(buf);
        for (uint32_t i = 0; i < n; i++)
            buf[i] = pattern(off + i);
        ssize_t w = send(c, buf, n, 0);
        if (w <= 0)
            break;
        off += (uint32_t)w;
    }
    close(c);
    return NULL;
}

static uint16_t start_blast(uint32_t bytes)
{
    static blast_arg args[2];
    static int used;
    blast_arg *a = &args[used++];
    struct sockaddr_in addr = {.sin_family = AF_INET};
    socklen_t sl = sizeof(addr);
    a->lfd = socket(AF_INET, SOCK_STREAM, 0);
    a->bytes = bytes;
    bind(a->lfd, (struct sockaddr *)&addr, sizeof(addr));
    listen(a->lfd, 1);
    getsockname(a->lfd, (struct sockaddr *)&addr, &sl);
    pthread_t t;
    pthread_create(&t, NULL, blast, a);
    pthread_detach(t);
    return ntohs(addr.sin_port);
}

static int start_servers(void)
{
    static int ufd, tfd;
    struct sockaddr_in a = {.sin_family = AF_INET};
    socklen_t sl = sizeof(a);
    ufd = socket(AF_INET, SOCK_DGRAM, 0);
    bind(ufd, (struct sockaddr *)&a, sizeof(a));
    getsockname(ufd, (struct sockaddr *)&a, &sl);
    udp_port = ntohs(a.sin_port);
    tfd = socket(AF_INET, SOCK_STREAM, 0);
    a.sin_port = 0;
    bind(tfd, (struct sockaddr *)&a, sizeof(a));
    listen(tfd, 4);
    sl = sizeof(a);
    getsockname(tfd, (struct sockaddr *)&a, &sl);
    tcp_port = ntohs(a.sin_port);
    pthread_t t1, t2;
    pthread_create(&t1, NULL, udp_echo, &ufd);
    pthread_create(&t2, NULL, tcp_echo, &tfd);
    pthread_detach(t1);
    pthread_detach(t2);
    big_port = start_blast(BIG_BYTES);
    small_port = start_blast(SMALL_BYTES);
    return 0;
}

/* utime + stime of the engine thread ("mpc-engine") in clock ticks, or -1. */
static long engine_cpu_ticks(void)
{
    DIR *d = opendir("/proc/self/task");
    if (!d)
        return -1;
    long ticks = -1;
    struct dirent *e;
    char path[300], buf[1024];
    while ((e = readdir(d)) != NULL && ticks < 0) {
        if (e->d_name[0] == '.')
            continue;
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", e->d_name);
        FILE *f = fopen(path, "r");
        if (!f)
            continue;
        int ok = fgets(buf, sizeof(buf), f) && strncmp(buf, "mpc-engine", 10) == 0;
        fclose(f);
        if (!ok)
            continue;
        snprintf(path, sizeof(path), "/proc/self/task/%s/stat", e->d_name);
        f = fopen(path, "r");
        if (!f)
            break;
        size_t n = fread(buf, 1, sizeof(buf) - 1, f);
        fclose(f);
        buf[n] = 0;
        char *p = strrchr(buf, ')'); /* after the comm: state, then fields 4..13, utime, stime */
        long ut = 0, st = 0;
        if (p && sscanf(p + 2, "%*c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %ld %ld", &ut, &st) == 2)
            ticks = ut + st;
    }
    closedir(d);
    return ticks;
}

/* Reads packets from the fake TUN until one matches proto (and optional tcp flag
 * mask), or timeout. Returns length. */
static ssize_t recv_pkt(uint8_t *buf, size_t cap, uint8_t proto, uint8_t need_flags, int timeout_ms)
{
    for (;;) {
        struct pollfd p = {.fd = tun_app, .events = POLLIN};
        if (poll(&p, 1, timeout_ms) <= 0)
            return -1;
        ssize_t n = recv(tun_app, buf, cap, 0);
        if (n < 20)
            continue;
        if (buf[9] != proto)
            continue;
        if (proto == 6) {
            size_t ihl = (buf[0] & 15) * 4;
            if ((buf[ihl + 13] & need_flags) != need_flags)
                continue;
        }
        return n;
    }
}

static void test_udp(void)
{
    uint8_t pkt[2048];
    const char msg[] = "ping-udp";
    size_t n = build_udp(pkt, 4, APP4, 5555, HOST4, udp_port, msg, sizeof(msg));
    CHECK_EQ(send(tun_app, pkt, n, 0), (ssize_t)n);
    ssize_t r = recv_pkt(pkt, sizeof(pkt), 17, 0, 2000);
    CHECK(r > 28);
    if (r <= 28)
        return;
    CHECK(memcmp(pkt + 12, HOST4, 4) == 0);
    CHECK(memcmp(pkt + 16, APP4, 4) == 0);
    CHECK_EQ(rd16be(pkt + 20), udp_port);
    CHECK_EQ(rd16be(pkt + 22), 5555);
    CHECK(memcmp(pkt + 28, msg, sizeof(msg)) == 0);
    /* Second datagram reuses the lwIP session. */
    n = build_udp(pkt, 4, APP4, 5555, HOST4, udp_port, "again", 5);
    send(tun_app, pkt, n, 0);
    r = recv_pkt(pkt, sizeof(pkt), 17, 0, 2000);
    CHECK(r == 28 + 5 && memcmp(pkt + 28, "again", 5) == 0);
}

static void test_tcp(void)
{
    uint8_t pkt[2048];
    uint32_t iss = 1000;
    size_t n = build_tcp(pkt, 4, APP4, 40001, HOST4, tcp_port, iss, 0, 0x02, 65535, NULL, 0);
    send(tun_app, pkt, n, 0);
    ssize_t r = recv_pkt(pkt, sizeof(pkt), 6, 0x12, 2000);
    CHECK(r >= 40);
    if (r < 40)
        return;
    uint32_t srv_seq = rd32be(pkt + 24);
    CHECK_EQ(rd32be(pkt + 28), iss + 1);
    CHECK(memcmp(pkt + 12, HOST4, 4) == 0);
    uint32_t seq = iss + 1, ack = srv_seq + 1;
    n = build_tcp(pkt, 4, APP4, 40001, HOST4, tcp_port, seq, ack, 0x10, 65535, NULL, 0);
    send(tun_app, pkt, n, 0);
    const char msg[] = "hello-tcp";
    n = build_tcp(pkt, 4, APP4, 40001, HOST4, tcp_port, seq, ack, 0x18, 65535, msg, sizeof(msg));
    send(tun_app, pkt, n, 0);
    seq += sizeof(msg);
    /* Collect echoed payload (may arrive with ACK-only segments in between). */
    char got[64] = {0};
    size_t gotn = 0;
    for (int tries = 0; tries < 10 && gotn < sizeof(msg); tries++) {
        r = recv_pkt(pkt, sizeof(pkt), 6, 0x10, 2000);
        if (r < 40)
            break;
        size_t ihl = (pkt[0] & 15) * 4, thl = (pkt[ihl + 12] >> 4) * 4;
        size_t plen = (size_t)r - ihl - thl;
        if (plen && gotn + plen <= sizeof(got)) {
            memcpy(got + gotn, pkt + ihl + thl, plen);
            gotn += plen;
            ack = rd32be(pkt + ihl + 4) + (uint32_t)plen;
        }
    }
    CHECK_EQ(gotn, sizeof(msg));
    CHECK(memcmp(got, msg, sizeof(msg)) == 0);
    /* Close from the app side. */
    n = build_tcp(pkt, 4, APP4, 40001, HOST4, tcp_port, seq, ack, 0x11, 65535, NULL, 0);
    send(tun_app, pkt, n, 0);
    r = recv_pkt(pkt, sizeof(pkt), 6, 0x01, 2000); /* server FIN relayed back */
    CHECK(r >= 40);
    if (r >= 40) {
        n = build_tcp(pkt, 4, APP4, 40001, HOST4, tcp_port, seq + 1, rd32be(pkt + 24) + 1, 0x10,
                      65535, NULL, 0);
        send(tun_app, pkt, n, 0);
    }
}

/* Downloads `bytes` through the relay, ACKing in order with a 64 KiB window. If stall_ms,
 * stops reading for that long right after the handshake while measuring engine CPU.
 * Returns bytes received in order and verified against the pattern. */
static uint32_t tcp_download(uint16_t port, uint16_t sport, uint32_t bytes, int stall_ms, long *stall_ticks)
{
    uint8_t pkt[2048];
    uint32_t iss = 5000;
    size_t n = build_tcp(pkt, 4, APP4, sport, HOST4, port, iss, 0, 0x02, 65535, NULL, 0);
    send(tun_app, pkt, n, 0);
    ssize_t r = recv_pkt(pkt, sizeof(pkt), 6, 0x12, 2000);
    if (r < 40)
        return 0;
    uint32_t base = rd32be(pkt + 24) + 1, ack = base, got = 0;
    int bad = 0, fin = 0;
    n = build_tcp(pkt, 4, APP4, sport, HOST4, port, iss + 1, ack, 0x10, 65535, NULL, 0);
    send(tun_app, pkt, n, 0);
    if (stall_ms) {
        usleep(200 * 1000); /* let the relay read everything and see the server's FIN */
        long t0 = engine_cpu_ticks();
        usleep((useconds_t)stall_ms * 1000);
        long t1 = engine_cpu_ticks();
        *stall_ticks = t0 >= 0 && t1 >= 0 ? t1 - t0 : -1;
    }
    while (!fin) {
        r = recv_pkt(pkt, sizeof(pkt), 6, 0, 3000);
        if (r < 40)
            break;
        size_t ihl = (pkt[0] & 15) * 4, thl = (pkt[ihl + 12] >> 4) * 4;
        uint32_t seq = rd32be(pkt + ihl + 4);
        size_t plen = (size_t)r - ihl - thl;
        if (seq == ack && plen) {
            for (size_t i = 0; i < plen; i++)
                bad += pkt[ihl + thl + i] != pattern(got + (uint32_t)i);
            got += (uint32_t)plen;
            ack += (uint32_t)plen;
        }
        if ((pkt[ihl + 13] & 0x01) && seq + plen == ack) {
            ack += 1;
            fin = 1;
        }
        n = build_tcp(pkt, 4, APP4, sport, HOST4, port, iss + 1, ack, fin ? 0x11 : 0x10, 65535, NULL, 0);
        send(tun_app, pkt, n, 0);
    }
    CHECK(fin);
    CHECK_EQ(bad, 0);
    return got;
}

/* Fast download with large server writes: every byte arrives, in order (regression: a
 * 64 KiB socket read was handed to lwIP as a 0-byte write and silently lost). */
static void test_tcp_download(void)
{
    uint32_t got = tcp_download(big_port, 40100, BIG_BYTES, 0, NULL);
    CHECK_EQ(got, BIG_BYTES);
    printf("tcp download: %u of %u bytes verified\n", got, BIG_BYTES);
}

/* App stops reading after the server has closed: the engine must sleep, not spin on a
 * level-triggered RDHUP/HUP it cannot act on (regression: 100 % CPU until the app read). */
static void test_tcp_stalled_reader(void)
{
    long ticks = -1;
    long hz = sysconf(_SC_CLK_TCK);
    uint32_t got = tcp_download(small_port, 40101, SMALL_BYTES, 1000, &ticks);
    CHECK_EQ(got, SMALL_BYTES);
    CHECK(ticks >= 0 && ticks * 10 < hz); /* < 10 % of one core during the 1 s stall */
    printf("stalled reader: engine used %ld/%ld ticks during a 1 s stall, %u bytes verified\n", ticks, hz, got);
}

static void test_refused(void)
{
    /* Connect to a closed port: relay connect fails -> RST to the app. */
    uint8_t pkt[2048];
    size_t n = build_tcp(pkt, 4, APP4, 40002, HOST4, 1, 77, 0, 0x02, 65535, NULL, 0);
    send(tun_app, pkt, n, 0);
    ssize_t r = recv_pkt(pkt, sizeof(pkt), 6, 0x12, 2000);
    CHECK(r >= 40);
    n = build_tcp(pkt, 4, APP4, 40002, HOST4, 1, 78, rd32be(pkt + 24) + 1, 0x10, 65535, NULL, 0);
    send(tun_app, pkt, n, 0);
    r = recv_pkt(pkt, sizeof(pkt), 6, 0x04, 2000);
    CHECK(r >= 40);
}

int main(void)
{
    if (host_ipv4(HOST4) != 0) {
        printf("SKIP: no non-loopback IPv4 address\n");
        return 0;
    }
    start_servers();
    int sp[2];
    CHECK_EQ(socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sp), 0);
    tun_app = sp[1];
    mkdir("engine_out", 0755);
    mpc_capture_config cfg = {.pcap_path = "engine_out/engine.pcap",
                              .snaplen = 256,
                              .mtu = 1500,
                              .variant = MPC_VARIANT_E_UID,
                              .ring_bytes = 1 << 20};
    int err;
    mpc_session *s = mpc_session_start(sp[0], &cfg, &err);
    CHECK(s != NULL);
    if (!s)
        TEST_DONE();
    /* Second session while one is active must be refused (lwIP global state). */
    int sp2[2];
    socketpair(AF_UNIX, SOCK_SEQPACKET, 0, sp2);
    CHECK(mpc_session_start(sp2[0], &cfg, &err) == NULL && err == EBUSY);
    close(sp2[1]);

    test_udp();
    test_tcp();
    test_tcp_download();
    test_tcp_stalled_reader();
    test_refused();
    usleep(100 * 1000);

    mpc_capture *c = mpc_session_capture(s);
    CHECK_EQ(mpc_session_stop(s), 0);
    CHECK_EQ(mpc_session_stop(s), 0); /* idempotent */
    uint64_t cnt[MPC_CNT__COUNT];
    mpc_capture_snapshot(c, cnt, MPC_CNT__COUNT);
    for (int i = 0; i < MPC_CNT__COUNT; i++)
        printf("  %s=%llu\n", mpc_counter_names[i], (unsigned long long)cnt[i]);
    CHECK_EQ(cnt[MPC_CNT_udp_sessions_total], 1);
    CHECK_EQ(cnt[MPC_CNT_tcp_conns_total], 4);
    CHECK_EQ(cnt[MPC_CNT_tcp_connect_failures], 1);
    CHECK_EQ(cnt[MPC_CNT_records_written], cnt[MPC_CNT_pkts_ul] + cnt[MPC_CNT_pkts_dl]);
    CHECK(cnt[MPC_CNT_pkts_ul] >= 9 && cnt[MPC_CNT_pkts_dl] >= 6);
    CHECK_EQ(cnt[MPC_CNT_capture_queue_drops_ul] + cnt[MPC_CNT_capture_queue_drops_dl], 0);
    CHECK_EQ(cnt[MPC_CNT_flows_created], 5);
    CHECK_EQ(cnt[MPC_CNT_engine_running], 0);
    /* The fake TUN was closed by the engine. */
    uint8_t b[16];
    CHECK_EQ(recv(tun_app, b, sizeof(b), MSG_DONTWAIT), 0);
    mpc_session_destroy(s);
    TEST_DONE();
}
