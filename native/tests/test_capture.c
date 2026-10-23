/* Capture pipeline fixture: synthetic packets -> tap -> ring -> writer -> PCAP (SLL).
 * Writes <dir>/fixture.pcap and <dir>/fixture.expected.json for the independent
 * Python parser + tshark validation (validation/scripts/check_fixture.py), and
 * checks drop accounting under a synthetic writer stall. */
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/resource.h>

#include "mpc/capture.h"
#include "testutil.h"

static const uint8_t APP4[4] = {10, 111, 0, 2};
static const uint8_t SRV4[4] = {93, 184, 216, 34};
static const uint8_t DNS4[4] = {192, 168, 1, 1};
static const uint8_t APP6[16] = {0xfd, 0x00, 0x6d, 0x70, 0x63, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
static const uint8_t SRV6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99};

typedef struct {
    int dir;
    uint32_t orig, cap;
    uint64_t ts_ns;
} expect_t;

static expect_t E[64];
static int NE;
static FILE *J;

static void feed(mpc_capture *c, int dir, const uint8_t *pkt, size_t len, uint64_t ts)
{
    uint32_t cl;
    uint8_t *slot = mpc_capture_begin(c, dir, ts, pkt, len, (uint32_t)len, &cl);
    CHECK(slot != NULL);
    if (!slot)
        return;
    memcpy(slot, pkt, cl);
    E[NE++] = (expect_t){dir, (uint32_t)len, cl, ts};
    mpc_capture_commit(c);
}

/* New-flow announcements seen by the (mimicked) Kotlin worker, by flow id. */
static uint64_t FIRST_SEEN[16];
static int ANNOUNCED;

static void poll_flows(mpc_capture *c)
{
    mpc_uid_request rq[16];
    int n = mpc_capture_uid_poll(c, rq, 16, 10);
    for (int i = 0; i < n; i++) {
        if (rq[i].flow_id < 16)
            FIRST_SEEN[rq[i].flow_id] = rq[i].first_seen_ns;
        ANNOUNCED++;
    }
}

static int fixture(const char *dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/fixture.pcap", dir);
    mpc_capture_config cfg = {.pcap_path = path,
                              .snaplen = 64,
                              .mtu = 1500,
                              .variant = MPC_VARIANT_E_UID,
                              .ring_bytes = 1 << 20};
    int err;
    mpc_capture *c = mpc_capture_create(&cfg, &err);
    CHECK(c != NULL);
    if (!c)
        return 1;
    CHECK_EQ(mpc_capture_start_writer(c), 0);
    uint64_t t0 = (uint64_t)c->anchor_boot_ns;
    uint8_t pkt[2048], payload[1400];
    for (size_t i = 0; i < sizeof(payload); i++)
        payload[i] = (uint8_t)i;
    size_t n;

    /* 1: TCP SYN UL (flow 1, uid pending) */
    n = build_tcp(pkt, 4, APP4, 40000, SRV4, 443, 1000, 0, 0x02, 65535, NULL, 0);
    feed(c, MPC_DIR_UPLINK, pkt, n, t0 + 1000);
    /* 2: SYN-ACK DL same flow */
    n = build_tcp(pkt, 4, SRV4, 443, APP4, 40000, 5000, 1001, 0x12, 65535, NULL, 0);
    feed(c, MPC_DIR_DOWNLINK, pkt, n, t0 + 2000);
    poll_flows(c);
    /* 3: data UL 1400 B -> truncated to 64 */
    n = build_tcp(pkt, 4, APP4, 40000, SRV4, 443, 1001, 5001, 0x18, 65535, payload, 1400);
    feed(c, MPC_DIR_UPLINK, pkt, n, t0 + 3000);
    /* 4: IPv6 UDP DNS-ish UL (flow 2), never resolved */
    n = build_udp(pkt, 6, APP6, 5353, SRV6, 53, payload, 20);
    feed(c, MPC_DIR_UPLINK, pkt, n, t0 + 4000);
    poll_flows(c);
    /* 5: IPv6 UDP DL reply same flow */
    n = build_udp(pkt, 6, SRV6, 53, APP6, 5353, payload, 100);
    feed(c, MPC_DIR_DOWNLINK, pkt, n, t0 + 5000);
    /* 6: ICMP echo (no flow) */
    uint8_t icmp[16] = {8, 0, 0, 0, 0, 1, 0, 1};
    n = build_ip(pkt, 4, APP4, DNS4, 1, icmp, sizeof(icmp), 0);
    feed(c, MPC_DIR_UPLINK, pkt, n, t0 + 6000);
    /* 7: non-initial fragment (no ports -> no flow) */
    n = build_ip(pkt, 4, APP4, SRV4, 17, payload, 100, 0x00b9);
    feed(c, MPC_DIR_UPLINK, pkt, n, t0 + 7000);
    /* 8: malformed 3-byte packet */
    uint8_t junk[3] = {0x45, 0, 0};
    feed(c, MPC_DIR_UPLINK, junk, 3, t0 + 8000);
    /* 9: zero-length packet */
    feed(c, MPC_DIR_UPLINK, junk, 0, t0 + 9000);
    /* 10: small UDP shorter than snaplen (exact length kept) */
    n = build_udp(pkt, 4, APP4, 6000, DNS4, 53, "abc", 3);
    feed(c, MPC_DIR_UPLINK, pkt, n, t0 + 10000);
    /* 11: TCP FIN then 12: new SYN on same tuple -> new generation (new flow id). */
    n = build_tcp(pkt, 4, APP4, 40000, SRV4, 443, 2401, 5001, 0x11, 65535, NULL, 0);
    feed(c, MPC_DIR_UPLINK, pkt, n, t0 + 11000);
    n = build_tcp(pkt, 4, APP4, 40000, SRV4, 443, 9000, 0, 0x02, 65535, NULL, 0);
    feed(c, MPC_DIR_UPLINK, pkt, n, t0 + 12000);

    poll_flows(c); /* flows 3, 4 */
    CHECK_EQ(mpc_capture_finish(c), 0);
    /* The request carries the exact timestamp of the flow's first packet (its first PCAP record). */
    CHECK_EQ(FIRST_SEEN[1], t0 + 1000);
    CHECK_EQ(FIRST_SEEN[2], t0 + 4000);
    CHECK_EQ(FIRST_SEEN[3], t0 + 10000);
    CHECK_EQ(FIRST_SEEN[4], t0 + 12000);
    uint64_t cnt[MPC_CNT__COUNT];
    mpc_capture_snapshot(c, cnt, MPC_CNT__COUNT);
    CHECK_EQ(cnt[MPC_CNT_records_written], NE);
    CHECK_EQ(cnt[MPC_CNT_capture_queue_drops_ul] + cnt[MPC_CNT_capture_queue_drops_dl], 0);
    CHECK_EQ(cnt[MPC_CNT_uid_requests_queued], 4); /* flows 1,2,3(udp v4),4(new gen) */
    CHECK_EQ(ANNOUNCED, 4); /* each flow generation announced exactly once */
    CHECK(cnt[MPC_CNT_capture_ring_peak_slots] <= (uint64_t)NE); /* real backlog, not ring size */
    CHECK_EQ(cnt[MPC_CNT_unparsable_packets], 2);
    CHECK_EQ(cnt[MPC_CNT_nonflow_packets], 2);

    snprintf(path, sizeof(path), "%s/fixture.expected.json", dir);
    J = fopen(path, "w");
    fprintf(J, "{\"snaplen\": %u, \"ip_snaplen\": 64,", MPC_HDR_MAX + 16);
    fprintf(J, " \"linktype\": 113, \"anchor_boot_ns\": %lld, \"anchor_real_ns\": %lld,\n \"records\": [\n",
            (long long)c->anchor_boot_ns, (long long)c->anchor_real_ns);
    for (int i = 0; i < NE; i++) {
        long long ts_ns = c->anchor_real_ns + ((long long)E[i].ts_ns - c->anchor_boot_ns);
        fprintf(J, "  {\"dir\": \"%s\", \"orig_len\": %u, \"cap_len\": %u, \"ts_ns\": %lld, \"boot_ns\": %llu}%s\n",
                E[i].dir == MPC_DIR_UPLINK ? "uplink" : "downlink", E[i].orig, E[i].cap, ts_ns,
                (unsigned long long)E[i].ts_ns, i + 1 < NE ? "," : "");
    }
    fprintf(J, " ]\n}\n");
    fclose(J);
    mpc_capture_destroy(c);
    return 0;
}

/* Writer stall: forwarding-side producer never blocks; drops are counted and
 * offered == written + dropped. */
static void stall(const char *dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/stall.pcap", dir);
    mpc_capture_config cfg = {.pcap_path = path, .snaplen = 256, .mtu = 1500,
                              .variant = MPC_VARIANT_D_WRITER, .ring_bytes = 64 * 1024};
    int err;
    mpc_capture *c = mpc_capture_create(&cfg, &err);
    CHECK(c != NULL);
    if (!c)
        return;
    CHECK_EQ(mpc_capture_start_writer(c), 0);
    mpc_capture_request_stall(c, 500);
    usleep(50 * 1000); /* writer is now sleeping in the stall */
    uint8_t pkt[2048], payload[1000] = {0};
    size_t n = build_udp(pkt, 4, APP4, 7000, SRV4, 9, payload, sizeof(payload));
    uint64_t offered = 0, accepted = 0;
    uint64_t t_start = mpc_now_boottime_ns();
    for (int i = 0; i < 5000; i++) {
        uint32_t cl;
        uint8_t *slot = mpc_capture_begin(c, MPC_DIR_UPLINK, mpc_now_boottime_ns(), pkt, n,
                                          (uint32_t)n, &cl);
        offered++;
        if (slot) {
            memcpy(slot, pkt, cl);
            mpc_capture_commit(c);
            accepted++;
        }
    }
    uint64_t t_prod = mpc_now_boottime_ns() - t_start;
    CHECK(t_prod < 400ull * 1000000ull); /* producer did not wait for the 500 ms stall */
    CHECK_EQ(mpc_capture_finish(c), 0);
    uint64_t cnt[MPC_CNT__COUNT];
    mpc_capture_snapshot(c, cnt, MPC_CNT__COUNT);
    uint64_t drops = cnt[MPC_CNT_capture_queue_drops_ul];
    CHECK(drops > 0);
    CHECK_EQ(cnt[MPC_CNT_records_written], accepted);
    CHECK_EQ(cnt[MPC_CNT_records_written] + drops, offered);
    CHECK_EQ(cnt[MPC_CNT_capture_ring_peak_slots], cnt[MPC_CNT_capture_ring_slots]);
    CHECK(cnt[MPC_CNT_writer_stall_ms] == 500);
    printf("stall: offered=%llu written=%llu dropped=%llu ring_slots=%llu producer_ms=%.2f\n",
           (unsigned long long)offered, (unsigned long long)cnt[MPC_CNT_records_written],
           (unsigned long long)drops, (unsigned long long)cnt[MPC_CNT_capture_ring_slots],
           t_prod / 1e6);
    mpc_capture_destroy(c);
}

/* Every record keeps at least the IP + transport header, whatever the configured length;
 * headers-only mode keeps exactly the headers. */
static uint32_t cap_of(mpc_capture *c, const uint8_t *pkt, size_t n)
{
    uint32_t cl = 0;
    uint8_t *slot = mpc_capture_begin(c, MPC_DIR_UPLINK, mpc_now_boottime_ns(), pkt, n, (uint32_t)n, &cl);
    CHECK(slot != NULL);
    if (slot) {
        memcpy(slot, pkt, cl);
        mpc_capture_commit(c);
    }
    return cl;
}

static void cap_of_dir(mpc_capture *c, int dir, const uint8_t *pkt, size_t n)
{
    uint32_t cl;
    uint8_t *slot = mpc_capture_begin(c, dir, mpc_now_boottime_ns(), pkt, n, (uint32_t)n, &cl);
    if (slot) {
        memcpy(slot, pkt, cl);
        mpc_capture_commit(c);
    }
}

static void header_floor(void)
{
    uint8_t pkt[2048], payload[1400] = {0};
    for (int mode = 0; mode < 2; mode++) {
        mpc_capture_config cfg = {.snaplen = mode ? MPC_SNAPLEN_HEADERS : 32, .mtu = 1500,
                                  .variant = MPC_VARIANT_C_COPY_NULL, .ring_bytes = 1 << 20};
        int err;
        mpc_capture *c = mpc_capture_create(&cfg, &err);
        CHECK(c != NULL);
        if (!c)
            return;
        CHECK_EQ(mpc_capture_start_writer(c), 0);
        size_t n = build_tcp(pkt, 4, APP4, 40000, SRV4, 443, 1, 2, 0x18, 65535, payload, 1000);
        CHECK_EQ(cap_of(c, pkt, n), 40); /* IPv4 20 + TCP 20 */
        n = build_tcp(pkt, 6, APP6, 40000, SRV6, 443, 1, 2, 0x18, 65535, payload, 1000);
        pkt[40 + 12] = 8 << 4; /* TCP data offset 32: 12 bytes of options (timestamps) */
        CHECK_EQ(cap_of(c, pkt, n), 72); /* IPv6 40 + TCP 32: the "normal case" */
        n = build_udp(pkt, 6, APP6, 5000, SRV6, 443, payload, 1200);
        CHECK_EQ(cap_of(c, pkt, n), 48); /* IPv6 40 + UDP 8 (e.g. QUIC) */
        uint8_t icmp[16] = {8, 0};
        n = build_ip(pkt, 4, APP4, DNS4, 1, icmp, sizeof(icmp), 0);
        CHECK_EQ(cap_of(c, pkt, n), mode ? 28 : 32); /* IPv4 20 + ICMP 8, or the 32 configured */
        n = build_tcp(pkt, 4, APP4, 40001, SRV4, 443, 1, 2, 0x02, 65535, NULL, 0);
        CHECK_EQ(cap_of(c, pkt, n), 40); /* bare SYN: whole packet */
        CHECK_EQ(mpc_capture_finish(c), 0);
        mpc_capture_destroy(c);
    }
    printf("header floor: IPv4+TCP 40, IPv6+TCP(opts) 72, IPv6+UDP 48 bytes kept with snaplen 32 and headers-only\n");
}

/* A flow whose announcement did not fit the full request queue is announced by a later
 * packet, so every flow eventually gets an owner lookup (and a FLOW_MAPPING). */
static void uid_request_retry(void)
{
    char path[] = "/tmp/mpc-retry-XXXXXX";
    int tfd = mkstemp(path);
    close(tfd);
    mpc_capture_config cfg = {.snaplen = 64, .mtu = 1500, .variant = MPC_VARIANT_E_UID, .ring_bytes = 4 << 20,
                              .pcap_path = path};
    int err;
    mpc_capture *c = mpc_capture_create(&cfg, &err);
    CHECK(c != NULL);
    if (!c)
        return;
    CHECK_EQ(mpc_capture_start_writer(c), 0);
    uint8_t pkt[128];
    int flows = 5000; /* > 4096 request slots */
    for (int i = 0; i < flows; i++) {
        size_t n = build_udp(pkt, 4, APP4, (uint16_t)(10000 + i), SRV4, 53, "q", 1);
        cap_of_dir(c, MPC_DIR_UPLINK, pkt, n);
    }
    uint64_t cnt[MPC_CNT__COUNT];
    mpc_capture_snapshot(c, cnt, MPC_CNT__COUNT);
    CHECK(cnt[MPC_CNT_uid_request_queue_overflows] > 0);
    mpc_uid_request rq[512];
    int got = 0, n;
    while ((n = mpc_capture_uid_poll(c, rq, 512, 0)) > 0)
        got += n;
    for (int i = 0; i < flows; i++) { /* second packet of every flow */
        size_t len = build_udp(pkt, 4, SRV4, 53, APP4, (uint16_t)(10000 + i), "r", 1);
        cap_of_dir(c, MPC_DIR_DOWNLINK, pkt, len);
    }
    while ((n = mpc_capture_uid_poll(c, rq, 512, 0)) > 0)
        got += n;
    CHECK_EQ(got, flows);
    CHECK_EQ(mpc_capture_finish(c), 0);
    mpc_capture_destroy(c);
    unlink(path);
    printf("uid request retry: %d flows announced after %llu queue overflows\n", got,
           (unsigned long long)cnt[MPC_CNT_uid_request_queue_overflows]);
}

/* Storage failure. (1) A device that rejects even the file header fails at start.
 * (2) A file that stops accepting data mid-capture (here: RLIMIT_FSIZE) is counted, not
 * fatal to the producer, and every offered record is either on disk or counted dropped. */
static void storage_error(const char *dir)
{
    if (access("/dev/full", W_OK) == 0) {
        mpc_capture_config full = {.pcap_path = "/dev/full", .snaplen = 128, .mtu = 1500,
                                   .variant = MPC_VARIANT_D_WRITER, .ring_bytes = 256 * 1024};
        int err;
        mpc_capture *c = mpc_capture_create(&full, &err);
        CHECK(c != NULL);
        if (c) {
            CHECK_EQ(mpc_capture_start_writer(c), -1);
            mpc_capture_destroy(c);
        }
    }
    char path[512];
    snprintf(path, sizeof(path), "%s/limited.pcap", dir);
    mpc_capture_config cfg = {.pcap_path = path, .snaplen = 128, .mtu = 1500,
                              .variant = MPC_VARIANT_D_WRITER, .ring_bytes = 1 << 20,
                              .writer_buf_bytes = 64 * 1024};
    int err;
    mpc_capture *c = mpc_capture_create(&cfg, &err);
    CHECK(c != NULL);
    if (!c)
        return;
    signal(SIGXFSZ, SIG_IGN); /* exceeding the limit -> EFBIG instead of a signal */
    struct rlimit old, lim = {.rlim_cur = 100 * 1024, .rlim_max = RLIM_INFINITY};
    getrlimit(RLIMIT_FSIZE, &old);
    lim.rlim_max = old.rlim_max;
    setrlimit(RLIMIT_FSIZE, &lim);
    CHECK_EQ(mpc_capture_start_writer(c), 0);
    uint8_t pkt[256], payload[100] = {0};
    size_t n = build_udp(pkt, 4, APP4, 7000, SRV4, 9, payload, sizeof(payload));
    const int offered = 5000; /* ~148 B per record: ~740 KB > 100 KB limit */
    for (int i = 0; i < offered; i++) {
        uint32_t cl;
        uint8_t *slot = mpc_capture_begin(c, MPC_DIR_UPLINK, mpc_now_boottime_ns(), pkt, n, (uint32_t)n, &cl);
        if (slot) {
            memcpy(slot, pkt, cl);
            mpc_capture_commit(c);
        }
    }
    CHECK_EQ(mpc_capture_finish(c), -1);
    setrlimit(RLIMIT_FSIZE, &old);
    uint64_t cnt[MPC_CNT__COUNT];
    mpc_capture_snapshot(c, cnt, MPC_CNT__COUNT);
    uint64_t q = cnt[MPC_CNT_capture_queue_drops_ul];
    CHECK(cnt[MPC_CNT_storage_errors] >= 1);
    CHECK(cnt[MPC_CNT_storage_dropped_records] > 0);
    CHECK_EQ(cnt[MPC_CNT_records_written] + cnt[MPC_CNT_storage_dropped_records] + q, (uint64_t)offered);
    CHECK(cnt[MPC_CNT_records_written] * 148 <= 100 * 1024); /* nothing counted that is not on disk */
    printf("storage error: %llu written, %llu dropped after the file stopped growing\n",
           (unsigned long long)cnt[MPC_CNT_records_written], (unsigned long long)cnt[MPC_CNT_storage_dropped_records]);
    mpc_capture_destroy(c);
    unlink(path);
}

/* V31: the forwarding-thread tap must not allocate. glibc mallinfo2() totals stay
 * unchanged across 200k begin/commit calls (flows created inside the bounded table). */
#include <malloc.h>
static void no_alloc_on_tap(void)
{
#if defined(__GLIBC__) && (__GLIBC__ > 2 || (__GLIBC__ == 2 && __GLIBC_MINOR__ >= 33))
    mpc_capture_config cfg = {.snaplen = 256, .mtu = 1500, .variant = MPC_VARIANT_C_COPY_NULL,
                              .ring_bytes = 4 << 20};
    int err;
    mpc_capture *c = mpc_capture_create(&cfg, &err);
    CHECK(c != NULL);
    if (!c)
        return;
    uint8_t pkt[2048];
    size_t n = build_udp(pkt, 4, APP4, 1, SRV4, 53, "q", 1);
    struct mallinfo2 m0 = mallinfo2();
    uint64_t ok = 0;
    for (int i = 0; i < 200000; i++) {
        pkt[20] = (uint8_t)(i >> 8); /* vary source port: new flows too */
        pkt[21] = (uint8_t)i;
        uint32_t cl;
        uint8_t *slot = mpc_capture_begin(c, i & 1 ? MPC_DIR_DOWNLINK : MPC_DIR_UPLINK,
                                          mpc_now_boottime_ns(), pkt, n, (uint32_t)n, &cl);
        if (slot) {
            memcpy(slot, pkt, cl);
            mpc_capture_commit(c);
            ok++;
        }
        if ((i & 1023) == 0) { /* emulate the consumer so the ring keeps accepting */
            uint64_t t;
            uint64_t avail = mpc_ring_available(&c->ring, &t);
            mpc_ring_release(&c->ring, t + avail);
        }
    }
    struct mallinfo2 m1 = mallinfo2();
    CHECK_EQ(m1.uordblks, m0.uordblks);
    CHECK_EQ(m1.hblkhd, m0.hblkhd);
    CHECK(ok > 0);
    printf("tap: %llu records, heap in-use delta=%lld bytes, mmap delta=%lld bytes\n",
           (unsigned long long)ok, (long long)(m1.uordblks - m0.uordblks), (long long)(m1.hblkhd - m0.hblkhd));
    mpc_capture_destroy(c);
#endif
}

int main(int argc, char **argv)
{
    const char *dir = argc > 1 ? argv[1] : ".";
    mkdir(dir, 0755);
    fixture(dir);
    stall(dir);
    header_floor();
    uid_request_retry();
    storage_error(dir);
    no_alloc_on_tap();
    TEST_DONE();
}
