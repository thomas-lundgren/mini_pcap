/* Capture pipeline fixture: synthetic packets -> tap -> ring -> writer -> PCAP (SLL).
 * Writes <dir>/fixture.pcap and <dir>/fixture.expected.json for the independent
 * Python parser + tshark validation (validation/scripts/check_fixture.py), and
 * checks drop accounting under a synthetic writer stall. */
#include <errno.h>
#include <sys/stat.h>
#include <unistd.h>

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
    uint64_t flow;
    int32_t uid;
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
    const mpc_rec_hdr *h = (const mpc_rec_hdr *)slot - 1;
    E[NE++] = (expect_t){dir, (uint32_t)len, cl, h->flow_id, h->uid, ts};
    mpc_capture_commit(c);
}

/* First-seen timestamps reported in UID requests, by flow id. */
static uint64_t FIRST_SEEN[16];

static void deliver(mpc_capture *c, uint64_t flow_id, int32_t uid)
{
    /* Mimic Kotlin: poll requests, answer the matching one. */
    mpc_uid_request rq[16];
    int n = mpc_capture_uid_poll(c, rq, 16, 10);
    for (int i = 0; i < n; i++) {
        if (rq[i].flow_id < 16)
            FIRST_SEEN[rq[i].flow_id] = rq[i].first_seen_ns;
        if (rq[i].flow_id != flow_id)
            continue;
        mpc_uid_resolution r = {.flow_id = flow_id, .uid = uid, .key = rq[i].key};
        CHECK_EQ(mpc_capture_uid_deliver(c, &r, 1), 1);
    }
    mpc_capture_apply_uids(c); /* normally on the forwarding thread via eventfd */
}

static int fixture(const char *dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/fixture.pcap", dir);
    mpc_capture_config cfg = {.pcap_path = path,
                              .snaplen = 64,
                              .mtu = 1500,
                              .variant = MPC_VARIANT_E_UID,
                              .ring_bytes = 1 << 20,
                              .if_name = "tun0",
                              .userappl = "mini_pcap_collect test_capture",
                              .os = "host-test"};
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
    /* UID resolution arrives after the first two packets. */
    deliver(c, 1, 10234);
    /* 3: data UL 1400 B -> truncated to 64 */
    n = build_tcp(pkt, 4, APP4, 40000, SRV4, 443, 1001, 5001, 0x18, 65535, payload, 1400);
    feed(c, MPC_DIR_UPLINK, pkt, n, t0 + 3000);
    /* 4: IPv6 UDP DNS-ish UL (flow 2), never resolved */
    n = build_udp(pkt, 6, APP6, 5353, SRV6, 53, payload, 20);
    feed(c, MPC_DIR_UPLINK, pkt, n, t0 + 4000);
    deliver(c, 2, -1); /* INVALID_UID */
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

    deliver(c, 99, 0); /* collect the remaining requests (flows 3, 4) */
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
    CHECK_EQ(cnt[MPC_CNT_uid_resolutions_applied], 2);
    CHECK_EQ(cnt[MPC_CNT_unparsable_packets], 2);
    CHECK_EQ(cnt[MPC_CNT_nonflow_packets], 2);

    /* Expected flow/uid assignments. */
    CHECK(E[0].flow == 1 && E[0].uid == -1);
    CHECK(E[1].flow == 1 && E[1].uid == -1);
    CHECK(E[2].flow == 1 && E[2].uid == 10234 && E[2].cap == 64 && E[2].orig == 1440);
    CHECK(E[3].flow == 2 && E[3].uid == -1);
    CHECK(E[4].flow == 2 && E[4].uid == -1);
    CHECK(E[5].flow == 0 && E[6].flow == 0 && E[7].flow == 0 && E[8].flow == 0);
    CHECK(E[9].flow == 3);
    CHECK(E[10].flow == 1 && E[10].uid == 10234);
    CHECK(E[11].flow == 4 && E[11].uid == -1);

    snprintf(path, sizeof(path), "%s/fixture.expected.json", dir);
    J = fopen(path, "w");
    fprintf(J, "{\"snaplen\": %u, \"ip_snaplen\": 64,", MPC_HDR_MAX + 16);
    fprintf(J, " \"linktype\": 113, \"anchor_boot_ns\": %lld, \"anchor_real_ns\": %lld,\n \"records\": [\n",
            (long long)c->anchor_boot_ns, (long long)c->anchor_real_ns);
    for (int i = 0; i < NE; i++) {
        long long ts_ns = c->anchor_real_ns + ((long long)E[i].ts_ns - c->anchor_boot_ns);
        fprintf(J, "  {\"dir\": \"%s\", \"orig_len\": %u, \"cap_len\": %u, \"flow_id\": %llu, \"uid\": %d, \"ts_ns\": %lld, \"boot_ns\": %llu}%s\n",
                E[i].dir == MPC_DIR_UPLINK ? "uplink" : "downlink", E[i].orig, E[i].cap,
                (unsigned long long)E[i].flow, E[i].uid, ts_ns, (unsigned long long)E[i].ts_ns,
                i + 1 < NE ? "," : "");
    }
    fprintf(J, " ],\n \"flow_uid_map\": {\"1\": 10234}\n}\n");
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

/* Storage failure: writing to a full device is counted, not fatal to the producer. */
static void storage_error(void)
{
    if (access("/dev/full", W_OK) != 0)
        return;
    mpc_capture_config cfg = {.pcap_path = "/dev/full", .snaplen = 128, .mtu = 1500,
                              .variant = MPC_VARIANT_D_WRITER, .ring_bytes = 256 * 1024};
    int err;
    mpc_capture *c = mpc_capture_create(&cfg, &err);
    CHECK(c != NULL);
    if (!c)
        return;
    CHECK_EQ(mpc_capture_start_writer(c), 0);
    uint8_t pkt[256];
    size_t n = build_udp(pkt, 4, APP4, 7000, SRV4, 9, "x", 1);
    for (int i = 0; i < 100; i++) {
        uint32_t cl;
        uint8_t *slot = mpc_capture_begin(c, MPC_DIR_UPLINK, mpc_now_boottime_ns(), pkt, n,
                                          (uint32_t)n, &cl);
        if (slot) {
            memcpy(slot, pkt, cl);
            mpc_capture_commit(c);
        }
    }
    CHECK_EQ(mpc_capture_finish(c), -1);
    uint64_t cnt[MPC_CNT__COUNT];
    mpc_capture_snapshot(c, cnt, MPC_CNT__COUNT);
    CHECK(cnt[MPC_CNT_storage_errors] >= 1);
    CHECK_EQ(cnt[MPC_CNT_storage_dropped_records], 100);
    mpc_capture_destroy(c);
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
    storage_error();
    no_alloc_on_tap();
    TEST_DONE();
}
