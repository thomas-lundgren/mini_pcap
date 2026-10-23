/* Native capture-path micro-benchmark (host): cost of the forwarding-thread tap
 * (parse + flow lookup + ring copy) and writer throughput to a real file, per
 * snaplen mode. Prints one JSON line per mode; exits non-zero only on gross
 * regressions (generous thresholds, host-dependent numbers are reported, not gated).
 * Usage: bench_capture [packets] [outdir] */
#include <stdlib.h>
#include <unistd.h>

#include "mpc/capture.h"
#include "testutil.h"

static const uint8_t APP4[4] = {10, 111, 0, 2};
static const uint8_t SRV4[4] = {93, 184, 216, 34};
static const uint8_t APP6[16] = {0xfd, 0x00, 0x6d, 0x70, 0x63, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
static const uint8_t SRV6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99};

static int run(const char *name, uint32_t snaplen, long packets, const char *dir)
{
    char path[512];
    snprintf(path, sizeof(path), "%s/bench_%s.pcap", dir, name);
    mpc_capture_config cfg = {.pcap_path = path, .snaplen = snaplen, .mtu = 1500,
                              .variant = MPC_VARIANT_D_WRITER, .ring_bytes = 8 << 20};
    int err;
    mpc_capture *c = mpc_capture_create(&cfg, &err);
    if (!c)
        return 1;
    mpc_capture_start_writer(c);
    /* Traffic mix: 64 TCP flows (IPv4, 1400 B), 32 QUIC-like UDP flows (IPv6, 1200 B), small ACKs. */
    static uint8_t pkts[3][64][1600];
    static size_t lens[3][64];
    uint8_t payload[1400] = {0};
    for (int f = 0; f < 64; f++) {
        lens[0][f] = build_tcp(pkts[0][f], 4, APP4, (uint16_t)(40000 + f), SRV4, 443, 1, 2, 0x18, 65535, payload, 1360);
        lens[1][f] = build_udp(pkts[1][f], 6, APP6, (uint16_t)(50000 + f % 32), SRV6, 443, payload, 1152);
        lens[2][f] = build_tcp(pkts[2][f], 4, SRV4, 443, APP4, (uint16_t)(40000 + f), 2, 1, 0x10, 65535, NULL, 0);
    }
    uint64_t t0 = mpc_now_boottime_ns();
    for (long i = 0; i < packets; i++) {
        int kind = (int)(i % 4 == 3 ? 2 : i % 4 == 2 ? 1 : 0);
        int f = (int)((i / 4) % 64);
        uint32_t cl;
        int dir_ = kind == 2 ? MPC_DIR_DOWNLINK : MPC_DIR_UPLINK;
        uint8_t *slot = mpc_capture_begin(c, dir_, mpc_now_boottime_ns(), pkts[kind][f], lens[kind][f],
                                          (uint32_t)lens[kind][f], &cl);
        if (slot) {
            memcpy(slot, pkts[kind][f], cl);
            mpc_capture_commit(c);
        }
        if ((i & 255) == 0)
            mpc_capture_batch_done(c);
    }
    uint64_t t_prod = mpc_now_boottime_ns() - t0;
    mpc_capture_finish(c);
    uint64_t t_all = mpc_now_boottime_ns() - t0;
    uint64_t cnt[MPC_CNT__COUNT];
    mpc_capture_snapshot(c, cnt, MPC_CNT__COUNT);
    uint64_t drops = cnt[MPC_CNT_capture_queue_drops_ul] + cnt[MPC_CNT_capture_queue_drops_dl];
    double ns_pkt = (double)t_prod / (double)packets;
    printf("{\"mode\": \"%s\", \"packets\": %ld, \"tap_ns_per_packet\": %.1f, \"records_written\": %llu, "
           "\"drops\": %llu, \"file_bytes\": %llu, \"bytes_per_record\": %.1f, \"end_to_end_mrec_s\": %.2f, "
           "\"write_syscalls\": %llu}\n",
           name, packets, ns_pkt, (unsigned long long)cnt[MPC_CNT_records_written], (unsigned long long)drops,
           (unsigned long long)cnt[MPC_CNT_file_bytes],
           (double)cnt[MPC_CNT_file_bytes] / (double)(cnt[MPC_CNT_records_written] ? cnt[MPC_CNT_records_written] : 1),
           (double)cnt[MPC_CNT_records_written] / ((double)t_all / 1e9) / 1e6,
           (unsigned long long)cnt[MPC_CNT_write_syscalls]);
    CHECK_EQ(cnt[MPC_CNT_records_written] + drops, (uint64_t)packets); /* every packet accounted for */
    CHECK(ns_pkt < 2000.0);                                             /* gross-regression guard */
    mpc_capture_destroy(c);
    unlink(path);
    return 0;
}

int main(int argc, char **argv)
{
    long packets = argc > 1 ? atol(argv[1]) : 2000000;
    const char *dir = argc > 2 ? argv[2] : ".";
    run("headers_only", MPC_SNAPLEN_HEADERS, packets, dir);
    run("snap128", 128, packets, dir);
    run("snap256", 256, packets, dir);
    run("full", 0, packets, dir);
    TEST_DONE();
}
