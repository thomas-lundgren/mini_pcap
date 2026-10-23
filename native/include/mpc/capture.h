/* Capture pipeline: forwarding-thread tap -> SPSC prefix ring -> writer thread -> PCAP.
 * The tap never blocks, allocates, formats or performs I/O. New flows are announced to
 * the (Kotlin) owner-lookup worker through a second SPSC ring; nothing flows back. */
#ifndef MPC_CAPTURE_H
#define MPC_CAPTURE_H

#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "mpc/flow.h"
#include "mpc/ring.h"

/* Benchmark variants (docs/PERFORMANCE_PLAN.md section 3). F differs from E only
 * in Kotlin-side features (measurement collectors, notification updates). */
enum {
    MPC_VARIANT_B_FORWARD_ONLY = 1,
    MPC_VARIANT_C_COPY_NULL = 2,
    MPC_VARIANT_D_WRITER = 3,
    MPC_VARIANT_E_UID = 4,
    MPC_VARIANT_F_FULL = 5,
};

/* Counter list: single source of truth for native snapshot order and the names
 * exported to Kotlin (CAPTURE_STATS / SESSION_END records, benchmark output). */
#define MPC_COUNTERS(X)            \
    X(pkts_ul)                     \
    X(pkts_dl)                     \
    X(bytes_ul)                    \
    X(bytes_dl)                    \
    X(capture_queue_drops_ul)      \
    X(capture_queue_drops_dl)      \
    X(unparsable_packets)          \
    X(nonflow_packets)             \
    X(flows_created)               \
    X(flows_expired)               \
    X(flow_table_full)             \
    X(uid_requests_queued)         \
    X(uid_request_queue_overflows) \
    X(records_written)             \
    X(records_discarded_null)      \
    X(captured_bytes)              \
    X(file_bytes)                  \
    X(write_syscalls)              \
    X(storage_errors)              \
    X(storage_dropped_records)     \
    X(writer_stall_ms)             \
    X(capture_ring_peak_slots)     \
    X(capture_ring_slots)          \
    X(capture_ring_slot_bytes)     \
    X(tun_read_packets)            \
    X(tun_read_errors)             \
    X(tun_write_errors)            \
    X(tun_read_batches)            \
    X(forward_alloc_failures)      \
    X(forwarding_errors)           \
    X(tcp_conns_total)             \
    X(tcp_conns_active)            \
    X(tcp_connect_failures)        \
    X(udp_sessions_total)          \
    X(udp_sessions_active)         \
    X(udp_send_errors)             \
    X(anchor_boottime_ns)          \
    X(anchor_realtime_ns)          \
    X(engine_running)

typedef struct {
#define MPC_CNT_FIELD(name) _Atomic uint64_t name;
    MPC_COUNTERS(MPC_CNT_FIELD)
#undef MPC_CNT_FIELD
} mpc_counters;

enum {
#define MPC_CNT_ENUM(name) MPC_CNT_##name,
    MPC_COUNTERS(MPC_CNT_ENUM)
#undef MPC_CNT_ENUM
        MPC_CNT__COUNT
};

extern const char *const mpc_counter_names[MPC_CNT__COUNT];

/* Single-writer counters: plain relaxed load+store (no RMW atomics on hot path). */
#define MPC_CINC(c, field, v)                                                              \
    atomic_store_explicit(&(c)->field,                                                     \
                          atomic_load_explicit(&(c)->field, memory_order_relaxed) + (v), \
                          memory_order_relaxed)
#define MPC_CSET(c, field, v) atomic_store_explicit(&(c)->field, (v), memory_order_relaxed)

#define MPC_SNAPLEN_HEADERS 0xFFFFFFFFu
/* Largest header prefix guaranteed in a record: IPv4 60 + TCP 60, or IPv6 40 +
 * extension headers + TCP 60. Longer header chains are cut at this length. */
#define MPC_HDR_MAX 192u

/* Record header stored at the start of every ring slot, followed by the packet prefix. */
typedef struct {
    uint64_t ts_ns; /* CLOCK_BOOTTIME at the capture point */
    uint32_t orig_len;
    uint16_t cap_len;
    uint8_t dir;
    uint8_t pad;
} mpc_rec_hdr; /* 16 bytes */

/* New-flow announcement (native -> Kotlin), 56 bytes, little endian. first_seen_ns is
 * the CLOCK_BOOTTIME timestamp of the flow's first packet (its first PCAP record unless
 * that record was dropped), so the analyzer matches FLOW_MAPPING by 5-tuple and time. */
typedef struct {
    uint64_t flow_id;
    mpc_flow_key key;
    uint64_t first_seen_ns;
} mpc_uid_request;

typedef struct {
    const char *pcap_path; /* NULL allowed for variants B/C */
    /* Bytes of IP packet to keep; 0 = full packet (mtu); MPC_SNAPLEN_HEADERS = headers only.
     * Every record keeps at least the IP + transport header (up to MPC_HDR_MAX bytes). */
    uint32_t snaplen;
    uint32_t mtu;
    int variant;
    size_t ring_bytes;
    size_t writer_buf_bytes;
    uint32_t flow_capacity;
} mpc_capture_config;

typedef struct mpc_capture {
    mpc_capture_config cfg;
    int tap_enabled;
    int uid_enabled;
    int write_file;
    uint32_t snap;     /* configured IP prefix; 0 in headers-only mode */
    uint32_t slot_cap; /* bytes a slot can hold: max(snap, MPC_HDR_MAX) */

    mpc_counters cnt;
    mpc_flow_table flows;
    mpc_ring ring;
    mpc_ring uid_req;
    int uid_req_efd; /* signalled when new flow announcements are queued */
    int writer_efd;  /* wakes the writer early */
    int uid_req_pending_signal;

    /* writer thread */
    pthread_t writer_thread;
    int writer_started;
    _Atomic int writer_stop;
    _Atomic int writer_sleeping;
    _Atomic uint32_t stall_request_ms;
    _Atomic int session_closed;
    int fd;
    uint8_t *wbuf;
    size_t wlen;
    uint64_t wrecords; /* records in wbuf, counted as written only once on disk */
    uint64_t ring_peak; /* writer-observed ring occupancy high watermark */
    int64_t anchor_boot_ns;
    int64_t anchor_real_ns;
} mpc_capture;

uint64_t mpc_now_boottime_ns(void);

/* Allocates every bounded pool up front. Returns NULL on failure (errno code in *err;
 * EINVAL for an MTU outside [576, 65535]). */
mpc_capture *mpc_capture_create(const mpc_capture_config *cfg, int *err);
int mpc_capture_start_writer(mpc_capture *c);
/* Called after the forwarding thread has stopped: drain, flush, fsync, close. */
int mpc_capture_finish(mpc_capture *c);
void mpc_capture_destroy(mpc_capture *c);

/* --- Forwarding-thread API (hot path) --- */

/* Observe one packet. hdr/hdr_len: contiguous leading bytes, which must include the IP
 * and transport headers when the packet has them (callers with chained buffers copy up
 * to MPC_HDR_MAX bytes first). Returns a pointer where the caller copies *cap_len bytes
 * then calls mpc_capture_commit(), or NULL if the record is not captured (drop counted). */
uint8_t *mpc_capture_begin(mpc_capture *c, int dir, uint64_t ts_ns, const uint8_t *hdr,
                           size_t hdr_len, uint32_t total_len, uint32_t *cap_len);
static inline void mpc_capture_commit(mpc_capture *c) { mpc_ring_commit(&c->ring); }

/* Once per forwarding loop iteration: deliver pending signals (UID worker, writer). */
void mpc_capture_batch_done(mpc_capture *c);
/* About 1 Hz: expire idle flows. */
void mpc_capture_housekeeping(mpc_capture *c, uint64_t now_ns);

/* --- Control-plane API (any thread) --- */
void mpc_capture_snapshot(mpc_capture *c, uint64_t *out, size_t n);
/* Blocks up to timeout_ms; copies up to max requests. Returns count, or -1 once closed. */
int mpc_capture_uid_poll(mpc_capture *c, mpc_uid_request *out, int max, int timeout_ms);
void mpc_capture_request_stall(mpc_capture *c, uint32_t ms);
void mpc_capture_close_uid(mpc_capture *c);

#endif
