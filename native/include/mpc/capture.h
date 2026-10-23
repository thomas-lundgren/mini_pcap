/* Capture pipeline: forwarding-thread tap -> SPSC prefix ring -> writer thread.
 * The tap never blocks, allocates, formats or performs I/O. */
#ifndef MPC_CAPTURE_H
#define MPC_CAPTURE_H

#include <pthread.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#include "mpc/flow.h"
#include "mpc/ring.h"

/* Benchmark variants (docs/PERFORMANCE_PLAN.md section 3). F differs from E only
 * in Kotlin-side features (notification updates, sidecar checkpoints). */
enum {
    MPC_VARIANT_B_FORWARD_ONLY = 1,
    MPC_VARIANT_C_COPY_NULL = 2,
    MPC_VARIANT_D_WRITER = 3,
    MPC_VARIANT_E_UID = 4,
    MPC_VARIANT_F_FULL = 5,
};

/* Counter list: single source of truth for native snapshot order and the names
 * exported to Kotlin (sidecar stats / benchmark output). */
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
    X(uid_resolutions_applied)     \
    X(uid_resolution_drops)        \
    X(records_written)             \
    X(records_discarded_null)      \
    X(captured_bytes)              \
    X(file_bytes)                  \
    X(write_syscalls)              \
    X(storage_errors)              \
    X(storage_dropped_records)     \
    X(writer_stall_ms)             \
    X(ctx_records_written)         \
    X(ctx_records_dropped)         \
    X(records_uid_late_bound)      \
    X(records_hold_bypassed)       \
    X(uid_writer_drops)            \
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
/* For the few counters bumped by more than one thread (control plane, rare). */
#define MPC_CINC_SHARED(c, field) atomic_fetch_add_explicit(&(c)->field, 1, memory_order_relaxed)
#define MPC_CSET(c, field, v) atomic_store_explicit(&(c)->field, (v), memory_order_relaxed)

/* Record header stored at the start of every ring slot, followed by prefix bytes. */
typedef struct {
    uint64_t ts_ns; /* CLOCK_BOOTTIME at the capture point */
    uint64_t flow_id; /* 0 = no flow (non-TCP/UDP, fragment, malformed, table full) */
    int32_t uid;      /* cached UID or MPC_UID_UNKNOWN */
    uint32_t orig_len;
    uint16_t cap_len;
    uint8_t dir;
    uint8_t flags;
    uint32_t reserved;
} mpc_rec_hdr;

/* Context record kinds (Kotlin -> native, ~1 Hz). A STATE record (position, motion,
 * radio) becomes the "current context" referenced as c=<seq> by later packets; an
 * INFO record (e.g. first-seen app identity) is written but not referenced. */
enum { MPC_CTX_STATE = 1, MPC_CTX_INFO = 2 };

#define MPC_CTX_SLOT_BYTES (16u << 10)
#define MPC_CTX_SLOTS 64u

typedef struct {
    uint64_t ts_ns; /* CLOCK_BOOTTIME when the snapshot was handed to native */
    uint32_t seq;
    uint32_t json_len;
    uint16_t info_len;
    uint8_t kind;
    uint8_t reserved[5];
} mpc_ctx_hdr;

/* UID request (native -> Kotlin): 48 bytes, little endian. */
typedef struct {
    uint64_t flow_id;
    mpc_flow_key key;
} mpc_uid_request;

/* UID resolution (Kotlin -> native): 56 bytes, little endian. */
typedef struct {
    uint64_t flow_id;
    int32_t uid;
    uint32_t reserved;
    mpc_flow_key key;
} mpc_uid_resolution;

typedef struct {
    const char *pcap_path; /* NULL allowed for variants B/C */
    uint32_t snaplen;      /* bytes of IP packet to keep; 0 = full packet (mtu) */
    uint32_t mtu;
    int variant;
    size_t ring_bytes;
    size_t writer_buf_bytes;
    uint32_t flow_capacity;
    const char *if_name;
    const char *userappl;
    const char *os;
    const char *hardware;
    /* Writer holds records up to this long so a UID resolved shortly after a flow's
     * first packets is written into them too (0 = write immediately, no late binding). */
    uint32_t uid_hold_ms;
} mpc_capture_config;

/* Writer-side flow_id -> uid cache for late binding (direct mapped). */
#define MPC_WUID_SLOTS 65536u
typedef struct {
    uint64_t flow_id;
    int32_t uid;
    uint32_t reserved;
} mpc_wuid_entry;

typedef struct mpc_capture {
    mpc_capture_config cfg;
    int tap_enabled;
    int uid_enabled;
    int write_file;
    uint32_t snap; /* effective snaplen */

    mpc_counters cnt;
    mpc_flow_table flows;
    mpc_ring ring;
    mpc_ring uid_req;
    mpc_ring uid_resp;
    int uid_req_efd;  /* signalled when new UID requests are queued */
    int uid_resp_efd; /* signalled by Kotlin delivery; watched by forwarder */
    int writer_efd;   /* wakes the writer early */
    int uid_req_pending_signal;

    /* context records (control plane -> writer) and writer-side late UID binding */
    mpc_ring ctx;
    pthread_mutex_t ctx_lock;
    int ctx_lock_init;
    mpc_ring uid_wr;
    mpc_wuid_entry *wuid;
    uint32_t cur_ctx; /* writer thread only: seq of the last STATE record written, 0 = none */

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
    int64_t anchor_boot_ns;
    int64_t anchor_real_ns;
} mpc_capture;

uint64_t mpc_now_boottime_ns(void);

/* Allocates every bounded pool up front. Returns NULL on failure (errno-ish code in *err). */
mpc_capture *mpc_capture_create(const mpc_capture_config *cfg, int *err);
int mpc_capture_start_writer(mpc_capture *c);
/* Called after the forwarding thread has stopped: drain, flush, fsync, close. */
int mpc_capture_finish(mpc_capture *c);
void mpc_capture_destroy(mpc_capture *c);

/* --- Forwarding-thread API (hot path) --- */

/* Observe one packet. hdr/hdr_len: contiguous leading bytes (>= IP+L4 headers when
 * available). Returns a pointer where the caller copies *cap_len bytes then calls
 * mpc_capture_commit(), or NULL if the record is not captured (drop counted). */
uint8_t *mpc_capture_begin(mpc_capture *c, int dir, uint64_t ts_ns, const uint8_t *hdr,
                           size_t hdr_len, uint32_t total_len, uint32_t *cap_len);
static inline void mpc_capture_commit(mpc_capture *c) { mpc_ring_commit(&c->ring); }

/* Once per forwarding loop iteration: deliver pending signals (UID worker, writer). */
void mpc_capture_batch_done(mpc_capture *c);
/* Apply UID resolutions queued by Kotlin (forwarding thread). */
void mpc_capture_apply_uids(mpc_capture *c);
/* About 1 Hz: expire idle flows. */
void mpc_capture_housekeeping(mpc_capture *c, uint64_t now_ns);

/* --- Control-plane API (any thread) --- */
void mpc_capture_snapshot(mpc_capture *c, uint64_t *out, size_t n);
/* Blocks up to timeout_ms; copies up to max requests. Returns count, or -1 once closed. */
int mpc_capture_uid_poll(mpc_capture *c, mpc_uid_request *out, int max, int timeout_ms);
/* Single producer (one Kotlin worker thread). Returns number accepted. */
int mpc_capture_uid_deliver(mpc_capture *c, const mpc_uid_resolution *res, int n);
void mpc_capture_request_stall(mpc_capture *c, uint32_t ms);
/* Any thread, ~1 Hz. Copies the record; returns 0, or -1 if disabled/too large/queue full
 * (counted as ctx_records_dropped). seq must increase for STATE records. */
int mpc_capture_context(mpc_capture *c, int kind, uint32_t seq, uint64_t ts_ns, const char *info,
                        size_t info_len, const uint8_t *json, size_t json_len);
void mpc_capture_close_uid(mpc_capture *c);

#endif
