#include "mpc/capture.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <time.h>
#include <unistd.h>

#include "mpc/packet.h"
#include "mpc/pcapng.h"

const char *const mpc_counter_names[MPC_CNT__COUNT] = {
#define MPC_CNT_NAME(name) #name,
    MPC_COUNTERS(MPC_CNT_NAME)
#undef MPC_CNT_NAME
};

#define WRITER_IDLE_WAIT_MS 20
#define WRITER_FLUSH_INTERVAL_NS 1000000000ULL
#define WRITER_BATCH 1024

uint64_t mpc_now_boottime_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_BOOTTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t now_realtime_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void efd_signal(int fd)
{
    uint64_t one = 1;
    ssize_t r = write(fd, &one, sizeof(one));
    (void)r;
}

static void efd_drain(int fd)
{
    uint64_t v;
    ssize_t r = read(fd, &v, sizeof(v));
    (void)r;
}

mpc_capture *mpc_capture_create(const mpc_capture_config *cfg, int *err)
{
    *err = 0;
    mpc_capture *c = calloc(1, sizeof(*c));
    if (!c) {
        *err = ENOMEM;
        return NULL;
    }
    c->cfg = *cfg;
    c->fd = -1;
    c->uid_req_efd = c->uid_resp_efd = c->writer_efd = -1;
    int v = cfg->variant;
    c->tap_enabled = v >= MPC_VARIANT_C_COPY_NULL;
    c->write_file = v >= MPC_VARIANT_D_WRITER;
    c->uid_enabled = v >= MPC_VARIANT_E_UID;
    uint32_t mtu = cfg->mtu ? cfg->mtu : 1500;
    c->snap = (cfg->snaplen == 0 || cfg->snaplen > mtu) ? mtu : cfg->snaplen;

    /* Anchor pair for boottime -> Unix epoch conversion (taken back to back). */
    uint64_t b0 = mpc_now_boottime_ns();
    uint64_t r = now_realtime_ns();
    uint64_t b1 = mpc_now_boottime_ns();
    c->anchor_boot_ns = (int64_t)(b0 + (b1 - b0) / 2);
    c->anchor_real_ns = (int64_t)r;
    MPC_CSET(&c->cnt, anchor_boottime_ns, (uint64_t)c->anchor_boot_ns);
    MPC_CSET(&c->cnt, anchor_realtime_ns, (uint64_t)c->anchor_real_ns);

    c->uid_req_efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    c->uid_resp_efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    c->writer_efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (c->uid_req_efd < 0 || c->uid_resp_efd < 0 || c->writer_efd < 0)
        goto fail;

    if (c->tap_enabled) {
        size_t ring_bytes = cfg->ring_bytes ? cfg->ring_bytes : (8u << 20);
        if (mpc_ring_init(&c->ring, (uint32_t)(sizeof(mpc_rec_hdr) + c->snap), ring_bytes) != 0)
            goto fail;
        if (mpc_flow_table_init(&c->flows, cfg->flow_capacity ? cfg->flow_capacity : 65536) != 0)
            goto fail;
        MPC_CSET(&c->cnt, capture_ring_slots, c->ring.nslots);
        MPC_CSET(&c->cnt, capture_ring_slot_bytes, c->ring.slot_size);
    }
    if (c->uid_enabled) {
        if (mpc_ring_init(&c->uid_req, sizeof(mpc_uid_request), 4096 * sizeof(mpc_uid_request)) != 0)
            goto fail;
        if (mpc_ring_init(&c->uid_resp, sizeof(mpc_uid_resolution),
                          4096 * sizeof(mpc_uid_resolution)) != 0)
            goto fail;
    }
    if (c->write_file) {
        if (!cfg->pcap_path) {
            *err = EINVAL;
            goto fail_keep_err;
        }
        c->fd = open(cfg->pcap_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (c->fd < 0)
            goto fail;
        size_t wb = cfg->writer_buf_bytes ? cfg->writer_buf_bytes : (1u << 20);
        if (wb < 64 * 1024)
            wb = 64 * 1024;
        c->cfg.writer_buf_bytes = wb;
        c->wbuf = malloc(wb);
        if (!c->wbuf)
            goto fail;
    }
    return c;
fail:
    *err = errno ? errno : ENOMEM;
fail_keep_err:
    mpc_capture_destroy(c);
    return NULL;
}

/* ---------------------------------------------------------------- hot path */

static void queue_uid_request(mpc_capture *c, const mpc_flow_entry *e)
{
    mpc_uid_request *rq = mpc_ring_reserve(&c->uid_req);
    if (!rq) {
        MPC_CINC(&c->cnt, uid_request_queue_overflows, 1);
        return;
    }
    rq->flow_id = e->flow_id;
    rq->key = e->key;
    mpc_ring_commit(&c->uid_req);
    MPC_CINC(&c->cnt, uid_requests_queued, 1);
    c->uid_req_pending_signal = 1;
}

uint8_t *mpc_capture_begin(mpc_capture *c, int dir, uint64_t ts_ns, const uint8_t *hdr,
                           size_t hdr_len, uint32_t total_len, uint32_t *cap_len)
{
    if (dir == MPC_DIR_UPLINK) {
        MPC_CINC(&c->cnt, pkts_ul, 1);
        MPC_CINC(&c->cnt, bytes_ul, total_len);
    } else {
        MPC_CINC(&c->cnt, pkts_dl, 1);
        MPC_CINC(&c->cnt, bytes_dl, total_len);
    }

    uint64_t flow_id = 0;
    int32_t uid = MPC_UID_UNKNOWN;
    mpc_pkt_info info;
    if (mpc_parse_packet(hdr, hdr_len, &info) != 0) {
        MPC_CINC(&c->cnt, unparsable_packets, 1);
    } else {
        mpc_flow_key key;
        if (mpc_flow_key_from_pkt(&info, dir, &key) == 0) {
            int is_new;
            mpc_flow_entry *e = mpc_flow_lookup(&c->flows, &key, info.tcp_flags, dir,
                                                mpc_coarse_seconds(ts_ns), &is_new);
            if (e) {
                flow_id = e->flow_id;
                uid = e->uid;
                if (is_new && c->uid_enabled) {
                    e->uid_state = MPC_UID_STATE_REQUESTED;
                    queue_uid_request(c, e);
                }
            }
        } else {
            MPC_CINC(&c->cnt, nonflow_packets, 1);
        }
    }

    mpc_rec_hdr *h = mpc_ring_reserve(&c->ring);
    if (!h) {
        if (dir == MPC_DIR_UPLINK)
            MPC_CINC(&c->cnt, capture_queue_drops_ul, 1);
        else
            MPC_CINC(&c->cnt, capture_queue_drops_dl, 1);
        return NULL;
    }
    uint32_t cl = total_len < c->snap ? total_len : c->snap;
    h->ts_ns = ts_ns;
    h->flow_id = flow_id;
    h->uid = uid;
    h->orig_len = total_len;
    h->cap_len = (uint16_t)cl;
    h->dir = (uint8_t)dir;
    h->flags = 0;
    *cap_len = cl;
    return (uint8_t *)(h + 1);
}

void mpc_capture_batch_done(mpc_capture *c)
{
    if (c->uid_req_pending_signal) {
        c->uid_req_pending_signal = 0;
        efd_signal(c->uid_req_efd);
    }
    if (c->tap_enabled && atomic_load_explicit(&c->writer_sleeping, memory_order_relaxed)) {
        uint64_t t;
        uint64_t used = mpc_ring_available(&c->ring, &t);
        /* Wake early only when a quarter of the ring is in use; otherwise the
         * writer's own 20 ms timeout bounds latency without per-batch syscalls. */
        if (used >= (c->ring.nslots >> 2) &&
            atomic_exchange_explicit(&c->writer_sleeping, 0, memory_order_relaxed))
            efd_signal(c->writer_efd);
    }
}

void mpc_capture_apply_uids(mpc_capture *c)
{
    efd_drain(c->uid_resp_efd);
    if (!c->uid_enabled)
        return;
    uint64_t tail;
    uint64_t n = mpc_ring_available(&c->uid_resp, &tail);
    for (uint64_t i = 0; i < n; i++) {
        const mpc_uid_resolution *r = mpc_ring_slot(&c->uid_resp, tail + i);
        mpc_flow_entry *e = mpc_flow_find(&c->flows, &r->key);
        /* Only apply to the same flow generation; never overwrite an earlier UID. */
        if (e && e->flow_id == r->flow_id && e->uid_state != MPC_UID_STATE_RESOLVED) {
            if (r->uid >= 0) {
                e->uid = r->uid;
                e->uid_state = MPC_UID_STATE_RESOLVED;
            } else {
                e->uid_state = MPC_UID_STATE_FAILED;
            }
            MPC_CINC(&c->cnt, uid_resolutions_applied, 1);
        }
    }
    mpc_ring_release(&c->uid_resp, tail + n);
}

void mpc_capture_housekeeping(mpc_capture *c, uint64_t now_ns)
{
    if (!c->tap_enabled)
        return;
    mpc_flow_sweep(&c->flows, mpc_coarse_seconds(now_ns), c->flows.capacity / 8);
    MPC_CSET(&c->cnt, flows_created, c->flows.flows_created);
    MPC_CSET(&c->cnt, flows_expired, c->flows.flows_expired);
    MPC_CSET(&c->cnt, flow_table_full, c->flows.table_full);
}

/* ---------------------------------------------------------------- writer */

static int write_all(mpc_capture *c, const uint8_t *p, size_t n)
{
    while (n) {
        ssize_t w = write(c->fd, p, n);
        MPC_CINC(&c->cnt, write_syscalls, 1);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += w;
        n -= (size_t)w;
        MPC_CINC(&c->cnt, file_bytes, (uint64_t)w);
    }
    return 0;
}

static void writer_flush(mpc_capture *c)
{
    if (c->wlen == 0)
        return;
    if (atomic_load_explicit(&c->cnt.storage_errors, memory_order_relaxed) == 0 &&
        write_all(c, c->wbuf, c->wlen) != 0)
        MPC_CINC(&c->cnt, storage_errors, 1);
    c->wlen = 0;
}

static inline uint64_t to_epoch_us(const mpc_capture *c, uint64_t ts_ns)
{
    int64_t real = c->anchor_real_ns + ((int64_t)ts_ns - c->anchor_boot_ns);
    return real > 0 ? (uint64_t)real / 1000u : 0;
}

static void serialize_record(mpc_capture *c, const mpc_rec_hdr *h)
{
    if (atomic_load_explicit(&c->cnt.storage_errors, memory_order_relaxed)) {
        MPC_CINC(&c->cnt, storage_dropped_records, 1);
        return;
    }
    char comment[48];
    size_t clen = mpc_format_comment(comment, h->flow_id, h->uid);
    size_t need = mpc_pcapng_epb_max(h->cap_len, clen);
    if (c->wlen + need > c->cfg.writer_buf_bytes)
        writer_flush(c);
    uint32_t flags = h->dir == MPC_DIR_UPLINK ? MPC_EPB_FLAG_OUTBOUND : MPC_EPB_FLAG_INBOUND;
    size_t n = mpc_pcapng_epb(c->wbuf + c->wlen, c->cfg.writer_buf_bytes - c->wlen, 0,
                              to_epoch_us(c, h->ts_ns), (const uint8_t *)(h + 1), h->cap_len,
                              h->orig_len, comment, clen, flags);
    c->wlen += n;
    MPC_CINC(&c->cnt, records_written, 1);
    MPC_CINC(&c->cnt, captured_bytes, h->cap_len);
}

static void *writer_main(void *arg)
{
    mpc_capture *c = arg;
    uint64_t last_flush = mpc_now_boottime_ns();
    struct pollfd pfd = {.fd = c->writer_efd, .events = POLLIN};
    for (;;) {
        uint32_t stall = atomic_exchange_explicit(&c->stall_request_ms, 0, memory_order_relaxed);
        if (stall) {
            /* Benchmark-only synthetic consumer stall (PERFORMANCE_PLAN V32). */
            struct timespec ts = {.tv_sec = stall / 1000, .tv_nsec = (long)(stall % 1000) * 1000000L};
            while (nanosleep(&ts, &ts) != 0 && errno == EINTR)
                ;
            MPC_CINC(&c->cnt, writer_stall_ms, stall);
        }
        uint64_t tail;
        uint64_t n = mpc_ring_available(&c->ring, &tail);
        if (n == 0) {
            if (atomic_load_explicit(&c->writer_stop, memory_order_acquire)) {
                /* Re-check after observing stop: the producer has fully quiesced. */
                if (mpc_ring_available(&c->ring, &tail) == 0)
                    break;
                continue;
            }
            uint64_t now = mpc_now_boottime_ns();
            if (c->wlen && now - last_flush >= WRITER_FLUSH_INTERVAL_NS) {
                writer_flush(c);
                last_flush = now;
            }
            atomic_store_explicit(&c->writer_sleeping, 1, memory_order_relaxed);
            poll(&pfd, 1, WRITER_IDLE_WAIT_MS);
            atomic_store_explicit(&c->writer_sleeping, 0, memory_order_relaxed);
            if (pfd.revents & POLLIN)
                efd_drain(c->writer_efd);
            continue;
        }
        if (n > WRITER_BATCH)
            n = WRITER_BATCH;
        if (c->write_file) {
            for (uint64_t i = 0; i < n; i++)
                serialize_record(c, mpc_ring_slot(&c->ring, tail + i));
        } else {
            MPC_CINC(&c->cnt, records_discarded_null, n);
        }
        mpc_ring_release(&c->ring, tail + n);
        uint64_t now = mpc_now_boottime_ns();
        if (c->wlen && now - last_flush >= WRITER_FLUSH_INTERVAL_NS) {
            writer_flush(c);
            last_flush = now;
        }
    }
    writer_flush(c);
    return NULL;
}

int mpc_capture_start_writer(mpc_capture *c)
{
    if (!c->tap_enabled)
        return 0;
    if (c->write_file) {
        size_t n = mpc_pcapng_shb(c->wbuf, c->cfg.writer_buf_bytes, c->cfg.userappl, c->cfg.os,
                                  c->cfg.hardware);
        n += mpc_pcapng_idb(c->wbuf + n, c->cfg.writer_buf_bytes - n, MPC_LINKTYPE_RAW, c->snap,
                            c->cfg.if_name ? c->cfg.if_name : "tun0", 6);
        c->wlen = n;
        writer_flush(c); /* headers on disk immediately: a valid (empty) capture */
    }
    if (pthread_create(&c->writer_thread, NULL, writer_main, c) != 0)
        return -1;
    c->writer_started = 1;
    return 0;
}

int mpc_capture_finish(mpc_capture *c)
{
    int rc = 0;
    if (c->writer_started) {
        atomic_store_explicit(&c->writer_stop, 1, memory_order_release);
        efd_signal(c->writer_efd);
        pthread_join(c->writer_thread, NULL);
        c->writer_started = 0;
    }
    if (c->ring.mem)
        MPC_CSET(&c->cnt, capture_ring_peak_slots,
                 atomic_load_explicit(&c->ring.peak_used, memory_order_relaxed));
    if (c->fd >= 0) {
        if (fsync(c->fd) != 0)
            rc = -1;
        if (close(c->fd) != 0)
            rc = -1;
        c->fd = -1;
    }
    if (atomic_load_explicit(&c->cnt.storage_errors, memory_order_relaxed))
        rc = -1;
    return rc;
}

void mpc_capture_destroy(mpc_capture *c)
{
    if (!c)
        return;
    if (c->writer_started)
        mpc_capture_finish(c);
    if (c->fd >= 0)
        close(c->fd);
    mpc_ring_free(&c->ring);
    mpc_ring_free(&c->uid_req);
    mpc_ring_free(&c->uid_resp);
    mpc_flow_table_free(&c->flows);
    free(c->wbuf);
    if (c->uid_req_efd >= 0)
        close(c->uid_req_efd);
    if (c->uid_resp_efd >= 0)
        close(c->uid_resp_efd);
    if (c->writer_efd >= 0)
        close(c->writer_efd);
    free(c);
}

/* ---------------------------------------------------------------- control plane */

void mpc_capture_snapshot(mpc_capture *c, uint64_t *out, size_t n)
{
    const _Atomic uint64_t *src = (const _Atomic uint64_t *)&c->cnt;
    if (c->ring.mem)
        MPC_CSET(&c->cnt, capture_ring_peak_slots,
                 atomic_load_explicit(&c->ring.peak_used, memory_order_relaxed));
    for (size_t i = 0; i < n && i < MPC_CNT__COUNT; i++)
        out[i] = atomic_load_explicit(&src[i], memory_order_relaxed);
}

int mpc_capture_uid_poll(mpc_capture *c, mpc_uid_request *out, int max, int timeout_ms)
{
    if (!c->uid_enabled) {
        if (atomic_load(&c->session_closed))
            return -1;
        struct timespec ts = {.tv_sec = timeout_ms / 1000, .tv_nsec = (timeout_ms % 1000) * 1000000L};
        nanosleep(&ts, NULL);
        return atomic_load(&c->session_closed) ? -1 : 0;
    }
    uint64_t tail;
    uint64_t n = mpc_ring_available(&c->uid_req, &tail);
    if (n == 0) {
        if (atomic_load(&c->session_closed))
            return -1;
        struct pollfd pfd = {.fd = c->uid_req_efd, .events = POLLIN};
        poll(&pfd, 1, timeout_ms);
        efd_drain(c->uid_req_efd);
        n = mpc_ring_available(&c->uid_req, &tail);
        if (n == 0)
            return atomic_load(&c->session_closed) ? -1 : 0;
    }
    if (n > (uint64_t)max)
        n = (uint64_t)max;
    for (uint64_t i = 0; i < n; i++)
        memcpy(&out[i], mpc_ring_slot(&c->uid_req, tail + i), sizeof(mpc_uid_request));
    mpc_ring_release(&c->uid_req, tail + n);
    return (int)n;
}

int mpc_capture_uid_deliver(mpc_capture *c, const mpc_uid_resolution *res, int n)
{
    if (!c->uid_enabled)
        return 0;
    int ok = 0;
    for (int i = 0; i < n; i++) {
        mpc_uid_resolution *slot = mpc_ring_reserve(&c->uid_resp);
        if (!slot) {
            MPC_CINC(&c->cnt, uid_resolution_drops, (uint64_t)(n - i));
            break;
        }
        *slot = res[i];
        mpc_ring_commit(&c->uid_resp);
        ok++;
    }
    if (ok)
        efd_signal(c->uid_resp_efd);
    return ok;
}

void mpc_capture_request_stall(mpc_capture *c, uint32_t ms)
{
    atomic_store_explicit(&c->stall_request_ms, ms, memory_order_relaxed);
    efd_signal(c->writer_efd);
}

void mpc_capture_close_uid(mpc_capture *c)
{
    atomic_store(&c->session_closed, 1);
    efd_signal(c->uid_req_efd);
}
