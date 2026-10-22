/* Bounded single-producer/single-consumer ring of fixed-size slots in one
 * preallocated block. Producer never blocks: a full ring returns NULL. */
#ifndef MPC_RING_H
#define MPC_RING_H

#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    _Alignas(64) _Atomic uint64_t head; /* written by producer */
    uint64_t tail_cache;                /* producer's cached view of tail */
    _Alignas(64) _Atomic uint64_t tail; /* written by consumer */
    _Alignas(64) uint8_t *mem;
    uint32_t slot_size;
    uint32_t nslots; /* power of two */
    uint32_t mask;
    _Atomic uint64_t peak_used; /* producer-maintained high watermark */
} mpc_ring;

/* slot_size is rounded up to 8 bytes; nslots is rounded down to a power of two
 * so that nslots*slot_size <= max_bytes. Returns 0 on success. */
int mpc_ring_init(mpc_ring *r, uint32_t slot_size, size_t max_bytes);
void mpc_ring_free(mpc_ring *r);

static inline void *mpc_ring_reserve(mpc_ring *r)
{
    uint64_t h = atomic_load_explicit(&r->head, memory_order_relaxed);
    if (h - r->tail_cache >= r->nslots) {
        r->tail_cache = atomic_load_explicit(&r->tail, memory_order_acquire);
        if (h - r->tail_cache >= r->nslots)
            return NULL;
    }
    return r->mem + (size_t)(h & r->mask) * r->slot_size;
}

static inline void mpc_ring_commit(mpc_ring *r)
{
    uint64_t h = atomic_load_explicit(&r->head, memory_order_relaxed) + 1;
    atomic_store_explicit(&r->head, h, memory_order_release);
    uint64_t used = h - r->tail_cache;
    if (used > atomic_load_explicit(&r->peak_used, memory_order_relaxed))
        atomic_store_explicit(&r->peak_used, used, memory_order_relaxed);
}

/* Consumer side: number of committed slots available. */
static inline uint64_t mpc_ring_available(mpc_ring *r, uint64_t *tail_out)
{
    uint64_t t = atomic_load_explicit(&r->tail, memory_order_relaxed);
    uint64_t h = atomic_load_explicit(&r->head, memory_order_acquire);
    *tail_out = t;
    return h - t;
}

static inline void *mpc_ring_slot(mpc_ring *r, uint64_t index)
{
    return r->mem + (size_t)(index & r->mask) * r->slot_size;
}

static inline void mpc_ring_release(mpc_ring *r, uint64_t new_tail)
{
    atomic_store_explicit(&r->tail, new_tail, memory_order_release);
}

#endif
