#include "mpc/ring.h"

#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

int mpc_ring_init(mpc_ring *r, uint32_t slot_size, size_t max_bytes)
{
    memset(r, 0, sizeof(*r));
    slot_size = (slot_size + 7u) & ~7u;
    if (slot_size == 0 || max_bytes < (size_t)slot_size * 2u)
        return -1;
    size_t n = max_bytes / slot_size;
    uint32_t p = 1;
    while ((size_t)p * 2 <= n && p < (1u << 30))
        p *= 2;
    size_t bytes = (size_t)p * slot_size;
    /* mmap + touch so the pool is resident before capture starts (no page
     * faults/allocations later on the forwarding thread). */
    void *m = mmap(NULL, bytes, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (m == MAP_FAILED)
        return -1;
    memset(m, 0, bytes);
    r->mem = m;
    r->slot_size = slot_size;
    r->nslots = p;
    r->mask = p - 1;
    return 0;
}

void mpc_ring_free(mpc_ring *r)
{
    if (r->mem)
        munmap(r->mem, (size_t)r->nslots * r->slot_size);
    memset(r, 0, sizeof(*r));
}
