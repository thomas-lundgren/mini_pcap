/* SPSC ring: ordering under concurrency, non-blocking full behaviour, bounds. */
#include <pthread.h>

#include "mpc/ring.h"
#include "testutil.h"

#define COUNT 2000000ULL

static mpc_ring R;
static uint64_t produced, dropped;

static void *producer(void *a)
{
    for (uint64_t i = 0; i < COUNT; i++) {
        uint64_t *slot = mpc_ring_reserve(&R);
        if (!slot) {
            dropped++;
            continue;
        }
        slot[0] = i;
        slot[1] = ~i;
        mpc_ring_commit(&R);
        produced++;
    }
    return NULL;
}

int main(void)
{
    CHECK_EQ(mpc_ring_init(&R, 20, 3000), 0);
    CHECK_EQ(R.slot_size, 24);
    CHECK_EQ(R.nslots, 64); /* 3000/24 = 125 -> 64 */

    /* Full ring returns NULL without blocking. */
    for (int i = 0; i < 64; i++) {
        CHECK(mpc_ring_reserve(&R) != NULL);
        mpc_ring_commit(&R);
    }
    CHECK(mpc_ring_reserve(&R) == NULL);
    uint64_t tail;
    CHECK_EQ(mpc_ring_available(&R, &tail), 64);
    mpc_ring_release(&R, tail + 64);
    CHECK(mpc_ring_reserve(&R) != NULL);
    CHECK_EQ(atomic_load(&R.peak_used), 64);
    mpc_ring_free(&R);

    CHECK_EQ(mpc_ring_init(&R, 16, 16 * 1024), 0);
    pthread_t th;
    pthread_create(&th, NULL, producer, NULL);
    uint64_t consumed = 0, last = 0, bad = 0;
    int first = 1;
    for (;;) {
        uint64_t n = mpc_ring_available(&R, &tail);
        if (n == 0) {
            if (produced + dropped == COUNT && mpc_ring_available(&R, &tail) == 0)
                break;
            continue;
        }
        for (uint64_t i = 0; i < n; i++) {
            uint64_t *s = mpc_ring_slot(&R, tail + i);
            if (s[1] != ~s[0] || (!first && s[0] <= last))
                bad++;
            last = s[0];
            first = 0;
        }
        consumed += n;
        mpc_ring_release(&R, tail + n);
    }
    pthread_join(th, NULL);
    CHECK_EQ(bad, 0);
    CHECK_EQ(consumed, produced);
    CHECK_EQ(produced + dropped, COUNT);
    printf("produced=%llu dropped=%llu\n", (unsigned long long)produced,
           (unsigned long long)dropped);
    mpc_ring_free(&R);
    TEST_DONE();
}
