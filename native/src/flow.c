#include "mpc/flow.h"

#include <stdlib.h>
#include <string.h>

/* Idle timeouts in coarse seconds (~1.07 s units). */
#define TCP_IDLE_TIMEOUT 600
#define TCP_CLOSED_TIMEOUT 10
#define UDP_IDLE_TIMEOUT 120
#define TCP_REUSE_IDLE 60

int mpc_flow_table_init(mpc_flow_table *t, uint32_t capacity_pow2)
{
    memset(t, 0, sizeof(*t));
    if (capacity_pow2 < 16 || (capacity_pow2 & (capacity_pow2 - 1)) != 0)
        return -1;
    t->slots = calloc(capacity_pow2, sizeof(mpc_flow_entry));
    if (!t->slots)
        return -1;
    t->capacity = capacity_pow2;
    t->mask = capacity_pow2 - 1;
    t->next_flow_id = 1;
    return 0;
}

void mpc_flow_table_free(mpc_flow_table *t)
{
    free(t->slots);
    memset(t, 0, sizeof(*t));
}

int mpc_flow_key_from_pkt(const mpc_pkt_info *info, int dir, mpc_flow_key *key)
{
    if (!info->has_ports || (info->proto != MPC_PROTO_TCP && info->proto != MPC_PROTO_UDP))
        return -1;
    memset(key, 0, sizeof(*key));
    key->ipver = info->ipver;
    key->proto = info->proto;
    size_t alen = info->ipver == 4 ? 4 : 16;
    if (dir == MPC_DIR_UPLINK) {
        memcpy(key->local, info->src, alen);
        memcpy(key->remote, info->dst, alen);
        key->lport = info->sport;
        key->rport = info->dport;
    } else {
        memcpy(key->local, info->dst, alen);
        memcpy(key->remote, info->src, alen);
        key->lport = info->dport;
        key->rport = info->sport;
    }
    return 0;
}

static inline uint64_t rd64(const uint8_t *p)
{
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

static inline uint32_t key_hash(const mpc_flow_key *k)
{
    const uint8_t *b = (const uint8_t *)k;
    uint64_t h = 0x9e3779b97f4a7c15ULL;
    for (int i = 0; i < 40; i += 8) {
        h ^= rd64(b + i);
        h *= 0xff51afd7ed558ccdULL;
        h ^= h >> 32;
    }
    return (uint32_t)h;
}

static inline int key_eq(const mpc_flow_key *a, const mpc_flow_key *b)
{
    return memcmp(a, b, sizeof(*a)) == 0;
}

mpc_flow_entry *mpc_flow_find(mpc_flow_table *t, const mpc_flow_key *key)
{
    uint32_t i = key_hash(key) & t->mask;
    for (uint32_t n = 0; n < t->capacity; n++, i = (i + 1) & t->mask) {
        mpc_flow_entry *e = &t->slots[i];
        if (e->flow_id == 0)
            return NULL;
        if (key_eq(&e->key, key))
            return e;
    }
    return NULL;
}

static void new_generation(mpc_flow_table *t, mpc_flow_entry *e, uint32_t now_s)
{
    e->flow_id = t->next_flow_id++;
    e->first_seen = 0; /* set by the caller, which knows the packet timestamp */
    e->uid_state = MPC_UID_STATE_NONE;
    e->flags = 0;
    e->last_seen = now_s;
    t->flows_created++;
}

mpc_flow_entry *mpc_flow_lookup(mpc_flow_table *t, const mpc_flow_key *key, uint8_t tcp_flags,
                                int dir, uint32_t now_s, int *is_new)
{
    *is_new = 0;
    uint32_t i = key_hash(key) & t->mask;
    for (uint32_t n = 0; n < t->capacity; n++, i = (i + 1) & t->mask) {
        mpc_flow_entry *e = &t->slots[i];
        if (e->flow_id == 0) {
            /* Keep load factor <= 3/4 so probe chains stay short. */
            if (t->count >= t->capacity - (t->capacity >> 2)) {
                t->table_full++;
                return NULL;
            }
            e->key = *key;
            new_generation(t, e, now_s);
            t->count++;
            *is_new = 1;
            goto update;
        }
        if (key_eq(&e->key, key)) {
            /* A fresh client SYN on a closed or long-idle tuple is a new flow generation. */
            if (key->proto == MPC_PROTO_TCP && dir == MPC_DIR_UPLINK &&
                (tcp_flags & (MPC_TCP_SYN | MPC_TCP_ACK)) == MPC_TCP_SYN &&
                ((e->flags & (MPC_FLOWF_FIN | MPC_FLOWF_RST)) ||
                 (uint32_t)(now_s - e->last_seen) > TCP_REUSE_IDLE)) {
                new_generation(t, e, now_s);
                *is_new = 1;
            }
            goto update;
        }
        continue;
    update:
        e->last_seen = now_s;
        if (key->proto == MPC_PROTO_TCP) {
            if (tcp_flags & MPC_TCP_FIN)
                e->flags |= MPC_FLOWF_FIN;
            if (tcp_flags & MPC_TCP_RST)
                e->flags |= MPC_FLOWF_RST;
        }
        return e;
    }
    t->table_full++;
    return NULL;
}

static int expired(const mpc_flow_entry *e, uint32_t now_s)
{
    uint32_t idle = now_s - e->last_seen;
    if (e->key.proto == MPC_PROTO_TCP) {
        if (e->flags & (MPC_FLOWF_FIN | MPC_FLOWF_RST))
            return idle > TCP_CLOSED_TIMEOUT;
        return idle > TCP_IDLE_TIMEOUT;
    }
    return idle > UDP_IDLE_TIMEOUT;
}

/* Linear-probing backward-shift deletion keeps lookups correct without tombstones. */
static void delete_at(mpc_flow_table *t, uint32_t i)
{
    uint32_t j = i;
    for (;;) {
        t->slots[i].flow_id = 0;
        for (;;) {
            j = (j + 1) & t->mask;
            if (t->slots[j].flow_id == 0) {
                t->count--;
                return;
            }
            uint32_t home = key_hash(&t->slots[j].key) & t->mask;
            /* Can slot j move to i? Only if its home is not cyclically in (i, j]. */
            if (i <= j ? (i < home && home <= j) : (i < home || home <= j))
                continue;
            break;
        }
        t->slots[i] = t->slots[j];
        i = j;
    }
}

void mpc_flow_sweep(mpc_flow_table *t, uint32_t now_s, uint32_t max_slots)
{
    if (max_slots > t->capacity)
        max_slots = t->capacity;
    uint32_t pos = t->sweep_pos;
    for (uint32_t n = 0; n < max_slots; n++) {
        mpc_flow_entry *e = &t->slots[pos];
        if (e->flow_id != 0 && expired(e, now_s)) {
            delete_at(t, pos);
            t->flows_expired++;
            /* An entry may have shifted into pos; re-examine it. */
            if (t->slots[pos].flow_id != 0)
                continue;
        }
        pos = (pos + 1) & t->mask;
    }
    t->sweep_pos = pos;
}
