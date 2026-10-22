/* Bounded, single-threaded flow table owned by the forwarding thread.
 * Keys are normalized so that "local" is always the device/app endpoint. */
#ifndef MPC_FLOW_H
#define MPC_FLOW_H

#include <stddef.h>
#include <stdint.h>

#include "mpc/packet.h"

#define MPC_UID_UNKNOWN (-1)

#define MPC_DIR_UPLINK 1   /* app -> network (read from TUN) */
#define MPC_DIR_DOWNLINK 2 /* network -> app (written to TUN) */

typedef struct {
    uint8_t ipver;
    uint8_t proto;
    uint16_t lport;
    uint16_t rport;
    uint16_t pad;
    uint8_t local[16];
    uint8_t remote[16];
} mpc_flow_key; /* 40 bytes, padding always zero so memcmp is valid */

enum {
    MPC_UID_STATE_NONE = 0,
    MPC_UID_STATE_REQUESTED = 1,
    MPC_UID_STATE_RESOLVED = 2,
    MPC_UID_STATE_FAILED = 3,
};

#define MPC_FLOWF_FIN 0x01
#define MPC_FLOWF_RST 0x02

typedef struct {
    mpc_flow_key key;
    uint64_t flow_id; /* 0 = empty slot */
    int32_t uid;
    uint32_t last_seen; /* coarse seconds (boottime_ns >> 30) */
    uint8_t uid_state;
    uint8_t flags;
    uint8_t pad[6];
} mpc_flow_entry;

typedef struct {
    mpc_flow_entry *slots;
    uint32_t capacity; /* power of two */
    uint32_t mask;
    uint32_t count;
    uint32_t sweep_pos;
    uint64_t next_flow_id;
    /* stats (forwarding thread only; read approximately) */
    uint64_t flows_created;
    uint64_t flows_expired;
    uint64_t table_full;
} mpc_flow_table;

int mpc_flow_table_init(mpc_flow_table *t, uint32_t capacity_pow2);
void mpc_flow_table_free(mpc_flow_table *t);

/* Build a normalized key from parsed packet info and direction.
 * Returns 0 if the packet belongs to a trackable flow (TCP/UDP with ports). */
int mpc_flow_key_from_pkt(const mpc_pkt_info *info, int dir, mpc_flow_key *key);

/* Look up or create the flow for a packet. *is_new is set when a new flow ID
 * was allocated (new flow or new generation). Returns NULL if the table is full. */
mpc_flow_entry *mpc_flow_lookup(mpc_flow_table *t, const mpc_flow_key *key, uint8_t tcp_flags,
                                int dir, uint32_t now_s, int *is_new);

/* Find an entry by key (no creation). */
mpc_flow_entry *mpc_flow_find(mpc_flow_table *t, const mpc_flow_key *key);

/* Incrementally expire idle flows; examines up to max_slots slots. */
void mpc_flow_sweep(mpc_flow_table *t, uint32_t now_s, uint32_t max_slots);

static inline uint32_t mpc_coarse_seconds(uint64_t boot_ns) { return (uint32_t)(boot_ns >> 30); }

#endif
