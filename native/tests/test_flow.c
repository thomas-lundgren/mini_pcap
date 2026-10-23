/* Flow table tests: normalization, generations, expiry and deletion correctness. */
#include "mpc/flow.h"
#include "mpc/packet.h"
#include "testutil.h"

static const uint8_t APP4[4] = {10, 111, 0, 2};
static const uint8_t SRV4[4] = {93, 184, 216, 34};

static void test_parse(void)
{
    uint8_t pkt[256];
    mpc_pkt_info in;
    size_t n = build_tcp(pkt, 4, APP4, 40000, SRV4, 443, 1, 0, 0x02, 65535, NULL, 0);
    CHECK_EQ(mpc_parse_packet(pkt, n, &in), 0);
    CHECK_EQ(in.ipver, 4);
    CHECK_EQ(in.proto, 6);
    CHECK_EQ(in.has_ports, 1);
    CHECK_EQ(in.sport, 40000);
    CHECK_EQ(in.dport, 443);
    CHECK_EQ(in.tcp_flags, 0x02);

    /* Non-initial IPv4 fragment: no ports. */
    uint8_t l4[16] = {0};
    n = build_ip(pkt, 4, APP4, SRV4, 17, l4, 16, 0x0010);
    CHECK_EQ(mpc_parse_packet(pkt, n, &in), 0);
    CHECK_EQ(in.has_ports, 0);

    /* IPv6 with hop-by-hop then UDP. */
    uint8_t a6[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
    uint8_t b6[16] = {0x20, 0x01, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t ext[8 + 8] = {17, 0, 1, 4, 0, 0, 0, 0, /* udp */ 0x13, 0x88, 0, 53, 0, 8, 0, 0};
    n = build_ip(pkt, 6, a6, b6, 0, ext, sizeof(ext), 0);
    CHECK_EQ(mpc_parse_packet(pkt, n, &in), 0);
    CHECK_EQ(in.ipver, 6);
    CHECK_EQ(in.proto, 17);
    CHECK_EQ(in.has_ports, 1);
    CHECK_EQ(in.sport, 5000);
    CHECK_EQ(in.dport, 53);

    /* Malformed. */
    CHECK_EQ(mpc_parse_packet(pkt, 3, &in), -1);
    uint8_t junk[40] = {0x75};
    CHECK_EQ(mpc_parse_packet(junk, sizeof(junk), &in), -1);
    /* Truncated: IPv6 header present, L4 missing -> parsable, no ports. */
    n = build_udp(pkt, 6, a6, 1000, b6, 53, "x", 1);
    CHECK_EQ(mpc_parse_packet(pkt, 42, &in), 0);
    CHECK_EQ(in.has_ports, 0);
}

static void test_normalize_and_generation(void)
{
    mpc_flow_table t;
    CHECK_EQ(mpc_flow_table_init(&t, 1024), 0);
    uint8_t pkt[256];
    mpc_pkt_info in;
    mpc_flow_key ku, kd;
    size_t n = build_tcp(pkt, 4, APP4, 40000, SRV4, 443, 1, 0, 0x02, 65535, NULL, 0);
    mpc_parse_packet(pkt, n, &in);
    CHECK_EQ(mpc_flow_key_from_pkt(&in, MPC_DIR_UPLINK, &ku), 0);
    n = build_tcp(pkt, 4, SRV4, 443, APP4, 40000, 9, 2, 0x12, 65535, NULL, 0);
    mpc_parse_packet(pkt, n, &in);
    CHECK_EQ(mpc_flow_key_from_pkt(&in, MPC_DIR_DOWNLINK, &kd), 0);
    CHECK(memcmp(&ku, &kd, sizeof(ku)) == 0);

    int is_new;
    mpc_flow_entry *e = mpc_flow_lookup(&t, &ku, 0x02, MPC_DIR_UPLINK, 100, &is_new);
    CHECK(e && is_new && e->flow_id == 1);
    e = mpc_flow_lookup(&t, &kd, 0x12, MPC_DIR_DOWNLINK, 100, &is_new);
    CHECK(e && !is_new && e->flow_id == 1);
    e->uid_state = MPC_UID_STATE_REQUESTED;
    /* FIN then a new SYN on the same tuple -> new generation, UID reset. */
    e = mpc_flow_lookup(&t, &ku, 0x11, MPC_DIR_UPLINK, 101, &is_new);
    CHECK(e && !is_new && (e->flags & MPC_FLOWF_FIN));
    e = mpc_flow_lookup(&t, &ku, 0x02, MPC_DIR_UPLINK, 102, &is_new);
    CHECK(e && is_new && e->flow_id == 2 && e->uid_state == MPC_UID_STATE_NONE); /* new generation: lookup again */
    /* SYN retransmission on a live flow is not a new generation. */
    e = mpc_flow_lookup(&t, &ku, 0x02, MPC_DIR_UPLINK, 103, &is_new);
    CHECK(e && !is_new && e->flow_id == 2);
    /* UDP keys differ from TCP keys with the same ports. */
    mpc_flow_key ku2 = ku;
    ku2.proto = 17;
    e = mpc_flow_lookup(&t, &ku2, 0, MPC_DIR_UPLINK, 103, &is_new);
    CHECK(e && is_new && e->flow_id == 3);
    mpc_flow_table_free(&t);
}

/* Random insert/expire against a reference array to validate backward-shift deletion. */
static void test_expiry_consistency(void)
{
    mpc_flow_table t;
    CHECK_EQ(mpc_flow_table_init(&t, 256), 0);
    enum { N = 180 };
    mpc_flow_key keys[N];
    uint64_t ids[N];
    srand(7);
    for (int i = 0; i < N; i++) {
        memset(&keys[i], 0, sizeof(keys[i]));
        keys[i].ipver = 4;
        keys[i].proto = 17;
        keys[i].lport = (uint16_t)(1000 + i);
        keys[i].rport = 53;
        keys[i].local[0] = 10;
        keys[i].remote[3] = (uint8_t)(rand() & 3);
        int is_new;
        /* Half the flows are "old" (time 0), half fresh (time 500). */
        mpc_flow_entry *e =
            mpc_flow_lookup(&t, &keys[i], 0, MPC_DIR_UPLINK, (i & 1) ? 500 : 0, &is_new);
        CHECK(e && is_new);
        ids[i] = e ? e->flow_id : 0;
    }
    CHECK_EQ(t.count, N);
    /* Fill to load-factor limit: additional inserts beyond 192 fail. */
    for (int round = 0; round < 3; round++)
        mpc_flow_sweep(&t, 600, 256);
    CHECK_EQ(t.count, N / 2);
    CHECK_EQ(t.flows_expired, N / 2);
    for (int i = 0; i < N; i++) {
        mpc_flow_entry *e = mpc_flow_find(&t, &keys[i]);
        if (i & 1)
            CHECK(e && e->flow_id == ids[i]);
        else
            CHECK(e == NULL);
    }
    /* Capacity limit. */
    int is_new;
    int created = 0, full = 0;
    for (int i = 0; i < 200; i++) {
        mpc_flow_key k = keys[0];
        k.lport = (uint16_t)(30000 + i);
        if (mpc_flow_lookup(&t, &k, 0, MPC_DIR_UPLINK, 500, &is_new))
            created++;
        else
            full++;
    }
    CHECK_EQ(created + N / 2, 192);
    CHECK(full > 0 && t.table_full == (uint64_t)full);
    mpc_flow_table_free(&t);
}

int main(void)
{
    test_parse();
    test_normalize_and_generation();
    test_expiry_consistency();
    TEST_DONE();
}
