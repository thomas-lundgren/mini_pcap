/* Byte-level fixture tests for the PCAP + Linux SLL serializer. */
#include "mpc/pcap.h"
#include "testutil.h"

static uint32_t le32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static uint16_t be16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }

static void test_file_header(void)
{
    uint8_t b[24];
    CHECK_EQ(mpc_pcap_file_header(b, 128 + 16), 24);
    CHECK_EQ(le32(b), 0xA1B23C4D);
    CHECK(b[4] == 2 && b[5] == 0 && b[6] == 4 && b[7] == 0);
    CHECK_EQ(le32(b + 16), 144);
    CHECK_EQ(le32(b + 20), 113);
}

static void test_record(void)
{
    uint8_t ip4[40] = {0x45, 0, 0, 40};
    uint8_t ip6[48] = {0x60};
    uint8_t out[128];
    uint64_t ts = 1792737923123456789ull;
    size_t n = mpc_pcap_record(out, sizeof(out), ts, 1, ip4, 40, 1400);
    CHECK_EQ(n, 16 + 16 + 40);
    CHECK_EQ(le32(out), 1792737923u);
    CHECK_EQ(le32(out + 4), 123456789u);
    CHECK_EQ(le32(out + 8), 56);   /* incl_len includes SLL */
    CHECK_EQ(le32(out + 12), 1416); /* orig_len includes SLL */
    CHECK_EQ(be16(out + 16), 4);    /* OUTGOING = uplink */
    CHECK_EQ(be16(out + 18), 0xFFFE);
    CHECK_EQ(be16(out + 20), 0);
    for (int i = 22; i < 30; i++)
        CHECK_EQ(out[i], 0);
    CHECK_EQ(be16(out + 30), 0x0800);
    CHECK(memcmp(out + 32, ip4, 40) == 0);

    n = mpc_pcap_record(out, sizeof(out), ts, 0, ip6, 48, 48);
    CHECK_EQ(be16(out + 16), 0); /* HOST = downlink */
    CHECK_EQ(be16(out + 30), 0x86DD);
    CHECK_EQ(n, 80);

    uint8_t junk[3] = {0x12, 0, 0};
    n = mpc_pcap_record(out, sizeof(out), ts, 1, junk, 3, 3);
    CHECK_EQ(be16(out + 30), 0); /* not IPv4/IPv6: protocol 0, still recorded */
    n = mpc_pcap_record(out, sizeof(out), ts, 1, NULL, 0, 0);
    CHECK_EQ(n, 32);
    CHECK_EQ(le32(out + 8), 16);
    CHECK_EQ(mpc_pcap_record(out, 40, ts, 1, ip4, 40, 40), 0); /* too small */
}

int main(void)
{
    test_file_header();
    test_record();
    TEST_DONE();
}
