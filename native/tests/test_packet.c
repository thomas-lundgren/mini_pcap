/* Header parser edge cases: transport-header end (hdr_len) per protocol, IPv6
 * extension-header chains (hop-by-hop, destination, AH, fragment), truncation. */
#include "mpc/packet.h"
#include "testutil.h"

static const uint8_t A4[4] = {10, 111, 0, 2}, B4[4] = {93, 184, 216, 34};
static const uint8_t A6[16] = {0xfd, 0, 0x6d, 0x70, 0x63, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};
static const uint8_t B6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x99};

/* IPv6 packet with the given extension headers (each 8 bytes, next-header chained) then UDP. */
static size_t v6_with_ext(uint8_t *out, const uint8_t *types, int n, uint16_t frag_off)
{
    uint8_t l4[256];
    size_t o = 0;
    for (int i = 0; i < n; i++) {
        uint8_t next = i + 1 < n ? types[i + 1] : 17;
        memset(l4 + o, 0, 8);
        l4[o] = next;
        if (types[i] == 51) {
            l4[o + 1] = 0; /* AH: (0 + 2) * 4 = 8 bytes */
        } else if (types[i] == 44) {
            wr16(l4 + o + 2, frag_off);
        }
        o += 8;
    }
    wr16(l4 + o, 5000);
    wr16(l4 + o + 2, 443);
    wr16(l4 + o + 4, 8 + 4);
    memcpy(l4 + o + 8, "data", 4);
    return build_ip(out, 6, A6, B6, types[0], l4, o + 12, 0);
}

int main(void)
{
    uint8_t p[512], payload[100] = {0};
    mpc_pkt_info in;

    size_t n = build_tcp(p, 4, A4, 1, B4, 2, 0, 0, 0x02, 1, NULL, 0);
    CHECK_EQ(mpc_parse_packet(p, n, &in), 0);
    CHECK(in.has_ports && in.hdr_len == 40);
    p[20 + 12] = 15 << 4; /* maximal TCP header: 60 bytes */
    CHECK_EQ(mpc_parse_packet(p, n, &in), 0);
    CHECK_EQ(in.hdr_len, 80);

    n = build_udp(p, 6, A6, 5000, B6, 443, payload, 50);
    CHECK_EQ(mpc_parse_packet(p, n, &in), 0);
    CHECK(in.proto == 17 && in.hdr_len == 48);

    uint8_t icmp[8] = {128};
    n = build_ip(p, 6, A6, B6, 58, icmp, 8, 0);
    CHECK_EQ(mpc_parse_packet(p, n, &in), 0);
    CHECK(!in.has_ports && in.hdr_len == 48);

    const uint8_t chain[] = {0, 60, 51};
    n = v6_with_ext(p, chain, 3, 0);
    CHECK_EQ(mpc_parse_packet(p, n, &in), 0);
    CHECK(in.proto == 17 && in.has_ports && in.sport == 5000 && in.hdr_len == 40 + 24 + 8);

    const uint8_t frag[] = {44};
    n = v6_with_ext(p, frag, 1, 0); /* first fragment: ports visible */
    CHECK_EQ(mpc_parse_packet(p, n, &in), 0);
    CHECK(in.has_ports && in.hdr_len == 56);
    n = v6_with_ext(p, frag, 1, 1480); /* non-initial fragment: no transport header */
    CHECK_EQ(mpc_parse_packet(p, n, &in), 0);
    CHECK(!in.has_ports && in.hdr_len == 48);

    n = v6_with_ext(p, chain, 3, 0);
    CHECK_EQ(mpc_parse_packet(p, 50, &in), 0); /* truncated inside the extension chain */
    CHECK(in.proto == 0 && !in.has_ports);

    n = build_ip(p, 4, A4, B4, 17, payload, 40, 0x00b9); /* IPv4 non-initial fragment */
    CHECK_EQ(mpc_parse_packet(p, n, &in), 0);
    CHECK(!in.has_ports && in.hdr_len == 20);
    p[0] = 0x4f; /* IHL 60 > available */
    CHECK_EQ(mpc_parse_packet(p, 40, &in), -1);
    CHECK_EQ(mpc_parse_packet(p, 0, &in), -1);
    TEST_DONE();
}
