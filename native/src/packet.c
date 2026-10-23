#include "mpc/packet.h"

#include <string.h>

static inline uint16_t rd16(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }

static void parse_l4(const uint8_t *l4, size_t avail, mpc_pkt_info *info, size_t l4off)
{
    info->hdr_len = (uint16_t)l4off;
    if (info->proto == MPC_PROTO_TCP) {
        if (avail < 14)
            return;
        size_t doff = (size_t)(l4[12] >> 4) * 4;
        info->hdr_len = (uint16_t)(l4off + (doff >= 20 ? doff : 20));
        info->sport = rd16(l4);
        info->dport = rd16(l4 + 2);
        info->tcp_flags = l4[13];
        info->has_ports = 1;
    } else if (info->proto == MPC_PROTO_UDP) {
        if (avail < 8)
            return;
        info->sport = rd16(l4);
        info->dport = rd16(l4 + 2);
        info->has_ports = 1;
        info->hdr_len = (uint16_t)(l4off + 8);
    } else if (info->proto == MPC_PROTO_ICMP || info->proto == MPC_PROTO_ICMPV6) {
        info->hdr_len = (uint16_t)(l4off + 8);
    }
}

int mpc_parse_packet(const uint8_t *p, size_t len, mpc_pkt_info *info)
{
    memset(info, 0, sizeof(*info));
    if (len < 1)
        return -1;
    uint8_t ver = p[0] >> 4;
    if (ver == 4) {
        if (len < 20)
            return -1;
        size_t ihl = (size_t)(p[0] & 0x0f) * 4;
        if (ihl < 20 || ihl > len)
            return -1;
        info->ipver = 4;
        info->proto = p[9];
        memcpy(info->src, p + 12, 4);
        memcpy(info->dst, p + 16, 4);
        uint16_t frag = rd16(p + 6);
        info->hdr_len = (uint16_t)ihl;
        if ((frag & 0x1fff) != 0)
            return 0; /* non-initial fragment: no transport header */
        parse_l4(p + ihl, len - ihl, info, ihl);
        return 0;
    }
    if (ver == 6) {
        if (len < 40)
            return -1;
        info->ipver = 6;
        memcpy(info->src, p + 8, 16);
        memcpy(info->dst, p + 24, 16);
        uint8_t nh = p[6];
        size_t off = 40;
        info->hdr_len = 40;
        /* Walk a bounded number of extension headers. */
        for (int i = 0; i < 8; i++) {
            if (nh == 0 || nh == 43 || nh == 60) { /* hop-by-hop, routing, dest opts */
                if (off + 8 > len) {
                    info->proto = 0;
                    return 0;
                }
                size_t hlen = ((size_t)p[off + 1] + 1) * 8;
                nh = p[off];
                off += hlen;
                info->hdr_len = (uint16_t)off;
                continue;
            }
            if (nh == 44) { /* fragment */
                if (off + 8 > len) {
                    info->proto = 0;
                    return 0;
                }
                uint16_t fo = rd16(p + off + 2);
                info->proto = p[off];
                off += 8;
                info->hdr_len = (uint16_t)off;
                if ((fo & 0xfff8) != 0)
                    return 0; /* non-initial fragment */
                nh = info->proto;
                continue;
            }
            break;
        }
        info->proto = nh;
        if (off <= len)
            parse_l4(p + off, len - off, info, off);
        return 0;
    }
    return -1;
}
