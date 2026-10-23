#include "mpc/pcap.h"

#include <string.h>

_Static_assert(__BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__, "PCAP fields are written in host order (little endian)");

static inline void w32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static inline void w16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static inline void b16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

size_t mpc_pcap_file_header(uint8_t *out, uint32_t snaplen)
{
    w32(out, MPC_PCAP_MAGIC_NS);
    w16(out + 4, 2);
    w16(out + 6, 4);
    w32(out + 8, 0);  /* thiszone */
    w32(out + 12, 0); /* sigfigs */
    w32(out + 16, snaplen);
    w32(out + 20, MPC_LINKTYPE_LINUX_SLL);
    return MPC_PCAP_FILE_HDR;
}

size_t mpc_pcap_record(uint8_t *out, size_t cap, uint64_t ts_ns, int uplink, const uint8_t *ip,
                       uint32_t cap_len, uint32_t orig_len)
{
    size_t total = mpc_pcap_record_max(cap_len);
    if (total > cap)
        return 0;
    w32(out, (uint32_t)(ts_ns / 1000000000ull));
    w32(out + 4, (uint32_t)(ts_ns % 1000000000ull));
    w32(out + 8, cap_len + MPC_SLL_HDR);
    w32(out + 12, orig_len + MPC_SLL_HDR);
    uint8_t *s = out + MPC_PCAP_REC_HDR;
    b16(s, uplink ? MPC_SLL_OUTGOING : MPC_SLL_HOST);
    b16(s + 2, MPC_ARPHRD_NONE);
    b16(s + 4, 0); /* no link-layer address */
    memset(s + 6, 0, 8);
    uint16_t proto = 0;
    if (cap_len)
        proto = (ip[0] >> 4) == 4 ? 0x0800 : (ip[0] >> 4) == 6 ? 0x86DD : 0;
    b16(s + 14, proto);
    if (cap_len)
        memcpy(s + MPC_SLL_HDR, ip, cap_len);
    return total;
}
