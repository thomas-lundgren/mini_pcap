/* PCAPNG v1 block serializer (SHB, IDB, EPB). Little-endian/native byte order,
 * declared by the SHB byte-order magic. Used only on the writer thread. */
#ifndef MPC_PCAPNG_H
#define MPC_PCAPNG_H

#include <stddef.h>
#include <stdint.h>

#define MPC_LINKTYPE_RAW 101 /* LINKTYPE_RAW: raw IPv4/IPv6, version from first nibble */
#define MPC_LINKTYPE_UPPER_PDU 252 /* LINKTYPE_WIRESHARK_UPPER_PDU: tagged PDU for a named dissector */

#define MPC_EPB_FLAG_INBOUND 0x1u  /* epb_flags bits 0-1 = 01 */
#define MPC_EPB_FLAG_OUTBOUND 0x2u /* epb_flags bits 0-1 = 10 */

/* Each function returns the number of bytes written, or 0 if cap is too small. */
size_t mpc_pcapng_shb(uint8_t *out, size_t cap, const char *userappl, const char *os,
                      const char *hardware);
size_t mpc_pcapng_idb(uint8_t *out, size_t cap, uint16_t linktype, uint32_t snaplen,
                      const char *if_name, uint8_t tsresol);

/* Upper bound on EPB size for given captured length and comment length. */
static inline size_t mpc_pcapng_epb_max(size_t cap_len, size_t comment_len)
{
    return 28 + ((cap_len + 3) & ~(size_t)3) + 4 + ((comment_len + 3) & ~(size_t)3) + 8 + 4 + 4;
}

/* flags == 0 omits the epb_flags option; comment_len == 0 omits opt_comment. */
size_t mpc_pcapng_epb(uint8_t *out, size_t cap, uint32_t if_id, uint64_t ts, const uint8_t *data,
                      uint32_t cap_len, uint32_t orig_len, const char *comment, size_t comment_len,
                      uint32_t flags);

/* Upper bound for mpc_pcapng_upper_pdu_epb(). */
static inline size_t mpc_pcapng_upper_pdu_max(size_t info_len, size_t json_len)
{
    return mpc_pcapng_epb_max(4 + 4 + 4 + info_len + 4 + json_len, 0);
}

/* EPB whose data is an Upper PDU: dissector tag "json", optional Info-column text,
 * end tag, then the JSON bytes (tags unpadded, big endian). Wireshark decodes it
 * with its built-in JSON dissector. */
size_t mpc_pcapng_upper_pdu_epb(uint8_t *out, size_t cap, uint32_t if_id, uint64_t ts,
                                const char *info, size_t info_len, const uint8_t *json,
                                size_t json_len);

#define MPC_COMMENT_MAX 64
/* Formats the v2 metadata comment, keys in this order and each optional:
 * "u=<uid>" (uid >= 0), "f=<flow>" (flow_id != 0), "c=<ctx>" (ctx != 0), joined by ';'.
 * Returns length (no NUL); 0 = no comment. buf >= MPC_COMMENT_MAX. */
size_t mpc_format_comment(char *buf, uint64_t flow_id, int32_t uid, uint32_t ctx);

#endif
