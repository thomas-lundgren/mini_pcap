/* PCAPNG v1 block serializer (SHB, IDB, EPB). Little-endian/native byte order,
 * declared by the SHB byte-order magic. Used only on the writer thread. */
#ifndef MPC_PCAPNG_H
#define MPC_PCAPNG_H

#include <stddef.h>
#include <stdint.h>

#define MPC_LINKTYPE_RAW 101 /* LINKTYPE_RAW: raw IPv4/IPv6, version from first nibble */

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

/* Formats the v1 metadata comment: "f-<flow>" or "u-<uid>;f-<flow>" (uid >= 0).
 * Returns length (no NUL), 0 when flow_id == 0 and uid < 0 (no comment). buf >= 48. */
size_t mpc_format_comment(char *buf, uint64_t flow_id, int32_t uid);

#endif
