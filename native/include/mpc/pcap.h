/* Classic PCAP serializer (nanosecond variant) with Linux cooked capture v1 (SLL)
 * pseudo-headers that carry packet direction. Used only on the writer thread. */
#ifndef MPC_PCAP_H
#define MPC_PCAP_H

#include <stddef.h>
#include <stdint.h>

#define MPC_PCAP_MAGIC_NS 0xA1B23C4Du /* nanosecond-resolution timestamps */
#define MPC_LINKTYPE_LINUX_SLL 113
#define MPC_PCAP_FILE_HDR 24
#define MPC_PCAP_REC_HDR 16
#define MPC_SLL_HDR 16

/* SLL packet types (big endian on disk): direction convention of this logger. */
#define MPC_SLL_HOST 0     /* downlink: received by the device */
#define MPC_SLL_OUTGOING 4 /* uplink: sent by the device */
#define MPC_ARPHRD_NONE 0xFFFE /* what Linux reports for TUN devices */

/* Global header; snaplen is the IP prefix length + MPC_SLL_HDR. Returns 24. */
size_t mpc_pcap_file_header(uint8_t *out, uint32_t snaplen);

/* Upper bound on one record (record header + SLL + data). */
static inline size_t mpc_pcap_record_max(size_t cap_len)
{
    return MPC_PCAP_REC_HDR + MPC_SLL_HDR + cap_len;
}

/* One record: ts_ns is nanoseconds since the Unix epoch. cap_len/orig_len are IP
 * lengths; the stored lengths include the 16-byte SLL header. Returns bytes
 * written, or 0 if cap is too small. */
size_t mpc_pcap_record(uint8_t *out, size_t cap, uint64_t ts_ns, int uplink, const uint8_t *ip,
                       uint32_t cap_len, uint32_t orig_len);

#endif
