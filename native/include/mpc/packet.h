/* Minimal, bounds-checked IPv4/IPv6 + TCP/UDP header parser for the hot path.
 * No allocation, no syscalls. */
#ifndef MPC_PACKET_H
#define MPC_PACKET_H

#include <stddef.h>
#include <stdint.h>

#define MPC_PROTO_ICMP 1
#define MPC_PROTO_TCP 6
#define MPC_PROTO_UDP 17
#define MPC_PROTO_ICMPV6 58

#define MPC_TCP_FIN 0x01
#define MPC_TCP_SYN 0x02
#define MPC_TCP_RST 0x04
#define MPC_TCP_ACK 0x10

typedef struct {
    uint8_t ipver;     /* 4 or 6; 0 = not a parsable IP packet */
    uint8_t proto;     /* final L4 protocol number, 0 if unknown */
    uint8_t has_ports; /* 1 when TCP/UDP ports were read (not a non-initial fragment) */
    uint8_t tcp_flags;
    uint16_t sport, dport; /* host byte order */
    uint8_t src[16], dst[16]; /* IPv4 uses the first 4 bytes, rest zero */
} mpc_pkt_info;

/* Returns 0 on success (info->ipver != 0), -1 when the packet is not parsable.
 * len is the number of contiguous bytes available at p. */
int mpc_parse_packet(const uint8_t *p, size_t len, mpc_pkt_info *info);

#endif
