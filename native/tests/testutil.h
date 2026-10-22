/* Shared test helpers: assertions and synthetic IPv4/IPv6 TCP/UDP packet builders. */
#ifndef MPC_TESTUTIL_H
#define MPC_TESTUTIL_H

#include <arpa/inet.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures;

#define CHECK(cond)                                                                \
    do {                                                                           \
        if (!(cond)) {                                                             \
            fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
            g_failures++;                                                          \
        }                                                                          \
    } while (0)

#define CHECK_EQ(a, b)                                                                  \
    do {                                                                                \
        long long _a = (long long)(a), _b = (long long)(b);                             \
        if (_a != _b) {                                                                 \
            fprintf(stderr, "%s:%d: CHECK_EQ failed: %s=%lld %s=%lld\n", __FILE__,       \
                    __LINE__, #a, _a, #b, _b);                                          \
            g_failures++;                                                               \
        }                                                                               \
    } while (0)

#define TEST_DONE()                                                   \
    do {                                                              \
        if (g_failures) {                                             \
            fprintf(stderr, "FAILED: %d check(s)\n", g_failures);    \
            return 1;                                                 \
        }                                                             \
        printf("OK\n");                                               \
        return 0;                                                     \
    } while (0)

static inline uint32_t csum_add(uint32_t sum, const uint8_t *p, size_t n)
{
    for (size_t i = 0; i + 1 < n; i += 2)
        sum += (uint32_t)((p[i] << 8) | p[i + 1]);
    if (n & 1)
        sum += (uint32_t)(p[n - 1] << 8);
    return sum;
}

static inline uint16_t csum_fold(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static inline void wr16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static inline void wr32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* L4 checksum over pseudo header. ip: 4 or 6; src/dst raw address bytes. */
static inline uint16_t l4_csum(int ip, const uint8_t *src, const uint8_t *dst, uint8_t proto,
                               const uint8_t *l4, size_t l4len)
{
    uint32_t sum = 0;
    size_t alen = ip == 4 ? 4 : 16;
    sum = csum_add(sum, src, alen);
    sum = csum_add(sum, dst, alen);
    uint8_t ph[8] = {0};
    if (ip == 4) {
        ph[0] = 0;
        ph[1] = proto;
        wr16(ph + 2, (uint16_t)l4len);
        sum = csum_add(sum, ph, 4);
    } else {
        wr32(ph, (uint32_t)l4len);
        ph[7] = proto;
        sum = csum_add(sum, ph, 8);
    }
    sum = csum_add(sum, l4, l4len);
    return csum_fold(sum);
}

/* Builds an IP header (v4: 20 bytes, v6: 40) + L4 bytes into out. Returns length. */
static inline size_t build_ip(uint8_t *out, int ip, const uint8_t *src, const uint8_t *dst,
                              uint8_t proto, const uint8_t *l4, size_t l4len, uint16_t frag)
{
    if (ip == 4) {
        memset(out, 0, 20);
        out[0] = 0x45;
        wr16(out + 2, (uint16_t)(20 + l4len));
        wr16(out + 4, 0x1234);
        wr16(out + 6, frag);
        out[8] = 64;
        out[9] = proto;
        memcpy(out + 12, src, 4);
        memcpy(out + 16, dst, 4);
        wr16(out + 10, csum_fold(csum_add(0, out, 20)));
        memcpy(out + 20, l4, l4len);
        return 20 + l4len;
    }
    memset(out, 0, 40);
    out[0] = 0x60;
    wr16(out + 4, (uint16_t)l4len);
    out[6] = proto;
    out[7] = 64;
    memcpy(out + 8, src, 16);
    memcpy(out + 24, dst, 16);
    memcpy(out + 40, l4, l4len);
    return 40 + l4len;
}

static inline size_t build_udp(uint8_t *out, int ip, const uint8_t *src, uint16_t sport,
                               const uint8_t *dst, uint16_t dport, const void *payload,
                               size_t plen)
{
    uint8_t l4[2048];
    wr16(l4, sport);
    wr16(l4 + 2, dport);
    wr16(l4 + 4, (uint16_t)(8 + plen));
    wr16(l4 + 6, 0);
    memcpy(l4 + 8, payload, plen);
    uint16_t c = l4_csum(ip, src, dst, 17, l4, 8 + plen);
    wr16(l4 + 6, c ? c : 0xffff);
    return build_ip(out, ip, src, dst, 17, l4, 8 + plen, 0);
}

static inline size_t build_tcp(uint8_t *out, int ip, const uint8_t *src, uint16_t sport,
                               const uint8_t *dst, uint16_t dport, uint32_t seq, uint32_t ack,
                               uint8_t flags, uint16_t win, const void *payload, size_t plen)
{
    uint8_t l4[2048];
    memset(l4, 0, 20);
    wr16(l4, sport);
    wr16(l4 + 2, dport);
    wr32(l4 + 4, seq);
    wr32(l4 + 8, ack);
    l4[12] = 5 << 4;
    l4[13] = flags;
    wr16(l4 + 14, win);
    memcpy(l4 + 20, payload, plen);
    wr16(l4 + 16, l4_csum(ip, src, dst, 6, l4, 20 + plen));
    return build_ip(out, ip, src, dst, 6, l4, 20 + plen, 0);
}

static inline uint16_t rd16be(const uint8_t *p) { return (uint16_t)((p[0] << 8) | p[1]); }
static inline uint32_t rd32be(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

#endif
