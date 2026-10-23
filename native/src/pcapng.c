#include "mpc/pcapng.h"

#include <string.h>

#define BT_SHB 0x0A0D0D0Au
#define BT_IDB 0x00000001u
#define BT_EPB 0x00000006u

static inline void w16(uint8_t *p, uint16_t v) { memcpy(p, &v, 2); }
static inline void w32(uint8_t *p, uint32_t v) { memcpy(p, &v, 4); }
static inline size_t pad4(size_t n) { return (n + 3) & ~(size_t)3; }

/* Writes one option (code, len, value, zero padding); returns bytes used. */
static size_t opt(uint8_t *p, uint16_t code, const void *val, size_t len)
{
    w16(p, code);
    w16(p + 2, (uint16_t)len);
    if (len)
        memcpy(p + 4, val, len);
    size_t padded = pad4(len);
    if (padded > len)
        memset(p + 4 + len, 0, padded - len);
    return 4 + padded;
}

static size_t str_opt_size(const char *s)
{
    return s && *s ? 4 + pad4(strlen(s)) : 0;
}

size_t mpc_pcapng_shb(uint8_t *out, size_t cap, const char *userappl, const char *os,
                      const char *hardware)
{
    size_t total = 28 + str_opt_size(hardware) + str_opt_size(os) + str_opt_size(userappl) + 4;
    if (total > cap || total > 0xffff)
        return 0;
    w32(out, BT_SHB);
    w32(out + 4, (uint32_t)total);
    w32(out + 8, 0x1A2B3C4Du);
    w16(out + 12, 1);
    w16(out + 14, 0);
    uint64_t section_len = UINT64_MAX; /* -1: unspecified */
    memcpy(out + 16, &section_len, 8);
    size_t o = 24;
    if (hardware && *hardware)
        o += opt(out + o, 2, hardware, strlen(hardware)); /* shb_hardware */
    if (os && *os)
        o += opt(out + o, 3, os, strlen(os)); /* shb_os */
    if (userappl && *userappl)
        o += opt(out + o, 4, userappl, strlen(userappl)); /* shb_userappl */
    o += opt(out + o, 0, NULL, 0); /* opt_endofopt */
    w32(out + o, (uint32_t)total);
    return o + 4;
}

size_t mpc_pcapng_idb(uint8_t *out, size_t cap, uint16_t linktype, uint32_t snaplen,
                      const char *if_name, uint8_t tsresol)
{
    size_t total = 16 + str_opt_size(if_name) + 8 /* if_tsresol */ + 4 + 4;
    if (total > cap)
        return 0;
    w32(out, BT_IDB);
    w32(out + 4, (uint32_t)total);
    w16(out + 8, linktype);
    w16(out + 10, 0);
    w32(out + 12, snaplen);
    size_t o = 16;
    if (if_name && *if_name)
        o += opt(out + o, 2, if_name, strlen(if_name)); /* if_name */
    o += opt(out + o, 9, &tsresol, 1);                  /* if_tsresol */
    o += opt(out + o, 0, NULL, 0);
    w32(out + o, (uint32_t)total);
    return o + 4;
}

size_t mpc_pcapng_epb(uint8_t *out, size_t cap, uint32_t if_id, uint64_t ts, const uint8_t *data,
                      uint32_t cap_len, uint32_t orig_len, const char *comment, size_t comment_len,
                      uint32_t flags)
{
    if (comment_len > 0xffff)
        return 0;
    size_t opts = 0;
    if (comment_len)
        opts += 4 + pad4(comment_len);
    if (flags)
        opts += 8;
    if (opts)
        opts += 4; /* opt_endofopt */
    size_t total = 28 + pad4(cap_len) + opts + 4;
    if (total > cap)
        return 0;
    w32(out, BT_EPB);
    w32(out + 4, (uint32_t)total);
    w32(out + 8, if_id);
    w32(out + 12, (uint32_t)(ts >> 32));
    w32(out + 16, (uint32_t)ts);
    w32(out + 20, cap_len);
    w32(out + 24, orig_len);
    size_t o = 28;
    if (cap_len && data != out + o) /* data may already be in place (Upper PDU) */
        memcpy(out + o, data, cap_len);
    o += cap_len;
    while (o & 3)
        out[o++] = 0;
    if (comment_len)
        o += opt(out + o, 1, comment, comment_len); /* opt_comment */
    if (flags)
        o += opt(out + o, 2, &flags, 4); /* epb_flags */
    if (opts)
        o += opt(out + o, 0, NULL, 0);
    w32(out + o, (uint32_t)total);
    return o + 4;
}

/* Writes decimal digits of v at p; returns count. No locale, no allocation. */
static size_t u64_dec(char *p, uint64_t v)
{
    char tmp[20];
    size_t n = 0;
    do {
        tmp[n++] = (char)('0' + (v % 10));
        v /= 10;
    } while (v);
    for (size_t i = 0; i < n; i++)
        p[i] = tmp[n - 1 - i];
    return n;
}

size_t mpc_format_comment(char *buf, uint64_t flow_id, int32_t uid, uint32_t ctx)
{
    size_t o = 0;
    if (uid >= 0) {
        buf[o++] = 'u';
        buf[o++] = '=';
        o += u64_dec(buf + o, (uint64_t)uid);
    }
    if (flow_id) {
        if (o)
            buf[o++] = ';';
        buf[o++] = 'f';
        buf[o++] = '=';
        o += u64_dec(buf + o, flow_id);
    }
    if (ctx) {
        if (o)
            buf[o++] = ';';
        buf[o++] = 'c';
        buf[o++] = '=';
        o += u64_dec(buf + o, ctx);
    }
    return o;
}

static size_t pdu_tag(uint8_t *p, uint16_t tag, const void *v, size_t len)
{
    p[0] = (uint8_t)(tag >> 8);
    p[1] = (uint8_t)tag;
    p[2] = (uint8_t)(len >> 8);
    p[3] = (uint8_t)len;
    if (len)
        memcpy(p + 4, v, len);
    return 4 + len;
}

size_t mpc_pcapng_upper_pdu_epb(uint8_t *out, size_t cap, uint32_t if_id, uint64_t ts,
                                const char *info, size_t info_len, const uint8_t *json,
                                size_t json_len)
{
    if (info_len > 0xffff || json_len > 0xffffff)
        return 0;
    size_t total = mpc_pcapng_upper_pdu_max(info_len, json_len);
    if (cap < total)
        return 0;
    /* Build the PDU in place where the EPB packet data goes (offset 28). */
    uint8_t *d = out + 28;
    size_t o = pdu_tag(d, 12, "json", 4); /* EXP_PDU_TAG_DISSECTOR_NAME */
    if (info_len)
        o += pdu_tag(d + o, 36, info, info_len); /* EXP_PDU_TAG_COL_INFO_TEXT */
    o += pdu_tag(d + o, 0, NULL, 0); /* EXP_PDU_TAG_END_OF_OPT */
    memcpy(d + o, json, json_len);
    o += json_len;
    /* Header and padding/options around the PDU, reusing the EPB encoder's layout. */
    return mpc_pcapng_epb(out, cap, if_id, ts, d, (uint32_t)o, (uint32_t)o, NULL, 0, 0);
}
