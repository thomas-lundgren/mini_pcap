/* Byte-level fixture tests for the PCAPNG serializer and comment grammar. */
#include "mpc/pcapng.h"
#include "testutil.h"

static uint32_t le32(const uint8_t *p)
{
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

static uint16_t le16(const uint8_t *p)
{
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

static void test_comment(void)
{
    char b[48];
    size_t n = mpc_format_comment(b, 1042, -1);
    CHECK(n == 6 && memcmp(b, "f-1042", 6) == 0);
    n = mpc_format_comment(b, 1042, 10234);
    CHECK(n == 14 && memcmp(b, "u-10234;f-1042", 14) == 0);
    n = mpc_format_comment(b, 0, -1);
    CHECK_EQ(n, 0);
    n = mpc_format_comment(b, 0, 0);
    CHECK(n == 3 && memcmp(b, "u-0", 3) == 0);
    n = mpc_format_comment(b, UINT64_MAX, 2147483647);
    CHECK(n == strlen("u-2147483647;f-18446744073709551615"));
    CHECK(memcmp(b, "u-2147483647;f-18446744073709551615", n) == 0);
}

static void test_shb_idb(void)
{
    uint8_t buf[512];
    size_t n = mpc_pcapng_shb(buf, sizeof(buf), "app", "Android 17", NULL);
    CHECK(n > 0 && n % 4 == 0);
    CHECK_EQ(le32(buf), 0x0A0D0D0A);
    CHECK_EQ(le32(buf + 4), n);
    CHECK_EQ(le32(buf + n - 4), n);
    CHECK_EQ(le32(buf + 8), 0x1A2B3C4D);
    CHECK_EQ(le16(buf + 12), 1);
    CHECK_EQ(le16(buf + 14), 0);
    /* options: shb_os (3) "Android 17" (10 -> pad 12), shb_userappl (4) "app" (3 -> 4), end */
    CHECK_EQ(le16(buf + 24), 3);
    CHECK_EQ(le16(buf + 26), 10);
    CHECK(memcmp(buf + 28, "Android 17\0\0", 12) == 0);
    CHECK_EQ(le16(buf + 40), 4);
    CHECK_EQ(le16(buf + 42), 3);
    CHECK_EQ(le32(buf + 48), 0);
    CHECK_EQ(n, 24 + 16 + 8 + 4 + 4);
    CHECK_EQ(mpc_pcapng_shb(buf, 20, "app", NULL, NULL), 0);

    n = mpc_pcapng_idb(buf, sizeof(buf), 101, 256, "tun0", 6);
    CHECK_EQ(n, 16 + 8 + 8 + 4 + 4);
    CHECK_EQ(le32(buf), 1);
    CHECK_EQ(le32(buf + 4), n);
    CHECK_EQ(le16(buf + 8), 101);
    CHECK_EQ(le32(buf + 12), 256);
    CHECK_EQ(le16(buf + 16), 2);
    CHECK_EQ(le16(buf + 18), 4);
    CHECK(memcmp(buf + 20, "tun0", 4) == 0);
    CHECK_EQ(le16(buf + 24), 9);
    CHECK_EQ(le16(buf + 26), 1);
    CHECK_EQ(buf[28], 6);
    CHECK_EQ(le32(buf + n - 4), n);
}

static void test_epb(void)
{
    uint8_t buf[256];
    uint8_t data[5] = {0x45, 1, 2, 3, 4};
    uint64_t ts = 0x0123456789abcdefULL;
    size_t n = mpc_pcapng_epb(buf, sizeof(buf), 0, ts, data, 5, 1400, "f-7", 3,
                              MPC_EPB_FLAG_OUTBOUND);
    /* 28 hdr + 8 data(5 padded) + comment 4+4 + flags 8 + end 4 + trailer 4 */
    CHECK_EQ(n, 28 + 8 + 8 + 8 + 4 + 4);
    CHECK_EQ(le32(buf), 6);
    CHECK_EQ(le32(buf + 4), n);
    CHECK_EQ(le32(buf + 12), 0x01234567);
    CHECK_EQ(le32(buf + 16), 0x89abcdef);
    CHECK_EQ(le32(buf + 20), 5);
    CHECK_EQ(le32(buf + 24), 1400);
    CHECK(memcmp(buf + 28, data, 5) == 0);
    CHECK(buf[33] == 0 && buf[34] == 0 && buf[35] == 0);
    CHECK_EQ(le16(buf + 36), 1);
    CHECK_EQ(le16(buf + 38), 3);
    CHECK(memcmp(buf + 40, "f-7\0", 4) == 0);
    CHECK_EQ(le16(buf + 44), 2);
    CHECK_EQ(le16(buf + 46), 4);
    CHECK_EQ(le32(buf + 48), 2);
    CHECK_EQ(le32(buf + 52), 0);
    CHECK_EQ(le32(buf + n - 4), n);
    CHECK(n <= mpc_pcapng_epb_max(5, 3));

    /* No options at all: no endofopt either. Zero-length packet. */
    n = mpc_pcapng_epb(buf, sizeof(buf), 0, 1, NULL, 0, 0, NULL, 0, 0);
    CHECK_EQ(n, 32);
    CHECK_EQ(le32(buf + n - 4), 32);
    /* Exactly-aligned data. */
    uint8_t d8[8] = {0x60};
    n = mpc_pcapng_epb(buf, sizeof(buf), 0, 1, d8, 8, 8, NULL, 0, MPC_EPB_FLAG_INBOUND);
    CHECK_EQ(n, 28 + 8 + 8 + 4 + 4);
    /* Capacity too small -> 0. */
    CHECK_EQ(mpc_pcapng_epb(buf, 40, 0, 1, d8, 8, 8, "f-1", 3, 1), 0);
}

int main(void)
{
    test_comment();
    test_shb_idb();
    test_epb();
    TEST_DONE();
}
