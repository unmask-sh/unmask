/*
 * bv_parser_test.c — known-answer tests for the pure parts of the _bv path:
 * the entry decoder, the decimal and base-36 readers, the proof-of-work's
 * leading-zero count, the Cookie header splitter and the IPv6 /64 fold.
 *
 * The fuzzers (bv_parser_fuzz.c) prove these never read out of bounds;
 * this file pins what they answer.  The base-36 and leading-zero vectors
 * are the ones challenge.js and the Go cookies package agree on, so a drift
 * in any of the three shows up here before it loops a visitor.
 *
 * Build / run:
 *   gcc -std=gnu99 -Wall -Wextra bv_parser.c bv_parser_test.c -o bv_parser_test
 *   ./bv_parser_test
 */

#include "bv_parser.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_pass, g_fail;

#define CHECK(cond, msg) do {                                             \
    if (cond) { g_pass++; }                                               \
    else { g_fail++; fprintf(stderr, "FAIL: %s:%d  %s\n",                 \
                             __FILE__, __LINE__, (msg)); }                \
} while (0)

/* Collect every `_bv` value of a header, "~"-joined into out, and return
 * how many there were. */
static int collect(const char *hdr, char *out, size_t cap) {
    size_t off = 0, voff, vlen, used = 0;
    int n = 0;
    out[0] = '\0';
    while (bv_cookie_next((const unsigned char *)hdr, strlen(hdr), "_bv", 3,
                          &off, &voff, &vlen)) {
        if (n > 0 && used + 1 < cap) { out[used++] = '~'; }
        if (used + vlen + 1 > cap) { break; }
        memcpy(out + used, hdr + voff, vlen);
        used += vlen;
        out[used] = '\0';
        n++;
    }
    return n;
}

int main(void) {
    bv_fields_t f;
    char got[256];

    /* --- bv_parse_entry --- */
    {
        const char *c = "1700000000.0123456789abcdef.captcha";
        CHECK(bv_parse_entry((const unsigned char *)c, strlen(c), &f) == 1
              && f.format == BV_FMT_CAPTCHA
              && f.day_off == 0 && f.day_len == 10
              && f.sig_off == 11 && f.sig_len == 16
              && f.tail_off == 28 && f.tail_len == 7, "entry: CAPTCHA form");
        c = "1700000000.pow2.3k5x.18";
        CHECK(bv_parse_entry((const unsigned char *)c, strlen(c), &f) == 1
              && f.format == BV_FMT_POW2
              && f.day_len == 10 && f.sig_len == 4
              && f.tail_off == 16 && f.tail_len == 4, "entry: pow2 form");
        c = "1700000000.pow1.3k5x.18";
        CHECK(bv_parse_entry((const unsigned char *)c, strlen(c), &f) == 0,
              "entry: a 4-segment form other than pow2 is refused");
        c = "1700000000.0123456789abcde.captcha";
        CHECK(bv_parse_entry((const unsigned char *)c, strlen(c), &f) == 0,
              "entry: a 15-digit signature is refused");
        c = "17000000001.0123456789abcdef.captcha";
        CHECK(bv_parse_entry((const unsigned char *)c, strlen(c), &f) == 0,
              "entry: an 11-digit day is refused");
        c = "1700000000.0123456789abcdef.";
        CHECK(bv_parse_entry((const unsigned char *)c, strlen(c), &f) == 0,
              "entry: an empty kind is refused");
        CHECK(bv_parse_entry((const unsigned char *)"1.2", 3, &f) == 0,
              "entry: too short");
        CHECK(bv_parse_entry(NULL, 0, &f) == 0 && f.format == BV_FMT_NONE,
              "entry: NULL");
    }

    /* --- bv_atoll --- */
    CHECK(bv_atoll((const unsigned char *)"1700000000", 10) == 1700000000,
          "atoll: unix seconds");
    CHECK(bv_atoll((const unsigned char *)"0", 1) == 0, "atoll: zero");
    CHECK(bv_atoll((const unsigned char *)"999999999999999999", 18)
          == 999999999999999999LL, "atoll: 18 digits");
    CHECK(bv_atoll((const unsigned char *)"9999999999999999999", 19) == -1,
          "atoll: 19 digits refused");
    CHECK(bv_atoll((const unsigned char *)"12a", 3) == -1, "atoll: non-digit");
    CHECK(bv_atoll((const unsigned char *)"", 0) == -1, "atoll: empty");
    CHECK(bv_atoll((const unsigned char *)"-1", 2) == -1, "atoll: sign refused");

    /* --- bv_base36 (the PoW nonce) --- */
    CHECK(bv_base36((const unsigned char *)"0", 1) == 0, "base36: 0");
    CHECK(bv_base36((const unsigned char *)"z", 1) == 35, "base36: z");
    CHECK(bv_base36((const unsigned char *)"Z", 1) == 35, "base36: upper case");
    CHECK(bv_base36((const unsigned char *)"10", 2) == 36, "base36: 10");
    CHECK(bv_base36((const unsigned char *)"3k5x", 4) == 166101, "base36: 3k5x");
    CHECK(bv_base36((const unsigned char *)"1y2p0ij32e8e7", 13) == INT64_MAX,
          "base36: INT64_MAX");
    CHECK(bv_base36((const unsigned char *)"1y2p0ij32e8e8", 13) == -1,
          "base36: INT64_MAX + 1 refused");
    CHECK(bv_base36((const unsigned char *)"zzzzzzzzzzzzz", 13) == -1,
          "base36: 13 z's refused");
    CHECK(bv_base36((const unsigned char *)"00000000000001", 14) == -1,
          "base36: 14 characters refused");
    CHECK(bv_base36((const unsigned char *)"", 0) == -1, "base36: empty");
    CHECK(bv_base36((const unsigned char *)"1-", 2) == -1, "base36: bad char");
    CHECK(bv_base36(NULL, 0) == -1, "base36: NULL");

    /* --- bv_leading_zero_bits --- */
    {
        const unsigned char z2[] = {0x00, 0x00};
        const unsigned char b1[] = {0x00, 0x0f};
        const unsigned char b2[] = {0x01};
        const unsigned char b3[] = {0x80};
        const unsigned char b4[] = {0x00, 0x00, 0x20, 0xff};
        CHECK(bv_leading_zero_bits(z2, 2) == 16, "lzb: all zero");
        CHECK(bv_leading_zero_bits(b1, 2) == 12, "lzb: 00 0f");
        CHECK(bv_leading_zero_bits(b2, 1) == 7, "lzb: 01");
        CHECK(bv_leading_zero_bits(b3, 1) == 0, "lzb: 80");
        CHECK(bv_leading_zero_bits(b4, 4) == 18, "lzb: 00 00 20 ff");
        CHECK(bv_leading_zero_bits(b4, 0) == 0, "lzb: empty");
        CHECK(bv_leading_zero_bits(NULL, 4) == 0, "lzb: NULL");
    }

    /* --- bv_cookie_next --- */
    CHECK(collect("_bv=1.a.b", got, sizeof(got)) == 1 && strcmp(got, "1.a.b") == 0,
          "cookie: single pair");
    CHECK(collect("x=1; _bv=1.a.b; y=2", got, sizeof(got)) == 1
          && strcmp(got, "1.a.b") == 0, "cookie: among others");
    CHECK(collect("_bv=old; _bv=new", got, sizeof(got)) == 2
          && strcmp(got, "old~new") == 0, "cookie: every duplicate");
    CHECK(collect("_bvx=1; x_bv=2; _b=3", got, sizeof(got)) == 0,
          "cookie: a longer or shorter name is not a match");
    CHECK(collect("_BV=1", got, sizeof(got)) == 0, "cookie: case-sensitive name");
    CHECK(collect("_bv", got, sizeof(got)) == 0, "cookie: bare name");
    CHECK(collect("_bv; _bv=v", got, sizeof(got)) == 1 && strcmp(got, "v") == 0,
          "cookie: a bare name does not hide the next pair");
    CHECK(collect("_bv=", got, sizeof(got)) == 1 && strcmp(got, "") == 0,
          "cookie: empty value");
    CHECK(collect("_bv=\"1.a.b\"", got, sizeof(got)) == 1 && strcmp(got, "1.a.b") == 0,
          "cookie: quoted value loses its quotes");
    CHECK(collect("_bv=\"\"", got, sizeof(got)) == 1 && strcmp(got, "") == 0,
          "cookie: quoted empty value");
    CHECK(collect("_bv=\"x", got, sizeof(got)) == 1 && strcmp(got, "\"x") == 0,
          "cookie: an unbalanced quote stays");
    CHECK(collect("_bv = 1.a.b ; y=2", got, sizeof(got)) == 1
          && strcmp(got, "1.a.b") == 0, "cookie: spaces around '=' and before ';'");
    CHECK(collect("_bv\t=\t1.a.b", got, sizeof(got)) == 1 && strcmp(got, "1.a.b") == 0,
          "cookie: tabs around '='");
    CHECK(collect(";;; _bv=a;;;_bv=b;", got, sizeof(got)) == 2
          && strcmp(got, "a~b") == 0, "cookie: runs of separators");
    CHECK(collect("a=b=c; _bv=1=2", got, sizeof(got)) == 1 && strcmp(got, "1=2") == 0,
          "cookie: '=' inside a value is kept");
    CHECK(collect("", got, sizeof(got)) == 0, "cookie: empty header");
    {
        size_t off = 0, voff = 0, vlen = 0;
        CHECK(bv_cookie_next(NULL, 0, "_bv", 3, &off, &voff, &vlen) == 0,
              "cookie: NULL header");
    }

    /* --- unmask_bind_ip_token (the vectors bv_parser_fuzz.c also pins) --- */
    {
        char tok[16];
        CHECK(unmask_bind_ip_token("1.2.3.4", 7, tok) == 0, "bind: IPv4 as-is");
        CHECK(unmask_bind_ip_token("2001:db8:1:2:3:4:5:6", 20, tok) == 16
              && memcmp(tok, "20010db800010002", 16) == 0, "bind: IPv6 /64");
        CHECK(unmask_bind_ip_token("::ffff:1.2.3.4", 14, tok) == 0,
              "bind: v4-mapped as-is");
    }

    printf("bv_parser_test: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
