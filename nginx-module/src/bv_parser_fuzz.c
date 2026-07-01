/*
 * bv_parser_fuzz.c — stand-alone fuzz wrapper for bv_parse_entry / bv_atoll.
 *
 * Same self-contained style as ja4_parser_fuzz.c (no libFuzzer / clang
 * dependency): a tight loop of random, truncated and edge-case inputs.  Pair
 * with ASan + UBSan for the strongest signal; exits 0 only if every call
 * returns cleanly AND every "success" parse hands back in-bounds field spans:
 *
 *   gcc -fsanitize=address,undefined -g -O1 \
 *       bv_parser.c bv_parser_fuzz.c -o bv_parser_fuzz
 *   ./bv_parser_fuzz 2000000
 */
#include "bv_parser.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint32_t rng_state = 0x9e3779b9u;

static uint32_t rng_next(void) {
    uint32_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    rng_state = x;
    return x;
}

/* Every field a successful parse returns must sit fully inside [0,len). */
static void check_fields(const bv_fields_t *f, size_t len) {
    assert(f->format != BV_FMT_NONE);
    assert(f->day_off  <= len && f->day_len  <= len - f->day_off);
    assert(f->sig_off  <= len && f->sig_len  <= len - f->sig_off);
    assert(f->tail_off <= len && f->tail_len <= len - f->tail_off);
}

static void run_one(const unsigned char *d, size_t n) {
    bv_fields_t f;
    if (bv_parse_entry(n ? d : NULL, n, &f)) {
        check_fields(&f, n);
    }
    (void)bv_atoll(n ? d : NULL, n);
}

static void fuzz_random(size_t iters) {
    unsigned char buf[256];
    for (size_t i = 0; i < iters; i++) {
        size_t n = rng_next() % (sizeof(buf) + 1); /* 0..256 (exceeds the 80-byte cap) */
        for (size_t j = 0; j < n; j++) {
            uint32_t r = rng_next();
            /* Bias toward the alphabet that actually appears in a _bv cookie so
             * the random stream reaches the deeper structural branches, not
             * just the length / first-dot early rejects. */
            switch (r & 7) {
                case 0: case 1: buf[j] = '.'; break;
                case 2:         buf[j] = '~'; break;
                case 3:         buf[j] = (unsigned char)('0' + (r >> 3) % 10); break;
                case 4:         buf[j] = (unsigned char)('a' + (r >> 3) % 6);  break; /* hex tail */
                default:        buf[j] = (unsigned char)(r >> 3); break;
            }
        }
        run_one(buf, n);
    }
}

static void fuzz_truncated(void) {
    /* Real-ish entries + degenerate shapes, truncated at every offset to catch
     * an off-by-one read past the buffer at any split boundary. */
    static const char *seeds[] = {
        "19876.0123456789abcdef.captcha_only",
        "19876.pow2.000000abcdef0.18",
        "1.2.3", "1.2.3.4", "...", "....", "~~~",
        "1..0123456789abcdef", "1234567890.0123456789abcdef.k",
        ".0123456789abcdef.kind", "x.pow2..flags",
    };
    for (size_t s = 0; s < sizeof(seeds) / sizeof(seeds[0]); s++) {
        const unsigned char *d = (const unsigned char *)seeds[s];
        size_t L = strlen(seeds[s]);
        for (size_t cut = 0; cut <= L; cut++) {
            run_one(d, cut);
        }
    }
}

static void fuzz_edges(void) {
    bv_fields_t f;
    (void)bv_parse_entry(NULL, 0, &f);
    unsigned char one = '.';
    (void)bv_parse_entry(&one, 1, &f);
    (void)bv_atoll(NULL, 0);

    /* All dots at and beyond the 80-byte length cap. */
    unsigned char dots[128];
    memset(dots, '.', sizeof(dots));
    for (size_t n = 4; n <= sizeof(dots); n++) {
        run_one(dots, n);
    }

    /* atoll overflow guard: 18 / 19 / 20-digit all-nines. */
    (void)bv_atoll((const unsigned char *)"999999999999999999", 18);
    (void)bv_atoll((const unsigned char *)"9999999999999999999", 19);
    (void)bv_atoll((const unsigned char *)"99999999999999999999", 20);
}

/* unmask_bind_ip_token: fixed vectors pin the C output to the Go admin's
 * cookies.bindIP() (a drift here = IPv6 cookies that mint in Go but fail in the
 * plugin = a challenge loop), then an OOB sweep over assorted lengths/bytes. */
static void check_bind_ip(void) {
    char out[16];
    struct { const char *ip; const char *want; } v[] = {
        {"1.2.3.4", NULL},                            /* IPv4        -> as-is */
        {"203.0.113.5", NULL},
        {"2001:db8::1", "20010db800000000"},          /* IPv6        -> /64   */
        {"2001:db8:1:2:3:4:5:6", "20010db800010002"},
        {"fe80::1", "fe80000000000000"},
        {"::ffff:1.2.3.4", NULL},                     /* v4-mapped   -> as-is */
        {"not-an-ip", NULL},                          /* unparseable -> as-is */
        {"", NULL},
    };
    for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); i++) {
        size_t n = unmask_bind_ip_token(v[i].ip, strlen(v[i].ip), out);
        if (v[i].want == NULL) {
            assert(n == 0);
        } else {
            assert(n == 16 && memcmp(out, v[i].want, 16) == 0);
        }
    }
    /* ASan / UBSan: must never read outside [ip, ip+len) for any input. */
    unsigned char buf[64];
    for (size_t n = 0; n <= sizeof(buf); n++) {
        for (size_t i = 0; i < n; i++) {
            uint32_t x = rng_next();
            buf[i] = (x & 7) == 0 ? ':' : (unsigned char)(x & 0xff); /* bias colons */
        }
        (void)unmask_bind_ip_token((const char *)buf, n, out);
    }
}

int main(int argc, char **argv) {
    size_t iters = (argc > 1) ? (size_t)strtoul(argv[1], NULL, 10) : 1000000;
    rng_state = (uint32_t)time(NULL) | 1u;

    check_bind_ip();
    fuzz_edges();
    fuzz_truncated();
    fuzz_random(iters);

    printf("bv_parser_fuzz: %zu random iters + truncation sweep + edges + bind-ip parity — no crash\n", iters);
    return 0;
}
