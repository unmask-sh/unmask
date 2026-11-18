/*
 * bv_parser_fuzz.c — stand-alone fuzz wrapper for bv_parse_entry / bv_atoll.
 *
 * Same self-contained style as ja4_parser_fuzz.c (no libFuzzer / clang
 * dependency): a tight loop of random, shaped, truncated and edge-case
 * inputs, each handed over from the end of a heap block (see at_end).  Pair
 * with ASan + UBSan, without which the block's end is not watched; exits 0
 * only if every call returns cleanly AND every "success" parse hands back
 * in-bounds field spans of a width its format has:
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

/* Every input reaches the parser from the END of a heap block: the byte
 * after it is the sanitizer's redzone, so a read of even one byte past the
 * length the parser was given stops the run.  Until 0.1.58 the inputs came
 * out of stack arrays and string literals longer than themselves, where such
 * a read lands on bytes that are there and nothing notices -- the harness
 * proved the parser stayed inside the array, not inside the input.  Every
 * 64th call also runs from the START of a block of exactly the input's size,
 * which is what a read before the input would trip. */
#define ARENA 320
static unsigned char *arena;
static size_t         calls;

static const unsigned char *at_end(const unsigned char *d, size_t n) {
    assert(n <= ARENA);
    unsigned char *p = arena + ARENA - n;
    if (n) {
        memcpy(p, d, n);
    }
    return p;
}

/* Every field a successful parse returns must sit fully inside [0,len), and
 * be of a width the format has. */
static void check_fields(const bv_fields_t *f, size_t len) {
    assert(f->format != BV_FMT_NONE);
    assert(f->day_off  <= len && f->day_len  <= len - f->day_off);
    assert(f->sig_off  <= len && f->sig_len  <= len - f->sig_off);
    assert(f->tail_off <= len && f->tail_len <= len - f->tail_off);
    assert(f->day_len >= 1 && f->day_len <= 10);
    if (f->format == BV_FMT_CAPTCHA) {
        /* The verifier sizes its MAC compare by sig_len: no other width. */
        assert(f->sig_len == BV_SIG_HEX || f->sig_len == BV_SIG_HEX_WIDE);
        assert(f->tail_len >= 1 && f->tail_len <= 32);
        assert(f->tail_off + f->tail_len == len);
    } else {
        assert(f->format == BV_FMT_POW2 && f->sig_len == 4);
        assert(f->tail_len >= 1 && f->tail_len <= 13);
    }
}

static void parse_at(const unsigned char *d, size_t n) {
    bv_fields_t f;
    if (bv_parse_entry(d, n, &f)) {
        check_fields(&f, n);
    }
    (void)bv_atoll(d, n);
    (void)bv_base36(d, n);
}

static void run_one(const unsigned char *d, size_t n) {
    if (n == 0) {
        parse_at(NULL, 0);
        parse_at(arena + ARENA, 0);   /* one past the end, nothing to read */
        return;
    }
    parse_at(at_end(d, n), n);
    if ((calls++ & 63) == 0) {
        unsigned char *q = malloc(n);
        assert(q != NULL);
        memcpy(q, d, n);
        parse_at(q, n);
        free(q);
    }
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

/* fuzz_shaped: entries of the right shape -- digits, a dot, hex, a dot, a
 * word -- with each segment's length drawn from just around its bounds, so
 * that the run spends its time on the accept / refuse edges (a signature of
 * 15, 16, 17, 31, 32, 33 digits; a kind of 0, 1, 32, 33 characters; an entry
 * of 76 to 81 bytes) instead of on the first missing dot. */
static void fuzz_shaped(size_t iters) {
    static const size_t day_n[]  = {0, 1, 9, 10, 11};
    static const size_t sig_n[]  = {0, 4, 15, 16, 17, 24, 31, 32, 33, 40};
    static const size_t kind_n[] = {0, 1, 7, 11, 31, 32, 33, 36};
    unsigned char buf[ARENA];
    for (size_t i = 0; i < iters; i++) {
        uint32_t r = rng_next();
        size_t dn = day_n[r % 5], sn = sig_n[(r >> 4) % 10], kn = kind_n[(r >> 9) % 8];
        size_t n = 0;
        for (size_t j = 0; j < dn; j++) buf[n++] = (unsigned char)('0' + rng_next() % 10);
        buf[n++] = '.';
        if (((r >> 13) & 15) == 0) {
            memcpy(buf + n, "pow2", 4); n += 4;
        } else {
            for (size_t j = 0; j < sn; j++) buf[n++] = (unsigned char)"0123456789abcdef"[rng_next() & 15];
        }
        buf[n++] = '.';
        for (size_t j = 0; j < kn; j++) buf[n++] = (unsigned char)('a' + rng_next() % 26);
        if (((r >> 17) & 7) == 0) {            /* a fourth segment */
            buf[n++] = '.';
            buf[n++] = '1';
        }
        if (((r >> 20) & 31) == 0 && n > 0) {  /* one byte gone wrong */
            buf[rng_next() % n] = (unsigned char)rng_next();
        }
        run_one(buf, n);
        if (((r >> 25) & 7) == 0) {            /* and cut short */
            run_one(buf, rng_next() % (n + 1));
        }
    }
}

static void fuzz_truncated(void) {
    /* Real-ish entries + degenerate shapes, truncated at every offset to catch
     * an off-by-one read past the buffer at any split boundary. */
    static const char *seeds[] = {
        "19876.0123456789abcdef.captcha_only",
        "1700000000.0123456789abcdef0123456789abcdef.captcha",
        "1700000000.0123456789abcdef0123456789abcdef.abcdefghijklmnopqrstuvwxyzabcdef",
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
        /* A relay range used as the bind key (ngx_unmask_bind_key) never
         * parses as an address, so the fold would leave it alone too -- the
         * same as Go's bindIP, which the verifier and the daemon both rely on. */
        {"140.248.33.0/24", NULL},
        {"2a02:26f7:c9c0::/44", NULL},
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
        (void)unmask_bind_ip_token((const char *)at_end(buf, n), n, out);
    }
}

/* bv_cookie_next: random Cookie headers biased to the cookie alphabet, plus
 * real shapes truncated at every offset.  Every value it yields must lie
 * inside the header, and the scan must terminate. */
static void fuzz_cookie(size_t iters) {
    unsigned char buf[300];
    static const char *seeds[] = {
        "_bv=1700000000.0123456789abcdef.captcha; x=1",
        "x=1; _bv=\"1700000000.pow2.3k5x.18\"; _bv = v ;_bv",
        ";;=;=;_bv==;_bv=\"\";\"_bv\"=1",
    };
    for (size_t s = 0; s < sizeof(seeds) / sizeof(seeds[0]); s++) {
        size_t L = strlen(seeds[s]);
        for (size_t cut = 0; cut <= L; cut++) {
            size_t off = 0, voff = 0, vlen = 0, guard = 0;
            const unsigned char *h = at_end((const unsigned char *)seeds[s], cut);
            while (bv_cookie_next(h, cut, "_bv", 3,
                                  &off, &voff, &vlen)) {
                assert(voff <= cut && vlen <= cut - voff);
                assert(++guard <= cut + 1);
            }
        }
    }
    for (size_t i = 0; i < iters; i++) {
        size_t n = rng_next() % (sizeof(buf) + 1);
        size_t off = 0, voff = 0, vlen = 0, guard = 0;
        for (size_t j = 0; j < n; j++) {
            uint32_t r = rng_next();
            switch (r & 7) {
                case 0:  buf[j] = ';'; break;
                case 1:  buf[j] = '='; break;
                case 2:  buf[j] = ' '; break;
                case 3:  buf[j] = '"'; break;
                case 4:  buf[j] = '_'; break;
                case 5:  buf[j] = (unsigned char)("bv"[(r >> 3) & 1]); break;
                default: buf[j] = (unsigned char)(r >> 3); break;
            }
        }
        const unsigned char *h = at_end(buf, n);
        while (bv_cookie_next(h, n, "_bv", 3, &off, &voff, &vlen)) {
            assert(voff <= n && vlen <= n - voff);
            assert(++guard <= n + 1);
        }
    }
}

int main(int argc, char **argv) {
    size_t iters = (argc > 1) ? (size_t)strtoul(argv[1], NULL, 10) : 1000000;
    rng_state = (uint32_t)time(NULL) | 1u;
    arena = malloc(ARENA);
    assert(arena != NULL);

    check_bind_ip();
    fuzz_edges();
    fuzz_truncated();
    fuzz_random(iters);
    fuzz_shaped(iters);
    fuzz_cookie(iters);
    free(arena);

    printf("bv_parser_fuzz: %zu random + %zu shaped iters + truncation sweep + edges + bind-ip parity + cookie splitter, every input at the end of a heap block — no crash\n", iters, iters);
    return 0;
}
