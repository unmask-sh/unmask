/*
 * ja4_build_fuzz.c — stand-alone fuzz wrapper for ja4_build_string.
 *
 * Three angles, all of which must run without a crash / sanitizer trap and
 * must keep ja4_build_string's output-buffer contract:
 *
 *   1. parse-then-build : random bytes -> ja4_parse_client_hello -> build
 *      (the real per-handshake path; exercises the parser + builder together).
 *   2. random struct     : a ja4_parsed_t filled with random data AND
 *      deliberately out-of-range counts (negative / past JA4_MAX_*), to prove
 *      the defensive clamp keeps every read/write inside the scratch buffers.
 *   3. tiny out buffers  : every capacity 0..JA4_STRING_MAX, to prove the
 *      result is always NUL-terminated and never exceeds the buffer.
 *
 * Pair with ASan/UBSan for the strongest signal (SHA256 needs libcrypto):
 *   clang -fsanitize=address,undefined -fno-sanitize-recover=all -g -O1 \
 *       ja4_parser.c ja4_build.c ja4_build_fuzz.c -lcrypto -o ja4_build_fuzz
 *   ./ja4_build_fuzz 1000000
 */

#include "ja4_build.h"
#include "ja4_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

static uint32_t rng_state = 0x243f6a88u;

static uint32_t rng_next(void) {
    /* xorshift32 — deterministic enough for repro. */
    uint32_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    rng_state = x;
    return x;
}

/* Assert ja4_build_string's contract: result fits and is NUL-terminated. */
static void check_contract(const char *out, size_t n, size_t cap) {
    if (cap == 0) return; /* nothing written */
    if (n >= cap) {
        fprintf(stderr, "ja4_build_fuzz: length %zu >= cap %zu\n", n, cap);
        abort();
    }
    if (out[n] != '\0') {
        fprintf(stderr, "ja4_build_fuzz: not NUL-terminated at %zu\n", n);
        abort();
    }
}

static void fuzz_parse_then_build(size_t iters) {
    uint8_t buf[2048];
    ja4_parsed_t p;
    char out[JA4_STRING_MAX];
    for (size_t k = 0; k < iters; k++) {
        size_t nlen = rng_next() % sizeof(buf);
        for (size_t j = 0; j < nlen; j++) buf[j] = (uint8_t)rng_next();
        if (ja4_parse_client_hello(buf, nlen, &p) == 0) {
            size_t n = ja4_build_string(&p, out, sizeof(out));
            check_contract(out, n, sizeof(out));
        }
    }
}

static void fuzz_random_struct(size_t iters) {
    ja4_parsed_t p;
    char out[JA4_STRING_MAX];
    for (size_t k = 0; k < iters; k++) {
        /* Fill the arrays fully so reads up to any (clamped) count land on
         * initialized memory; the clamp is what keeps them in bounds. */
        for (int i = 0; i < JA4_MAX_CIPHERS; i++)    p.ciphers[i]    = rng_next() & 0xFFFF;
        for (int i = 0; i < JA4_MAX_EXTENSIONS; i++) p.extensions[i] = rng_next() & 0xFFFF;
        for (int i = 0; i < JA4_MAX_SIG_ALGS; i++)   p.sig_algs[i]   = rng_next() & 0xFFFF;
        p.legacy_version         = rng_next() & 0xFFFF;
        p.supported_versions_max = rng_next() & 0xFFFF;
        /* Counts span well past the valid range (incl. negative) so the
         * clamp is the only thing standing between us and an overrun. */
        p.ncipher   = (int)(rng_next() % 600) - 50; /* -50 .. 549 */
        p.nexts     = (int)(rng_next() % 600) - 50;
        p.nsig_algs = (int)(rng_next() % 200) - 50;
        p.has_sig_algs       = (int)(rng_next() & 1);
        p.sni_present_domain = (int)(rng_next() & 1);
        p.alpn_first = (int)(rng_next() & 0xFF);
        p.alpn_last  = (int)(rng_next() & 0xFF);

        size_t n = ja4_build_string(&p, out, sizeof(out));
        check_contract(out, n, sizeof(out));
    }
}

static void fuzz_tiny_out(void) {
    ja4_parsed_t p;
    memset(&p, 0, sizeof(p));
    p.legacy_version = 0x0303;
    p.ncipher = 2; p.ciphers[0] = 0x1301; p.ciphers[1] = 0x1302;
    p.alpn_first = '0'; p.alpn_last = '0';
    for (size_t cap = 0; cap <= JA4_STRING_MAX; cap++) {
        char small[JA4_STRING_MAX + 1];
        memset(small, 0x7f, sizeof(small));
        size_t n = ja4_build_string(&p, small, cap);
        check_contract(small, n, cap);
    }
}


/* A TLS 1.3-style ClientHello as browsers send it: GREASE in the cipher and
 * extension lists, SNI, supported_versions, signature_algorithms, ALPN and
 * a key_share.  The seed for the mutation fuzz below: random bytes almost
 * never pass the handshake header, so they never reach the extension
 * parsing; a seed mutated by a few bytes does. */
static const uint8_t seed_hello[] = {
    0x01, 0x00, 0x00, 0xa4,                         /* ClientHello, len=164 */
    0x03, 0x03,                                     /* legacy_version TLS 1.2 */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* random */
    0x00,                                           /* session_id_length */
    0x00, 0x0a, 0x2a, 0x2a, 0x13, 0x01, 0x13, 0x02, 0x13, 0x03, 0xc0, 0x2b, /* ciphers: GREASE + 4 */
    0x01, 0x00,                                     /* compression: null */
    0x00, 0x71,                                     /* extensions length = 113 */
    0x3a, 0x3a, 0x00, 0x00,                         /* GREASE ext, empty */
    0x00, 0x00, 0x00, 0x10, 0x00, 0x0e, 0x00, 0x00, 0x0b,
    'e','x','a','m','p','l','e','.','c','o','m',    /* SNI example.com */
    0x00, 0x2b, 0x00, 0x05, 0x04, 0x03, 0x04, 0x03, 0x03, /* supported_versions 1.3, 1.2 */
    0x00, 0x0d, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x04, 0x01, /* sigalgs */
    0x00, 0x10, 0x00, 0x0e, 0x00, 0x0c, 0x02, 'h', '2', 0x05, 'h','t','t','p','/','1','.','1', /* ALPN */
    0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1d, 0x00, 0x20, /* key_share x25519 */
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32,
    0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x1d  /* supported_groups */
};

/* Mutated seeds through parse -> build (the random pass rarely parses, so
 * it exercises the builder on an empty struct only). */
static size_t fuzz_mutated_parse_build(size_t iters) {
    uint8_t buf[sizeof(seed_hello) + 64];
    char out_str[128];
    ja4_parsed_t parsed;
    size_t accepted = 0;
    for (size_t i = 0; i < iters; i++) {
        size_t n = sizeof(seed_hello);
        memcpy(buf, seed_hello, n);
        unsigned int k = 1 + rng_next() % 8;
        for (unsigned int j = 0; j < k; j++) buf[rng_next() % n] = (uint8_t)rng_next();
        if ((rng_next() & 3) == 0) n = rng_next() % (n + 1);
        if (ja4_parse_client_hello(buf, n, &parsed) == 0) {
            accepted++;
            (void)ja4_build_string(&parsed, out_str, sizeof(out_str));
            (void)ja4_build_string(&parsed, out_str, 1 + rng_next() % sizeof(out_str));
        }
    }
    return accepted;
}

int main(int argc, char **argv) {
    size_t iters = (argc > 1) ? (size_t)strtoul(argv[1], NULL, 10) : 1000000;
    rng_state = (uint32_t)time(NULL) | 1u;

    fuzz_tiny_out();
    fuzz_random_struct(iters);
    fuzz_parse_then_build(iters);
    {
        size_t accepted = fuzz_mutated_parse_build(iters);
        printf("ja4_build_fuzz: %zu struct + %zu parse-build + %zu mutated (%zu accepted) iters "
               "+ tiny-out sweep, no crash\n", iters, iters, iters, accepted);
    }
    return 0;
}
