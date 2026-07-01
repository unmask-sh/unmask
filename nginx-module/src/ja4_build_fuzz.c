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

int main(int argc, char **argv) {
    size_t iters = (argc > 1) ? (size_t)strtoul(argv[1], NULL, 10) : 1000000;
    rng_state = (uint32_t)time(NULL) | 1u;

    fuzz_tiny_out();
    fuzz_random_struct(iters);
    fuzz_parse_then_build(iters);

    printf("ja4_build_fuzz: %zu struct + %zu parse-build iters + tiny-out sweep — no crash\n",
           iters, iters);
    return 0;
}
