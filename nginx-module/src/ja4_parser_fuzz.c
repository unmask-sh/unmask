/*
 * ja4_parser_fuzz.c — stand-alone fuzz wrapper for ja4_parse_client_hello.
 *
 * Not a libfuzzer harness (= no clang / sanitizer dependency); just a
 * tight loop that throws random / boundary inputs at the parser and
 * exits 0 only if every call returns cleanly without crashing.  Pair
 * with ASan during CI for the strongest signal:
 *
 *   gcc -fsanitize=address -g -O1 \
 *       ja4_parser.c ja4_parser_fuzz.c -o ja4_parser_fuzz
 *   ./ja4_parser_fuzz 100000
 */

#include "ja4_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

static uint32_t rng_state = 0x12345678u;

static uint32_t rng_next(void) {
    /* xorshift32 — deterministic enough for repro */
    uint32_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    rng_state = x;
    return x;
}

static void fuzz_random(size_t iters) {
    uint8_t  buf[2048];
    ja4_parsed_t out;
    for (size_t i = 0; i < iters; i++) {
        size_t n = rng_next() % sizeof(buf);
        for (size_t j = 0; j < n; j++) buf[j] = (uint8_t)rng_next();
        /* The function MUST NOT crash regardless of input. */
        (void)ja4_parse_client_hello(buf, n, &out);
    }
}

static void fuzz_truncated(void) {
    /* Take a known-valid TLS 1.2 ClientHello and truncate at every offset
     * to catch off-by-one read past the buffer. */
    static const uint8_t hello[] = {
        0x16, 0x03, 0x01, 0x00, 0x4f,                   /* TLS record header (Handshake, TLS 1.0, len=79) */
        0x01, 0x00, 0x00, 0x4b,                         /* Handshake header (ClientHello, len=75) */
        0x03, 0x03,                                     /* legacy_version = TLS 1.2 */
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* random */
        0x00,                                           /* session_id_length */
        0x00, 0x04, 0x13, 0x01, 0x13, 0x02,             /* cipher_suites: len=4, two AES_128 ciphers */
        0x01, 0x00,                                     /* compression_methods: len=1, null */
        0x00, 0x1e,                                     /* extensions length = 30 */
        0x00, 0x00, 0x00, 0x09, 0x00, 0x07, 0x00, 0x00, 0x04, 'a','b','c','d',   /* SNI (host_name="abcd") */
        0x00, 0x10, 0x00, 0x08, 0x00, 0x06, 0x02, 'h', '2', 0x02, 'h', '1'      /* ALPN h2,h1 */
    };
    ja4_parsed_t out;
    for (size_t cut = 0; cut < sizeof(hello); cut++) {
        (void)ja4_parse_client_hello(hello, cut, &out);
    }
}

static void fuzz_zero_and_one(void) {
    ja4_parsed_t out;
    (void)ja4_parse_client_hello(NULL, 0, &out);
    uint8_t one = 0;
    (void)ja4_parse_client_hello(&one, 1, &out);
}

int main(int argc, char **argv) {
    size_t iters = (argc > 1) ? (size_t)strtoul(argv[1], NULL, 10) : 100000;
    rng_state = (uint32_t)time(NULL);

    fuzz_zero_and_one();
    fuzz_truncated();
    fuzz_random(iters);

    printf("ja4_parser_fuzz: %zu random iters + truncation sweep + edge cases — no crash\n", iters);
    return 0;
}
