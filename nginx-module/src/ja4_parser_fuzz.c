/*
 * ja4_parser_fuzz.c — stand-alone fuzz wrapper for ja4_parse_client_hello.
 *
 * Not a libfuzzer harness (= no clang / sanitizer dependency); just a
 * tight loop that throws random / boundary inputs at the parser, each from
 * the end of a heap block (see at_end), and exits 0 only if every call
 * returns cleanly without crashing.  Pair with ASan during CI, without which
 * the block's end is not watched:
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


/* Every input reaches the parser from the END of a heap block: the byte
 * after it is the sanitizer's redzone, so a read of even one byte past the
 * length the parser was given stops the run.  Until 0.1.58 the inputs came
 * out of stack arrays and constants longer than themselves, where such a
 * read lands on bytes that are there and nothing notices -- the harness
 * proved the parser stayed inside the array, not inside the input.  Every
 * 64th call also runs from the START of a block of exactly the input's
 * size, which is what a read before the input would trip. */
#define ARENA 2112
static uint8_t *arena;
static size_t         calls;

static const uint8_t *at_end(const uint8_t *d, size_t n) {
    uint8_t *p;
    if (n > ARENA) {
        fprintf(stderr, "ja4_parser_fuzz: an input of %zu bytes does not fit the arena\n", n);
        abort();
    }
    p = arena + ARENA - n;
    if (n) {
        memcpy(p, d, n);
    }
    return p;
}

/* parse: ja4_parse_client_hello on d[0..n), handed over as at_end says. */
static int parse(const uint8_t *d, size_t n, ja4_parsed_t *out) {
    int rc = ja4_parse_client_hello(at_end(d, n), n, out);
    if (n > 0 && (calls++ & 63) == 0) {
        ja4_parsed_t again;
        uint8_t *q = malloc(n);
        if (q == NULL) abort();
        memcpy(q, d, n);
        if (ja4_parse_client_hello(q, n, &again) != rc) {
            fprintf(stderr, "ja4_parser_fuzz: one input, two answers\n");
            abort();
        }
        free(q);
    }
    return rc;
}

static void fuzz_random(size_t iters) {
    uint8_t  buf[2048];
    ja4_parsed_t out;
    for (size_t i = 0; i < iters; i++) {
        size_t n = rng_next() % sizeof(buf);
        for (size_t j = 0; j < n; j++) buf[j] = (uint8_t)rng_next();
        /* The function MUST NOT crash regardless of input. */
        (void)parse(buf, n, &out);
    }
}

/* A TLS 1.2 ClientHello, as the handshake message the parser is handed: two
 * ciphers, SNI and ALPN.  The truncation sweep's first subject. */
static const uint8_t short_hello[] = {
    0x01, 0x00, 0x00, 0x46,                         /* Handshake header (ClientHello, len=70) */
    0x03, 0x03,                                     /* legacy_version = TLS 1.2 */
    0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, /* random */
    0x00,                                           /* session_id_length */
    0x00, 0x04, 0x13, 0x01, 0x13, 0x02,             /* cipher_suites: len=4, two AES ciphers */
    0x01, 0x00,                                     /* compression_methods: len=1, null */
    0x00, 0x19,                                     /* extensions length = 25 */
    0x00, 0x00, 0x00, 0x09, 0x00, 0x07, 0x00, 0x00, 0x04, 'a','b','c','d',   /* SNI (host_name="abcd") */
    0x00, 0x10, 0x00, 0x08, 0x00, 0x06, 0x02, 'h', '2', 0x02, 'h', '1'      /* ALPN h2,h1 */
};


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

/* Truncation sweep: a hello that parses, cut at every offset.  The whole
 * message has to parse -- a sweep over one the parser refuses at its first
 * byte runs none of the code it is there for, and this one did for a long
 * time: its subject began with the TLS record header, which the parser is
 * never handed, and its lengths did not add up besides -- and every proper
 * prefix has to be refused: the handshake header says how long the message
 * is, and a parser that took less would be reading a hello the client did
 * not send. */
static void fuzz_truncated(void) {
    static const struct { const uint8_t *d; size_t n; const char *name; } subjects[] = {
        { short_hello, sizeof(short_hello), "the TLS 1.2 hello" },
        { seed_hello,  sizeof(seed_hello),  "the TLS 1.3 hello" },
    };
    ja4_parsed_t out;
    for (size_t s = 0; s < sizeof(subjects) / sizeof(subjects[0]); s++) {
        if (parse(subjects[s].d, subjects[s].n, &out) != 0) {
            fprintf(stderr, "ja4_parser_fuzz: %s does not parse whole\n", subjects[s].name);
            abort();
        }
        for (size_t cut = 0; cut < subjects[s].n; cut++) {
            if (parse(subjects[s].d, cut, &out) == 0) {
                fprintf(stderr, "ja4_parser_fuzz: %s parsed when cut to %zu bytes\n", subjects[s].name, cut);
                abort();
            }
        }
    }
}

/* Mutation fuzz: the seed with 1-8 bytes replaced and/or a random cut or
 * some junk appended.  Returns how many inputs the parser accepted, so the
 * run shows that the deep paths were exercised (the pure random pass
 * reaches almost none of them). */
static size_t fuzz_mutated(size_t iters) {
    uint8_t buf[sizeof(seed_hello) + 64];
    ja4_parsed_t out;
    size_t accepted = 0;
    for (size_t i = 0; i < iters; i++) {
        size_t n = sizeof(seed_hello);
        memcpy(buf, seed_hello, n);
        unsigned int k = 1 + rng_next() % 8;
        for (unsigned int j = 0; j < k; j++) {
            buf[rng_next() % n] = (uint8_t)rng_next();
        }
        if ((rng_next() & 3) == 0) n = rng_next() % (n + 1);        /* cut */
        if ((rng_next() & 7) == 0) {                                /* grow with junk */
            size_t extra = rng_next() % 64;
            for (size_t j = 0; j < extra; j++) buf[n + j] = (uint8_t)rng_next();
            n += extra;
        }
        if (parse(buf, n, &out) == 0) accepted++;
    }
    return accepted;
}

static void fuzz_zero_and_one(void) {
    ja4_parsed_t out;
    uint8_t one = 0;
    (void)ja4_parse_client_hello(NULL, 0, &out);
    (void)parse(&one, 0, &out);            /* one past the block's end, nothing to read */
    for (unsigned int b = 0; b < 256; b++) {
        one = (uint8_t)b;
        (void)parse(&one, 1, &out);
    }
}

int main(int argc, char **argv) {
    size_t iters = (argc > 1) ? (size_t)strtoul(argv[1], NULL, 10) : 100000;
    rng_state = (uint32_t)time(NULL);
    arena = malloc(ARENA);
    if (arena == NULL) return 1;

    fuzz_zero_and_one();
    fuzz_truncated();
    fuzz_random(iters);
    {
        ja4_parsed_t out;
        size_t accepted;
        if (parse(seed_hello, sizeof(seed_hello), &out) != 0
            || out.ncipher != 4 || out.sni_present_domain != 1
            || out.alpn_first != 'h' || out.supported_versions_max != 0x0304)
        {
            fprintf(stderr, "ja4_parser_fuzz: the seed hello did not parse as expected\n");
            return 1;
        }
        if (parse(short_hello, sizeof(short_hello), &out) != 0
            || out.ncipher != 2 || out.sni_present_domain != 1
            || out.alpn_first != 'h' || out.alpn_last != '2')
        {
            fprintf(stderr, "ja4_parser_fuzz: the TLS 1.2 hello did not parse as expected\n");
            return 1;
        }
        accepted = fuzz_mutated(iters);
        printf("ja4_parser_fuzz: %zu random iters + %zu mutated iters (%zu accepted) "
               "+ truncation sweep of two hellos that parse + edge cases, "
               "every input at the end of a heap block, no crash\n", iters, iters, accepted);
    }
    free(arena);
    return 0;
}
