/*
 * ban_list_fuzz.c — stand-alone fuzz wrapper for the ban file parser.
 *
 * Same self-contained style as bv_parser_fuzz.c: random buffers biased to
 * the file's alphabet, the real shapes truncated at every offset, and the
 * invariants the module relies on checked after every parse -- the count
 * sizes the arrays exactly, every row's key and action lie inside the
 * buffer and are NUL-terminated within it, the rows are sorted, and the
 * lookup finds every row by its own key.  Pair with ASan + UBSan:
 *
 *   clang -fsanitize=address,undefined -fno-sanitize-recover=all -g -O1 \
 *       ban_list.c ban_list_fuzz.c -o ban_list_fuzz
 *   ./ban_list_fuzz 1000000
 */
#include "ban_list.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static uint32_t rng_state = 0x2545f491u;

static uint32_t rng_next(void) {
    uint32_t x = rng_state;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    rng_state = x;
    return x;
}

/* in_buf: s points into [buf, buf+len] and its NUL sits at or before buf+len. */
static int in_buf(const char *s, const char *buf, size_t len) {
    if (s < buf || s > buf + len) return 0;
    return memchr(s, '\0', (size_t)(buf + len - s) + 1) != NULL;
}

static void run_one(const unsigned char *d, size_t n) {
    char *buf = malloc(n + 1);
    size_t nr, np, got_r, got_p, i;
    unmask_ban_row_t *rows;
    unmask_ban_prefix_t *prefixes;

    assert(buf != NULL);
    memcpy(buf, d, n);
    buf[n] = 'X';   /* the parse must set this byte, never read past it */

    unmask_ban_count(buf, n, &nr, &np);
    rows = calloc(nr + 1, sizeof(*rows));
    prefixes = calloc(np + 1, sizeof(*prefixes));
    assert(rows != NULL && prefixes != NULL);

    assert(unmask_ban_parse(buf, n, rows, nr, &got_r, prefixes, np, &got_p) == 0);
    assert(got_r == nr && got_p == np);
    assert(buf[n] == '\0');

    for (i = 0; i < nr; i++) {
        assert(in_buf(rows[i].key, buf, n));
        assert(in_buf(rows[i].action, buf, n) || strcmp(rows[i].action, "deny") == 0);
        if (i > 0) assert(strcmp(rows[i - 1].key, rows[i].key) <= 0);
        assert(unmask_ban_lookup(rows, nr, rows[i].key) != NULL);
    }
    for (i = 0; i < np; i++) {
        assert(prefixes[i].prefix >= buf && prefixes[i].prefix + prefixes[i].prefix_len <= buf + n);
        assert(memchr(prefixes[i].prefix, '/', prefixes[i].prefix_len) != NULL);
        assert(in_buf(prefixes[i].action, buf, n) || strcmp(prefixes[i].action, "deny") == 0);
    }
    assert(unmask_ban_lookup(rows, nr, "") == NULL || nr > 0);

    free(prefixes);
    free(rows);
    free(buf);
}

static void fuzz_random(size_t iters) {
    unsigned char buf[512];
    for (size_t i = 0; i < iters; i++) {
        size_t n = rng_next() % (sizeof(buf) + 1);
        for (size_t j = 0; j < n; j++) {
            uint32_t r = rng_next();
            /* Bias toward the file's own alphabet so the deeper branches
             * (second '|', action, prefix rows, sorting) are reached. */
            switch (r & 15) {
                case 0: case 1: buf[j] = '|'; break;
                case 2: case 3: buf[j] = '\n'; break;
                case 4:         buf[j] = '/'; break;
                case 5:         buf[j] = '#'; break;
                case 6:         buf[j] = ' '; break;
                case 7:         buf[j] = '\r'; break;
                case 8:         buf[j] = '.'; break;
                case 9:         buf[j] = ':'; break;
                case 10: case 11: buf[j] = (unsigned char)('0' + (r >> 4) % 10); break;
                case 12: case 13: buf[j] = (unsigned char)('a' + (r >> 4) % 26); break;
                default:        buf[j] = (unsigned char)(r >> 4); break;
            }
        }
        run_one(buf, n);
    }
}

static void fuzz_truncated(void) {
    static const char *seeds[] = {
        "192.0.2.10|t13d3515h2_8daaf6152771_e5627efa2ab1|honeypot|pow_then_captcha\n"
        "|t13d1517h2_8daaf6152771_b0da82dd1658|manual|captcha_only\n"
        "192.0.2.11||manual|deny\n",
        "2001:db8:1:2::/64|\r\n203.0.113.0/24||manual|captcha_only\n",
        "c|x|s|deny\na|x|s|pow_only\nb|x\nbare\n",
        "# only a comment", "|||", "\n\n\n", "/", "a/b|", "a/b||",
    };
    for (size_t s = 0; s < sizeof(seeds) / sizeof(seeds[0]); s++) {
        const unsigned char *d = (const unsigned char *)seeds[s];
        size_t L = strlen(seeds[s]);
        for (size_t cut = 0; cut <= L; cut++) {
            run_one(d, cut);
        }
    }
}

int main(int argc, char **argv) {
    size_t iters = (argc > 1) ? (size_t)strtoul(argv[1], NULL, 10) : 1000000;
    rng_state = (uint32_t)time(NULL) | 1u;

    run_one((const unsigned char *)"", 0);
    fuzz_truncated();
    fuzz_random(iters);

    printf("ban_list_fuzz: %zu random iters + truncation sweep — no crash, invariants held\n", iters);
    return 0;
}
