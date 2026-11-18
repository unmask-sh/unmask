/*
 * bypass_list_fuzz.c — stand-alone fuzz wrapper for the run-time bypass list
 * parser.
 *
 * Same self-contained style as ban_list_fuzz.c: random buffers biased to the
 * file's alphabet, a real file truncated at every offset, and after every
 * parse the invariants the module relies on -- the count bounds the arrays,
 * every interval has lo <= hi, the intervals are sorted and disjoint, and the
 * binary search answers as a scan over them does, for random addresses and
 * for both ends of every interval.  Each input is handed over from the end
 * of a heap block (see at_end).  Pair with ASan + UBSan, without which the
 * block's end is not watched:
 *
 *   clang -fsanitize=address,undefined -fno-sanitize-recover=all -g -O1 \
 *       bypass_list.c bypass_list_fuzz.c -o bypass_list_fuzz
 *   ./bypass_list_fuzz 1000000
 */
#include "bypass_list.h"

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

static int scan_v4(const unmask_bypass_v4_t *v, size_t n, uint32_t a) {
    for (size_t i = 0; i < n; i++) {
        if (v[i].lo <= a && a <= v[i].hi) return 1;
    }
    return 0;
}

static int scan_v6(const unmask_bypass_v6_t *v, size_t n, const unsigned char *a) {
    for (size_t i = 0; i < n; i++) {
        if (memcmp(v[i].lo, a, 16) <= 0 && memcmp(a, v[i].hi, 16) <= 0) return 1;
    }
    return 0;
}


/* Every input reaches the parser from the END of a heap block: the byte
 * after it is the sanitizer's redzone, so a read of even one byte past the
 * length the parser was given stops the run.  Until 0.1.58 the inputs came
 * out of stack arrays and constants longer than themselves, where such a
 * read lands on bytes that are there and nothing notices -- the harness
 * proved the parser stayed inside the array, not inside the input.  Every
 * 64th call also runs from the START of a block of exactly the input's
 * size, which is what a read before the input would trip. */
#define ARENA 640
static char *arena;
static size_t       calls;

static const char *at_end(const char *d, size_t n) {
    char *p;
    if (n > ARENA) {
        fprintf(stderr, "bypass_list_fuzz: an input of %zu bytes does not fit the arena\n", n);
        abort();
    }
    p = arena + ARENA - n;
    if (n) {
        memcpy(p, d, n);
    }
    return p;
}

static void run_at(const char *d, size_t len);

/* run_one: the checks on in[0..len), handed over as at_end says. */
static void run_one(const char *in, size_t len) {
    if (in == NULL) {
        run_at(NULL, 0);
        return;
    }
    run_at(at_end(in, len), len);
    if (len > 0 && (calls++ & 63) == 0) {
        char *q = malloc(len);
        assert(q != NULL);
        memcpy(q, in, len);
        run_at(q, len);
        free(q);
    }
}

static void run_at(const char *d, size_t len) {
    size_t c4, c6, n4, n6;
    unmask_bypass_count(d, len, &c4, &c6);
    unmask_bypass_v4_t *v4 = malloc((c4 ? c4 : 1) * sizeof(*v4));
    unmask_bypass_v6_t *v6 = malloc((c6 ? c6 : 1) * sizeof(*v6));
    assert(v4 != NULL && v6 != NULL);
    (void) unmask_bypass_parse(d, len, v4, c4, &n4, v6, c6, &n6);
    assert(n4 <= c4 && n6 <= c6);
    for (size_t i = 0; i < n4; i++) {
        assert(v4[i].lo <= v4[i].hi);
        if (i > 0) assert(v4[i - 1].hi < v4[i].lo);
        assert(unmask_bypass_has_v4(v4, n4, v4[i].lo) && unmask_bypass_has_v4(v4, n4, v4[i].hi));
    }
    for (size_t i = 0; i < n6; i++) {
        assert(memcmp(v6[i].lo, v6[i].hi, 16) <= 0);
        if (i > 0) assert(memcmp(v6[i - 1].hi, v6[i].lo, 16) < 0);
        assert(unmask_bypass_has_v6(v6, n6, v6[i].lo) && unmask_bypass_has_v6(v6, n6, v6[i].hi));
    }
    for (int k = 0; k < 8; k++) {
        uint32_t a = rng_next();
        assert(unmask_bypass_has_v4(v4, n4, a) == scan_v4(v4, n4, a));
        unsigned char b[16];
        for (int j = 0; j < 16; j += 4) {
            uint32_t r = rng_next();
            memcpy(b + j, &r, 4);
        }
        if (n6 > 0 && (rng_next() & 1)) {
            memcpy(b, v6[rng_next() % n6].lo, 8);   /* near a real range */
        }
        assert(unmask_bypass_has_v6(v6, n6, b) == scan_v6(v6, n6, b));
    }
    free(v4);
    free(v6);
}

static const char alphabet[] = "0123456789abcdef.:/\n #\r\t";

static void fuzz_random(size_t iters) {
    char buf[512];
    for (size_t i = 0; i < iters; i++) {
        size_t n = rng_next() % sizeof(buf);
        for (size_t j = 0; j < n; j++) {
            buf[j] = (rng_next() & 7) == 0 ? (char) rng_next()
                                           : alphabet[rng_next() % (sizeof(alphabet) - 1)];
        }
        run_one(buf, n);
    }
}

static const char real_file[] =
    "# written by unmask: the ranges nginx's module reads at run time\n"
    "66.249.64.0/27\n66.249.64.32/27\n66.249.64.0/19\n"
    "2001:4860:4801:10::/64\n2001:4860:4801:12::/64\n"
    "203.0.113.7\n198.51.100.0/24\n2600:1901:0:c95d::/64\n::1\n0.0.0.0/0\n";

static void fuzz_truncated(void) {
    for (size_t n = 0; n <= sizeof(real_file) - 1; n++) {
        run_one(real_file, n);
    }
}

static void fuzz_mutated(size_t iters) {
    char buf[sizeof(real_file) + 64];
    for (size_t i = 0; i < iters; i++) {
        size_t n = sizeof(real_file) - 1;
        memcpy(buf, real_file, n);
        unsigned int k = 1 + rng_next() % 8;
        for (unsigned int j = 0; j < k; j++) {
            buf[rng_next() % n] = (rng_next() & 3) == 0 ? (char) rng_next()
                                                        : alphabet[rng_next() % (sizeof(alphabet) - 1)];
        }
        if ((rng_next() & 3) == 0) n = rng_next() % (n + 1);
        run_one(buf, n);
    }
}

int main(int argc, char **argv) {
    size_t iters = (argc > 1) ? (size_t) strtoul(argv[1], NULL, 10) : 100000;
    rng_state ^= (uint32_t) time(NULL);
    arena = malloc(ARENA);
    assert(arena != NULL);
    run_one(NULL, 0);
    fuzz_truncated();
    fuzz_random(iters);
    fuzz_mutated(iters);
    free(arena);
    printf("bypass_list_fuzz: %zu random + %zu mutated iters + truncation sweep, every input at the end of a heap block, no crash, invariants held\n",
           iters, iters);
    return 0;
}
