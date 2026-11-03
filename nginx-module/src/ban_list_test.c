/*
 * ban_list_test.c — known-answer tests for the ban file parser and lookup.
 *
 * Pins the line rules the module relied on while the parser lived inline:
 * four fields, the two-field legacy form, comments and blank lines, CRLF and
 * padding, the prefix-row shape, an unsorted file, and the three key shapes
 * the module looks up (ip|ja4, |ja4, ip|).
 *
 * Build / run:
 *   gcc -std=gnu99 -Wall -Wextra ban_list.c ban_list_test.c -o ban_list_test
 *   ./ban_list_test
 */

#include "ban_list.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass, g_fail;

#define CHECK(cond, msg) do {                                             \
    if (cond) { g_pass++; }                                               \
    else { g_fail++; fprintf(stderr, "FAIL: %s:%d  %s\n",                 \
                             __FILE__, __LINE__, (msg)); }                \
} while (0)

#define CHECK_STR(got, want, msg) do {                                    \
    const char *g_ = (got), *w_ = (want);                                 \
    if (g_ != NULL && strcmp(g_, w_) == 0) { g_pass++; }                  \
    else { g_fail++; fprintf(stderr,                                      \
        "FAIL: %s:%d  %s\n  got:  %s\n  want: %s\n",                       \
        __FILE__, __LINE__, (msg), g_ ? g_ : "(null)", w_); }             \
} while (0)

/* Parse a string literal through the public API, sizing the arrays from
 * unmask_ban_count() exactly as the module does.  The copy is freed by the
 * caller; rows point into it. */
typedef struct {
    char                *buf;
    unmask_ban_row_t    *rows;
    size_t               nrows;
    unmask_ban_prefix_t *prefixes;
    size_t               nprefixes;
    int                  rc;
} parsed_t;

static void parse(const char *text, parsed_t *out) {
    size_t len = strlen(text);
    size_t nr, np;
    out->buf = malloc(len + 1);
    memcpy(out->buf, text, len + 1);
    unmask_ban_count(out->buf, len, &nr, &np);
    out->rows = calloc(nr + 1, sizeof(*out->rows));
    out->prefixes = calloc(np + 1, sizeof(*out->prefixes));
    out->rc = unmask_ban_parse(out->buf, len, out->rows, nr, &out->nrows,
                               out->prefixes, np, &out->nprefixes);
}

static void done(parsed_t *p) {
    free(p->buf);
    free(p->rows);
    free(p->prefixes);
}

int main(void) {
    parsed_t p;

    /* T1: the daemon's four-field form, sorted, with the three key shapes. */
    parse("# honeypot bans\n"
          "|t13d1517h2_8daaf6152771_b0da82dd1658|manual|captcha_only\n"
          "192.0.2.10|t13d3515h2_8daaf6152771_e5627efa2ab1|honeypot|pow_then_captcha\n"
          "192.0.2.11||manual|deny\n"
          "\n"
          "2001:db8::1|t13d1517h2_yyy_zzz|community|deny\n", &p);
    CHECK(p.rc == 0, "T1 parses");
    CHECK(p.nrows == 4 && p.nprefixes == 0, "T1 four exact rows, no prefix");
    CHECK_STR(unmask_ban_lookup(p.rows, p.nrows,
              "192.0.2.10|t13d3515h2_8daaf6152771_e5627efa2ab1"),
              "pow_then_captcha", "T1 ip|ja4 key");
    CHECK_STR(unmask_ban_lookup(p.rows, p.nrows,
              "|t13d1517h2_8daaf6152771_b0da82dd1658"),
              "captcha_only", "T1 |ja4 key (scope ja4_only)");
    CHECK_STR(unmask_ban_lookup(p.rows, p.nrows, "192.0.2.11|"),
              "deny", "T1 ip| key (scope ip_only)");
    CHECK_STR(unmask_ban_lookup(p.rows, p.nrows, "2001:db8::1|t13d1517h2_yyy_zzz"),
              "deny", "T1 last row");
    CHECK(unmask_ban_lookup(p.rows, p.nrows, "192.0.2.10|") == NULL,
          "T1 an ip| key does not match an ip|ja4 row");
    CHECK(unmask_ban_lookup(p.rows, p.nrows, "192.0.2.12|") == NULL,
          "T1 unknown key");
    CHECK(unmask_ban_lookup(p.rows, p.nrows, "") == NULL, "T1 empty key");
    done(&p);

    /* T2: two-field legacy lines read as action "deny"; a three-field line
     * (no action) too; a four-field line with an empty action too. */
    parse("192.0.2.1|t13d_a_b\n"
          "192.0.2.2|t13d_a_b|manual\n"
          "192.0.2.3|t13d_a_b|manual|\n"
          "192.0.2.4|t13d_a_b|manual|pow_only\n", &p);
    CHECK(p.rc == 0 && p.nrows == 4, "T2 four rows");
    CHECK_STR(unmask_ban_lookup(p.rows, p.nrows, "192.0.2.1|t13d_a_b"), "deny",
              "T2 two fields -> deny");
    CHECK_STR(unmask_ban_lookup(p.rows, p.nrows, "192.0.2.2|t13d_a_b"), "deny",
              "T2 three fields -> deny");
    CHECK_STR(unmask_ban_lookup(p.rows, p.nrows, "192.0.2.3|t13d_a_b"), "deny",
              "T2 empty action -> deny");
    CHECK_STR(unmask_ban_lookup(p.rows, p.nrows, "192.0.2.4|t13d_a_b"), "pow_only",
              "T2 fourth field is the action");
    done(&p);

    /* T3: CRLF, padding, a comment after rows, no trailing newline. */
    parse("  192.0.2.5|t13d_a_b|manual|deny  \r\n"
          "\t# comment\r\n"
          "192.0.2.6|t13d_a_b|manual|captcha_only", &p);
    CHECK(p.rc == 0 && p.nrows == 2, "T3 two rows");
    CHECK_STR(unmask_ban_lookup(p.rows, p.nrows, "192.0.2.5|t13d_a_b"), "deny",
              "T3 padded CRLF line");
    CHECK_STR(unmask_ban_lookup(p.rows, p.nrows, "192.0.2.6|t13d_a_b"), "captcha_only",
              "T3 last line without a newline");
    done(&p);

    /* T4: an unsorted file is sorted for the binary search; a line without
     * any '|' is a key of its own. */
    parse("c|x|s|deny\n"
          "a|x|s|pow_only\n"
          "b|x|s|captcha_only\n"
          "bare\n", &p);
    CHECK(p.rc == 0 && p.nrows == 4, "T4 four rows");
    CHECK_STR(p.rows[0].key, "a|x", "T4 sorted: first");
    /* '|' sorts after every letter, so "bare" lands before "b|x". */
    CHECK_STR(p.rows[1].key, "bare", "T4 sorted: second");
    CHECK_STR(p.rows[2].key, "b|x", "T4 sorted: third");
    CHECK_STR(p.rows[3].key, "c|x", "T4 sorted: fourth");
    CHECK_STR(unmask_ban_lookup(p.rows, p.nrows, "a|x"), "pow_only", "T4 lookup a");
    CHECK_STR(unmask_ban_lookup(p.rows, p.nrows, "b|x"), "captcha_only", "T4 lookup b");
    CHECK_STR(unmask_ban_lookup(p.rows, p.nrows, "c|x"), "deny", "T4 lookup c");
    CHECK_STR(unmask_ban_lookup(p.rows, p.nrows, "bare"), "deny", "T4 lookup bare");
    done(&p);

    /* T5: prefix rows -- ip-only with "/len" -- are kept apart, in file
     * order, with their action; a '/' in a line that also has a JA4 is an
     * exact row (nothing could match it, but it is not a prefix). */
    parse("2001:db8:1:2::/64|\n"
          "203.0.113.0/24||manual|captcha_only\n"
          "198.51.100.7|t13d_a_b|manual|deny\n"
          "10.0.0.0/8|t13d_a_b|manual|deny\n", &p);
    CHECK(p.rc == 0, "T5 parses");
    CHECK(p.nprefixes == 2, "T5 two prefix rows");
    CHECK(p.nrows == 2, "T5 two exact rows");
    CHECK(p.nprefixes == 2 && p.prefixes[0].prefix_len == 17
          && strncmp(p.prefixes[0].prefix, "2001:db8:1:2::/64", 17) == 0,
          "T5 first prefix text");
    CHECK(p.nprefixes == 2 && strcmp(p.prefixes[0].action, "deny") == 0,
          "T5 two-field prefix row -> deny");
    CHECK(p.nprefixes == 2 && p.prefixes[1].prefix_len == 14
          && strncmp(p.prefixes[1].prefix, "203.0.113.0/24", 14) == 0
          && strcmp(p.prefixes[1].action, "captcha_only") == 0,
          "T5 second prefix text and action");
    CHECK_STR(unmask_ban_lookup(p.rows, p.nrows, "10.0.0.0/8|t13d_a_b"), "deny",
              "T5 a slash next to a JA4 is an exact row");
    done(&p);

    /* T6: empty input, comments only, and a buffer of separators. */
    parse("", &p);
    CHECK(p.rc == 0 && p.nrows == 0 && p.nprefixes == 0, "T6 empty");
    CHECK(unmask_ban_lookup(p.rows, p.nrows, "x") == NULL, "T6 lookup on empty");
    done(&p);
    parse("# a\n#b\n\n   \n\r\n", &p);
    CHECK(p.rc == 0 && p.nrows == 0 && p.nprefixes == 0, "T6 comments only");
    done(&p);
    parse("|\n||\n|||\n||||\n", &p);
    CHECK(p.rc == 0 && p.nrows == 4 && p.nprefixes == 0, "T6 bare separators are rows");
    CHECK_STR(unmask_ban_lookup(p.rows, p.nrows, "|"), "deny", "T6 '|' key");
    done(&p);

    /* T7: the count and the parse agree, so exact-sized arrays never
     * overflow; a short array is refused rather than overrun. */
    {
        char buf[] = "a|1|s|deny\nb|2|s|deny\n10.0.0.0/8|\n";
        unmask_ban_row_t rows[1];
        unmask_ban_prefix_t prefixes[1];
        size_t nr, np;
        unmask_ban_count(buf, strlen(buf), &nr, &np);
        CHECK(nr == 2 && np == 1, "T7 count");
        CHECK(unmask_ban_parse(buf, strlen(buf), rows, 1, &nr, prefixes, 1, &np) == -1,
              "T7 a short rows array is refused");
    }

    /* T8: NULL buffer. */
    {
        size_t nr = 9, np = 9;
        unmask_ban_count(NULL, 0, &nr, &np);
        CHECK(nr == 0 && np == 0, "T8 count on NULL");
        CHECK(unmask_ban_parse(NULL, 0, NULL, 0, &nr, NULL, 0, &np) == 0
              && nr == 0 && np == 0, "T8 parse on NULL");
        CHECK(unmask_ban_lookup(NULL, 0, "x") == NULL, "T8 lookup on NULL");
    }

    printf("ban_list_test: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
