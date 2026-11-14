/*
 * bypass_list_test.c — unit tests for the run-time bypass list parser.
 *
 *   gcc -std=gnu99 -Wall -Wextra bypass_list.c bypass_list_test.c -o t && ./t
 */
#include "bypass_list.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; fprintf(stderr, "FAIL: %s:%d  %s\n", __FILE__, __LINE__, msg); } \
} while (0)

/* The parsed list of one buffer, sized generously for the tests. */
typedef struct {
    unmask_bypass_v4_t v4[64];
    unmask_bypass_v6_t v6[64];
    size_t             n4, n6, bad;
} list_t;

static void parse(list_t *l, const char *text) {
    l->bad = unmask_bypass_parse(text, strlen(text), l->v4, 64, &l->n4, l->v6, 64, &l->n6);
}

static int has4(const list_t *l, const char *ip) {
    struct in_addr a;
    if (inet_pton(AF_INET, ip, &a) != 1) {
        fprintf(stderr, "bad test address %s\n", ip);
        return -1;
    }
    return unmask_bypass_has_v4(l->v4, l->n4, ntohl(a.s_addr));
}

static int has6(const list_t *l, const char *ip) {
    unsigned char a[16];
    if (inet_pton(AF_INET6, ip, a) != 1) {
        fprintf(stderr, "bad test address %s\n", ip);
        return -1;
    }
    return unmask_bypass_has_v6(l->v6, l->n6, a);
}

static void test_v4_addresses_and_ranges(void) {
    list_t l;
    parse(&l, "192.0.2.10\n198.51.100.0/24\n");
    CHECK(l.bad == 0 && l.n4 == 2 && l.n6 == 0, "two IPv4 entries, nothing skipped");
    CHECK(has4(&l, "192.0.2.10") == 1, "the lone address is in");
    CHECK(has4(&l, "192.0.2.11") == 0, "its neighbour is not");
    CHECK(has4(&l, "198.51.100.0") == 1 && has4(&l, "198.51.100.255") == 1, "both ends of the /24 are in");
    CHECK(has4(&l, "198.51.101.0") == 0 && has4(&l, "198.51.99.255") == 0, "just outside the /24 is not");
}

static void test_unsorted_overlapping_merged(void) {
    list_t l;
    parse(&l, "11.0.0.0/8\n10.1.0.0/16\n10.0.0.0/8\n10.255.255.255\n203.0.113.0/24\n192.0.2.77/24\n");
    CHECK(l.bad == 0, "nothing skipped");
    CHECK(l.n4 == 4, "10/8 swallows its /16 and its last address; 11/8, 192.0.2/24 and 203.0.113/24 stay");
    CHECK(has4(&l, "10.1.2.3") == 1 && has4(&l, "11.5.5.5") == 1, "inside the merged ranges");
    CHECK(has4(&l, "12.0.0.0") == 0 && has4(&l, "9.255.255.255") == 0, "outside them");
    CHECK(has4(&l, "192.0.2.0") == 1 && has4(&l, "192.0.2.255") == 1, "a range written off its boundary is masked to it");
    for (size_t i = 1; i < l.n4; i++) {
        CHECK(l.v4[i - 1].hi < l.v4[i].lo, "sorted and disjoint after the merge");
    }
}

static void test_comments_blanks_crlf(void) {
    list_t l;
    parse(&l, "# written by unmask\n\n   203.0.113.7   # a host\r\n\t2001:db8::1\r\n#203.0.113.9\n");
    CHECK(l.bad == 0 && l.n4 == 1 && l.n6 == 1, "comments, blanks and CR are not entries");
    CHECK(has4(&l, "203.0.113.7") == 1, "the address before a trailing comment counts");
    CHECK(has4(&l, "203.0.113.9") == 0, "a commented-out line does not");
    CHECK(has6(&l, "2001:db8::1") == 1, "a tab-indented IPv6 line counts");
}

static void test_bad_lines_skipped(void) {
    list_t l;
    parse(&l, "not-an-ip\n1.2.3.4/33\n1.2.3/24\n1.2.3.4/\n1.2.3.4/x\n::1/129\n1.2.3.4/0032\n"
              "192.0.2.1 192.0.2.2\n198.51.100.1\n");
    CHECK(l.bad == 8, "every malformed line is skipped and counted");
    CHECK(l.n4 == 1 && has4(&l, "198.51.100.1") == 1, "the good line after them still counts");
}

static void test_v6(void) {
    list_t l;
    parse(&l, "2001:db8::/32\n2600:1901:0:c95d::/64\n::1\n");
    CHECK(l.bad == 0 && l.n6 == 3 && l.n4 == 0, "three IPv6 entries");
    CHECK(has6(&l, "2001:db8:1::5") == 1 && has6(&l, "2001:db9::") == 0, "a /32");
    CHECK(has6(&l, "::1") == 1 && has6(&l, "::2") == 0, "a lone address");
    CHECK(has6(&l, "2600:1901:0:c95d:ffff:ffff:ffff:ffff") == 1, "the last address of a /64");
    CHECK(has6(&l, "2600:1901:0:c95e::") == 0, "the first past it");
    parse(&l, "2001:db8:abcd:12:34::/61\n");
    CHECK(has6(&l, "2001:db8:abcd:10::") == 1 && has6(&l, "2001:db8:abcd:17:ffff::") == 1, "a prefix that ends inside a byte");
    CHECK(has6(&l, "2001:db8:abcd:18::") == 0, "and the first address past it");
}

static void test_edges(void) {
    list_t l;
    parse(&l, "0.0.0.0/0\n");
    CHECK(l.n4 == 1 && has4(&l, "0.0.0.0") == 1 && has4(&l, "255.255.255.255") == 1, "/0 holds every IPv4 address");
    parse(&l, "255.255.255.255\n");
    CHECK(has4(&l, "255.255.255.255") == 1 && has4(&l, "255.255.255.254") == 0, "the top address alone");
    parse(&l, "::/0\n");
    CHECK(has6(&l, "::") == 1 && has6(&l, "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") == 1, "/0 holds every IPv6 address");
    parse(&l, "");
    CHECK(l.n4 == 0 && l.n6 == 0 && l.bad == 0, "an empty file holds nothing");
    CHECK(has4(&l, "192.0.2.1") == 0 && has6(&l, "::1") == 0, "and answers no");
}

static void test_count(void) {
    const char *t = "1.2.3.4\n::1\n# c\n\nbad\n2001:db8::/32 # x\n";
    size_t n4, n6;
    unmask_bypass_count(t, strlen(t), &n4, &n6);
    CHECK(n4 == 2 && n6 == 2, "count: every non-blank line, by the family it looks like");
    unmask_bypass_count(NULL, 0, &n4, &n6);
    CHECK(n4 == 0 && n6 == 0, "count of nothing");
}

static void test_caps_respected(void) {
    unmask_bypass_v4_t v4[2];
    size_t n4, n6;
    const char *t = "192.0.2.1\n192.0.2.3\n192.0.2.5\n::1\n";
    unmask_bypass_parse(t, strlen(t), v4, 2, &n4, NULL, 0, &n6);
    CHECK(n4 == 2 && n6 == 0, "no more entries than the arrays hold");
}

int main(void) {
    test_v4_addresses_and_ranges();
    test_unsorted_overlapping_merged();
    test_comments_blanks_crlf();
    test_bad_lines_skipped();
    test_v6();
    test_edges();
    test_count();
    test_caps_respected();
    printf("bypass_list_test: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
