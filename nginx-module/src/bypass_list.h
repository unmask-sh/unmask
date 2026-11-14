/*
 * bypass_list.h — pure-C parser and lookup for the run-time bypass list.
 *
 * The daemon writes bypass-ip.txt beside the ban file: the addresses and
 * ranges that skip the challenge -- crawlers' published ranges, the
 * operator's rows, the statistics exclusions -- one per line.  Every nginx
 * worker reads it into memory when it changes and answers
 * $unmask_bypass_ip_rt from it, so a range the daemon adds or drops applies
 * without a reload.  The file is the daemon's, but the parser still treats
 * it as untrusted input: the decode lives here, free of nginx types, where
 * bypass_list_test.c pins its behaviour and bypass_list_fuzz.c runs it under
 * ASan/UBSan.
 *
 * The ranges are kept as sorted, disjoint [lo, hi] intervals per family, so
 * a lookup is a binary search: the published crawler ranges run to
 * thousands of lines, past what a scan per request should cost.
 *
 * Contract: nothing here reads outside [buf, buf + len], and buf is not
 * written to.
 */
#ifndef UNMASK_BYPASS_LIST_H
#define UNMASK_BYPASS_LIST_H

#include <stddef.h>
#include <stdint.h>

/* An IPv4 interval, in host byte order, lo <= hi. */
typedef struct {
    uint32_t lo;
    uint32_t hi;
} unmask_bypass_v4_t;

/* An IPv6 interval, in network byte order (memcmp orders them), lo <= hi. */
typedef struct {
    unsigned char lo[16];
    unsigned char hi[16];
} unmask_bypass_v6_t;

/* An upper bound on the entries each family needs: the lines that are not
 * blank and not a '#' comment, counted for IPv6 when they hold a ':'. */
void unmask_bypass_count(const char *buf, size_t len, size_t *n4, size_t *n6);

/* Parse every line -- an address, or an address with "/len" -- into v4[] /
 * v6[] (at most cap4 / cap6 entries), then sort each array and merge the
 * intervals that overlap.  *n4 / *n6 get the counts after the merge.  Blank
 * lines, '#' comments and anything after a '#' are ignored.  Returns how many
 * lines held something that is not a range (skipped). */
size_t unmask_bypass_parse(const char *buf, size_t len,
                           unmask_bypass_v4_t *v4, size_t cap4, size_t *n4,
                           unmask_bypass_v6_t *v6, size_t cap6, size_t *n6);

/* 1 when addr lies in one of the n intervals (as unmask_bypass_parse leaves
 * them: sorted, disjoint), else 0.  addr is in host byte order for IPv4 and
 * in network byte order for IPv6. */
int unmask_bypass_has_v4(const unmask_bypass_v4_t *v4, size_t n, uint32_t addr);
int unmask_bypass_has_v6(const unmask_bypass_v6_t *v6, size_t n,
                         const unsigned char addr[16]);

#endif /* UNMASK_BYPASS_LIST_H */
