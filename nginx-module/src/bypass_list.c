/*
 * bypass_list.c — parser and lookup for the run-time bypass list.  See
 * bypass_list.h for the file it reads and the contract.
 */
#include "bypass_list.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

/* The blanks a line may carry around its range (and the \r of a CRLF file). */
static int
is_blank(char c)
{
    return c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f';
}

/* next_line: the range text of the line at *p -- a '#' and what follows cut
 * off, the blanks around it trimmed -- in *s / *n, and *p moved past the
 * line.  Returns 0 for a line with nothing on it. */
static int
next_line(const char **p, const char *end, const char **s, size_t *n)
{
    const char *b = *p, *e, *nl, *hash;

    nl = memchr(b, '\n', (size_t) (end - b));
    e = nl != NULL ? nl : end;
    *p = nl != NULL ? nl + 1 : end;
    hash = memchr(b, '#', (size_t) (e - b));
    if (hash != NULL) {
        e = hash;
    }
    while (b < e && is_blank(*b)) {
        b++;
    }
    while (e > b && is_blank(e[-1])) {
        e--;
    }
    *s = b;
    *n = (size_t) (e - b);
    return *n > 0;
}

void
unmask_bypass_count(const char *buf, size_t len, size_t *n4, size_t *n6)
{
    const char *p = buf, *end = buf + len, *s;
    size_t      n;

    *n4 = 0;
    *n6 = 0;
    if (buf == NULL) {
        return;
    }
    while (p < end) {
        if (!next_line(&p, end, &s, &n)) {
            continue;
        }
        if (memchr(s, ':', n) != NULL) {
            (*n6)++;
        } else {
            (*n4)++;
        }
    }
}

/* parse_range: one range's text into the interval of its family.  Returns 4
 * or 6 for the family it filled, 0 for text that is not a range. */
static int
parse_range(const char *s, size_t n, unmask_bypass_v4_t *r4,
            unmask_bypass_v6_t *r6)
{
    char           tok[64];
    char          *slash;
    long           bits = -1;
    unsigned char  a6[16];
    struct in_addr a4;
    int            i;

    /* The longest range is an IPv6 address written out with a /128. */
    if (n >= sizeof(tok)) {
        return 0;
    }
    memcpy(tok, s, n);
    tok[n] = '\0';

    slash = strchr(tok, '/');
    if (slash != NULL) {
        const char *q = slash + 1;
        if (*q == '\0' || strlen(q) > 3) {
            return 0;
        }
        bits = 0;
        for (; *q != '\0'; q++) {
            if (*q < '0' || *q > '9') {
                return 0;
            }
            bits = bits * 10 + (*q - '0');
        }
        *slash = '\0';
    }

    if (inet_pton(AF_INET, tok, &a4) == 1) {
        uint32_t a, mask;
        if (bits < 0) {
            bits = 32;
        }
        if (bits > 32) {
            return 0;
        }
        a = ntohl(a4.s_addr);
        mask = bits == 0 ? 0 : (uint32_t) 0xffffffffu << (32 - bits);
        r4->lo = a & mask;
        r4->hi = r4->lo | ~mask;
        return 4;
    }

    if (inet_pton(AF_INET6, tok, a6) == 1) {
        if (bits < 0) {
            bits = 128;
        }
        if (bits > 128) {
            return 0;
        }
        for (i = 0; i < 16; i++) {
            /* how many of this byte's bits the prefix covers */
            long          keep = bits - (long) i * 8;
            unsigned char m;
            if (keep >= 8) {
                m = 0xff;
            } else if (keep <= 0) {
                m = 0x00;
            } else {
                m = (unsigned char) (0xff << (8 - keep));
            }
            r6->lo[i] = (unsigned char) (a6[i] & m);
            r6->hi[i] = (unsigned char) (a6[i] | (unsigned char) ~m);
        }
        return 6;
    }

    return 0;
}

static int
cmp_v4(const void *a, const void *b)
{
    uint32_t x = ((const unmask_bypass_v4_t *) a)->lo;
    uint32_t y = ((const unmask_bypass_v4_t *) b)->lo;

    return x < y ? -1 : x > y;
}

static int
cmp_v6(const void *a, const void *b)
{
    return memcmp(((const unmask_bypass_v6_t *) a)->lo,
                  ((const unmask_bypass_v6_t *) b)->lo, 16);
}

/* Sort by the start and fold every interval that overlaps the one kept last
 * into it, which leaves them disjoint -- what the binary search needs. */
static size_t
merge_v4(unmask_bypass_v4_t *v, size_t n)
{
    size_t i, out = 0;

    if (n == 0) {
        return 0;
    }
    qsort(v, n, sizeof(*v), cmp_v4);
    for (i = 1; i < n; i++) {
        if (v[i].lo <= v[out].hi) {
            if (v[i].hi > v[out].hi) {
                v[out].hi = v[i].hi;
            }
        } else {
            v[++out] = v[i];
        }
    }
    return out + 1;
}

static size_t
merge_v6(unmask_bypass_v6_t *v, size_t n)
{
    size_t i, out = 0;

    if (n == 0) {
        return 0;
    }
    qsort(v, n, sizeof(*v), cmp_v6);
    for (i = 1; i < n; i++) {
        if (memcmp(v[i].lo, v[out].hi, 16) <= 0) {
            if (memcmp(v[i].hi, v[out].hi, 16) > 0) {
                memcpy(v[out].hi, v[i].hi, 16);
            }
        } else {
            v[++out] = v[i];
        }
    }
    return out + 1;
}

size_t
unmask_bypass_parse(const char *buf, size_t len,
                    unmask_bypass_v4_t *v4, size_t cap4, size_t *n4,
                    unmask_bypass_v6_t *v6, size_t cap6, size_t *n6)
{
    const char        *p = buf, *end = buf + len, *s;
    size_t             n, bad = 0, k4 = 0, k6 = 0;
    unmask_bypass_v4_t r4;
    unmask_bypass_v6_t r6;

    *n4 = 0;
    *n6 = 0;
    if (buf == NULL) {
        return 0;
    }
    while (p < end) {
        if (!next_line(&p, end, &s, &n)) {
            continue;
        }
        switch (parse_range(s, n, &r4, &r6)) {
        case 4:
            if (k4 < cap4) {
                v4[k4++] = r4;
            }
            break;
        case 6:
            if (k6 < cap6) {
                v6[k6++] = r6;
            }
            break;
        default:
            bad++;
        }
    }
    *n4 = merge_v4(v4, k4);
    *n6 = merge_v6(v6, k6);
    return bad;
}

int
unmask_bypass_has_v4(const unmask_bypass_v4_t *v4, size_t n, uint32_t addr)
{
    /* The first interval that starts past addr lies in [lo, hi). */
    size_t lo = 0, hi = n;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (v4[mid].lo <= addr) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo > 0 && addr <= v4[lo - 1].hi;
}

int
unmask_bypass_has_v6(const unmask_bypass_v6_t *v6, size_t n,
                     const unsigned char addr[16])
{
    size_t lo = 0, hi = n;

    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (memcmp(v6[mid].lo, addr, 16) <= 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return lo > 0 && memcmp(addr, v6[lo - 1].hi, 16) <= 0;
}
