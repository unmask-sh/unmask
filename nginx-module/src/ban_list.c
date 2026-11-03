/*
 * ban_list.c — see ban_list.h.  The line rules are the ones the module
 * applied inline before the parser moved here: trim, skip blank and '#'
 * lines, cut at the second '|' for the key, read the action after the
 * third, and treat an ip-only line with a '/' in its address as a prefix
 * row.  A line that reads as a row by these rules is a row; the file's
 * writer (the daemon) and this reader agree on nothing else.
 */
#include "ban_list.h"

#include <stdlib.h>   /* qsort */
#include <string.h>   /* memchr, strcmp */

/* One line, classified.  start/end bound the trimmed text; p1 and p2 are
 * the first and second '|' (NULL when absent); act is the action text, or
 * NULL for the default. */
typedef struct {
    char       *start;
    char       *end;
    char       *p1;
    char       *p2;
    const char *act;
    int         is_prefix;
} unmask_ban_line_t;

static const char unmask_ban_default_action[] = "deny";

/* Classify the line at [p, nl).  Returns 0 for a blank or comment line. */
static int
unmask_ban_classify(char *p, char *nl, unmask_ban_line_t *ln)
{
    char *end = nl;
    char *start = p;
    char *p3;

    while (end > start
           && (end[-1] == '\r' || end[-1] == ' ' || end[-1] == '\t'))
    {
        end--;
    }
    while (start < end && (*start == ' ' || *start == '\t')) {
        start++;
    }
    if (start == end || *start == '#') {
        return 0;
    }

    ln->start = start;
    ln->end = end;
    ln->act = NULL;
    ln->p1 = memchr(start, '|', (size_t)(end - start));
    ln->p2 = NULL;
    if (ln->p1 != NULL) {
        ln->p2 = memchr(ln->p1 + 1, '|', (size_t)(end - (ln->p1 + 1)));
        if (ln->p2 != NULL) {
            p3 = memchr(ln->p2 + 1, '|', (size_t)(end - (ln->p2 + 1)));
            if (p3 != NULL && p3 + 1 < end) {
                ln->act = p3 + 1;
            }
        }
    }
    /* An ip-only line whose address carries a prefix length: the JA4 field
     * is empty (the line ends at the first '|', or the second follows it at
     * once) and a '/' sits in the address. */
    ln->is_prefix = ln->p1 != NULL
        && memchr(start, '/', (size_t)(ln->p1 - start)) != NULL
        && (ln->p2 == NULL ? (ln->p1 + 1 == end) : (ln->p2 == ln->p1 + 1));
    return 1;
}

void
unmask_ban_count(const char *buf, size_t len, size_t *nrows, size_t *nprefixes)
{
    const char *p;
    const char *end;
    unmask_ban_line_t ln;

    *nrows = 0;
    *nprefixes = 0;
    if (buf == NULL) {
        return;
    }
    /* After the guard: an offset on a null pointer is undefined behaviour,
     * which UBSan reports even for an offset of zero. */
    p = buf;
    end = buf + len;
    while (p < end) {
        const char *nl = memchr(p, '\n', (size_t)(end - p));
        const char *stop = (nl != NULL) ? nl : end;
        /* The classifier takes a writable line but writes nothing. */
        if (unmask_ban_classify((char *) p, (char *) stop, &ln)) {
            if (ln.is_prefix) {
                (*nprefixes)++;
            } else {
                (*nrows)++;
            }
        }
        if (nl == NULL) {
            break;
        }
        p = nl + 1;
    }
}

static int
unmask_ban_row_cmp(const void *a, const void *b)
{
    return strcmp(((const unmask_ban_row_t *) a)->key,
                  ((const unmask_ban_row_t *) b)->key);
}

int
unmask_ban_parse(char *buf, size_t len,
                 unmask_ban_row_t *rows, size_t rows_cap, size_t *nrows,
                 unmask_ban_prefix_t *prefixes, size_t prefixes_cap,
                 size_t *nprefixes)
{
    char *p;
    char *end;
    size_t nr = 0, np = 0;
    int sorted = 1;
    unmask_ban_line_t ln;

    *nrows = 0;
    *nprefixes = 0;
    if (buf == NULL) {
        return 0;
    }
    /* After the guard: an offset on a null pointer is undefined behaviour,
     * which UBSan reports even for an offset of zero.  An empty buffer still
     * gets its terminator: callers hand over len + 1 bytes and read it. */
    p = buf;
    end = buf + len;
    buf[len] = '\0';

    while (p < end) {
        char *nl = memchr(p, '\n', (size_t)(end - p));
        char *stop = (nl != NULL) ? nl : end;

        if (unmask_ban_classify(p, stop, &ln)) {
            const char *act = (ln.act != NULL) ? ln.act
                                               : unmask_ban_default_action;
            /* Terminate the line, then the key at the second '|' so the
             * "<ip>|<ja4>" text stands alone for strcmp. */
            *ln.end = '\0';
            if (ln.p2 != NULL) {
                *ln.p2 = '\0';
            }
            if (ln.is_prefix) {
                if (np >= prefixes_cap) {
                    return -1;
                }
                prefixes[np].prefix = ln.start;
                prefixes[np].prefix_len = (size_t)(ln.p1 - ln.start);
                prefixes[np].action = act;
                np++;
            } else {
                if (nr >= rows_cap) {
                    return -1;
                }
                rows[nr].key = ln.start;
                rows[nr].action = act;
                if (nr > 0 && sorted
                    && strcmp(rows[nr - 1].key, rows[nr].key) > 0)
                {
                    sorted = 0;
                }
                nr++;
            }
        }
        if (nl == NULL) {
            break;
        }
        p = nl + 1;
    }

    /* The daemon writes the file sorted; a hand-written or an older file is
     * not, and the lookup is a binary search. */
    if (nr > 1 && !sorted) {
        qsort(rows, nr, sizeof(*rows), unmask_ban_row_cmp);
    }
    *nrows = nr;
    *nprefixes = np;
    return 0;
}

const char *
unmask_ban_lookup(const unmask_ban_row_t *rows, size_t nrows, const char *key)
{
    size_t lo = 0, hi = nrows;

    if (rows == NULL || key == NULL) {
        return NULL;
    }
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        int c = strcmp(rows[mid].key, key);
        if (c == 0) {
            return rows[mid].action;
        }
        if (c < 0) {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return NULL;
}
