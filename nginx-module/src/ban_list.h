/*
 * ban_list.h — pure-C parser and lookup for the ban file.
 *
 * The daemon writes the list ("<ip>|<ja4>|<source>|<action>" per line, sorted
 * by the "<ip>|<ja4>" prefix) and every nginx worker reads it into memory
 * when it changes.  The file is the daemon's, but the parser still treats it
 * as untrusted input: an operator hand-edits it, an older daemon wrote the
 * two-field form, a prefix row carries "/len".  So the decode lives here,
 * free of nginx types, where ban_list_test.c pins its behaviour and
 * ban_list_fuzz.c runs it under ASan/UBSan.  ngx_http_unmask_module.c reads
 * the file, sizes the arrays from unmask_ban_count(), calls unmask_ban_parse()
 * and turns the prefix rows into nginx CIDRs (ngx_ptocidr) itself.
 *
 * Contract: nothing here reads outside [buf, buf + len]; the parse writes
 * only NULs, in place, and buf[len] (which the caller provides).
 */
#ifndef UNMASK_BAN_LIST_H
#define UNMASK_BAN_LIST_H

#include <stddef.h>

/* An exact row: key is "<ip>|<ja4>" (NUL-terminated in place; a two-field
 * line keeps its whole text as the key), action is the fourth field, or
 * "deny" when the line has fewer than four (the safe default an unmigrated
 * file degrades to). */
typedef struct {
    const char *key;
    const char *action;
} unmask_ban_row_t;

/* A prefix row: an ip-only line whose address carries a /len
 * ("2001:db8:1:2::/64|", "203.0.113.0/24||manual|deny").  Kept apart from
 * the exact keys so the caller matches it by mask after them, and a more
 * specific exact line wins.  prefix is "<addr>/<len>", not NUL-terminated. */
typedef struct {
    const char *prefix;
    size_t      prefix_len;
    const char *action;
} unmask_ban_prefix_t;

/* Count the rows a buffer holds, by the same rules unmask_ban_parse() applies,
 * so the caller can size its arrays exactly.  Blank and '#' lines count for
 * nothing. */
void unmask_ban_count(const char *buf, size_t len,
                      size_t *nrows, size_t *nprefixes);

/* Parse the list in place.  buf must hold len + 1 bytes; the parse cuts
 * every row at its field boundaries with NULs and sets buf[len] = 0.  Exact
 * rows go to rows[] (at most rows_cap), sorted ascending by key for
 * unmask_ban_lookup(); prefix rows to prefixes[] (at most prefixes_cap), in
 * file order.  Returns 0, or -1 when an array is too small for the rows the
 * buffer holds (which unmask_ban_count() prevents). */
int unmask_ban_parse(char *buf, size_t len,
                     unmask_ban_row_t *rows, size_t rows_cap, size_t *nrows,
                     unmask_ban_prefix_t *prefixes, size_t prefixes_cap,
                     size_t *nprefixes);

/* Binary search for key in rows[] (sorted as unmask_ban_parse() leaves it).
 * Returns the row's action, or NULL when the key is not listed. */
const char *unmask_ban_lookup(const unmask_ban_row_t *rows, size_t nrows,
                              const char *key);

#endif /* UNMASK_BAN_LIST_H */
