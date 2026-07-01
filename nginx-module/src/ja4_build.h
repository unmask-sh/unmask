/*
 * ja4_build.h — pure JA4 string assembler.
 *
 * Takes a parsed ClientHello (ja4_parsed_t from ja4_parser.h) and builds the
 * JA4 fingerprint string "t13d1517h2_<12hex>_<12hex>".  Split out of
 * ngx_http_unmask_module.c so the assembly step — which runs on every TLS
 * handshake, on attacker-influenced data — can be unit-tested and ASan/UBSan
 * fuzzed in isolation, with no nginx / OpenSSL-SSL coupling.  The only
 * external dependency is OpenSSL's one-shot SHA256() (libcrypto), used for
 * the JA4 b/c hash sections.
 *
 * Spec: RFC 5246 (TLS 1.2) / RFC 8446 (TLS 1.3) +
 * https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md.
 * The BSL-licensed FoxIO reference implementation is not consulted
 * (= clean-room).
 */

#ifndef NGX_JA4_BUILD_H_INCLUDED_
#define NGX_JA4_BUILD_H_INCLUDED_

#include <stddef.h>

#include "ja4_parser.h"

/* Longest JA4 string is a(10) + '_' + b(12) + '_' + c(12) + NUL = 38 bytes.
 * 64 matches the buffer the nginx module hands in (NGX_JA4_MAX). */
#define JA4_STRING_MAX 64

/*
 * Build the JA4 string from a parsed ClientHello.
 *
 * Writes a NUL-terminated JA4 fingerprint into `out` (capacity `outlen`,
 * which must be >= 1).  Returns the number of bytes written excluding the
 * NUL, clamped so the result always fits (out[ret] == '\0').
 *
 * Pure: depends only on libc (qsort / snprintf / memcpy) + OpenSSL SHA256().
 * Never reads past the bounds of `parsed`; the parser caps ncipher / nexts /
 * nsig_algs at JA4_MAX_* so the internal scratch buffers are sufficient.
 */
size_t ja4_build_string(const ja4_parsed_t *parsed, char *out, size_t outlen);

#endif /* NGX_JA4_BUILD_H_INCLUDED_ */
