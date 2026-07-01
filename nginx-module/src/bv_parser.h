/*
 * bv_parser.h — pure-C structural parser for the `_bv` pass-cookie value.
 *
 * The `_bv` cookie is fully client-controlled, so its structural decode (the
 * dot-splitting + per-segment length bounds, before any HMAC / PoW check) is
 * an untrusted-input parser.  It lives here, free of nginx / OpenSSL types, so
 * it can be exercised by bv_parser_fuzz.c under ASan exactly as the JA4
 * ClientHello parser is.  ngx_http_unmask_module.c calls these; the keyed
 * HMAC-SHA1 / SHA-256-hashcash verification (which needs the secret, the
 * client IP and the host) stays in the module and consumes the field offsets
 * this parser returns.
 *
 * Contract: bv_parse_entry / bv_atoll MUST NOT read outside [data, data+len)
 * for ANY input, including empty, unterminated, all-dots, or max-length.
 */
#ifndef UNMASK_BV_PARSER_H
#define UNMASK_BV_PARSER_H

#include <stddef.h>
#include <stdint.h>

typedef enum {
    BV_FMT_NONE = 0,
    BV_FMT_CAPTCHA,   /* 3 segments: day.sig.kind   (sig = 16 hex, HMAC-SHA1)        */
    BV_FMT_POW2,      /* 4 segments: day."pow2".target.flags (SHA-256 hashcash)      */
} bv_format_t;

/*
 * Field offsets/lengths into the entry buffer, all guaranteed within [0,len).
 * For CAPTCHA: sig is the 16 hex chars compared against the HMAC; tail is the
 * "kind" segment.  For POW2: sig spells "pow2"; tail is the "target" segment.
 * The trailing "flags" segment of a POW2 cookie is not surfaced (the verifier
 * does not consume it), matching the module's original behaviour.
 */
typedef struct {
    bv_format_t format;
    size_t day_off,  day_len;
    size_t sig_off,  sig_len;
    size_t tail_off, tail_len;
} bv_fields_t;

/*
 * Decode one `_bv` entry's structure.  Returns 1 and fills *out on a
 * structurally valid entry, 0 otherwise (out->format is set to BV_FMT_NONE on
 * the 0 path).  No allocation, no clock, no crypto.
 */
int bv_parse_entry(const unsigned char *data, size_t len, bv_fields_t *out);

/*
 * Parse a decimal day / unix-seconds value.  Returns -1 on an empty string,
 * more than 18 digits (a 19-digit value can overflow int64 on the final *10),
 * or any non-digit byte.
 */
int64_t bv_atoll(const unsigned char *s, size_t n);

/*
 * unmask_bind_ip_token: fold a client IP text into the token used in the _bv
 * HMAC seed.  IPv6 privacy extensions rotate a client's address within its /64,
 * so binding the cookie to the full /128 re-challenges on every rotation;
 * folding IPv6 to its /64 lets all of one client's addresses share a signature.
 *
 *   IPv4 / IPv4-mapped / unparseable -> returns 0 (caller uses the original IP)
 *   pure IPv6                        -> writes the /64 (first 8 bytes) as 16
 *                                       lowercase hex chars to out, returns 16
 *
 * Pure (POSIX inet_pton + hex), so the fuzz / parity harness exercises it.  MUST
 * stay byte-identical to cookies.bindIP() in the Go admin.  out must hold 16.
 */
size_t unmask_bind_ip_token(const char *ip, size_t len, char *out);

#endif /* UNMASK_BV_PARSER_H */
