/*
 * bv_parser.h — pure-C structural parser for the `_bv` pass-cookie value.
 *
 * The `_bv` cookie is fully client-controlled, so its structural decode (the
 * dot-splitting + per-segment length bounds, before any HMAC / PoW check) is
 * an untrusted-input parser.  It lives here, free of nginx / OpenSSL types, so
 * it can be exercised by bv_parser_fuzz.c under ASan exactly as the JA4
 * ClientHello parser is.  ngx_http_unmask_module.c calls these; the keyed
 * HMAC / SHA-256-hashcash verification (which needs the secret, the
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
    BV_FMT_CAPTCHA,   /* 3 segments: day.sig.kind   (sig = 16 hex of an HMAC)      */
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

/*
 * bv_cookie_next: the next `name=value` pair in a Cookie header whose name is
 * `name`, scanning from *off (0 to start; advanced past the pair on return).
 * Returns 1 with *val_off / *val_len set (into hdr) when one is found, 0 at
 * the end.  The caller iterates because a browser can send several `_bv`
 * cookies at once (a stale one at another path beside the fresh one), and
 * nginx's own header parser returns only the first.
 *
 * Pairs are split on ';'.  Spaces and tabs around the name and the value are
 * skipped, as nginx's parser skips them (`_bv = v`), and a value wrapped in
 * double quotes (RFC 6265's cookie-value form, which a proxy or an SDK may
 * produce) is returned without the quotes.  Names are compared
 * case-sensitively; a bare name without '=' is skipped.  Never reads outside
 * [hdr, hdr + len).
 */
int bv_cookie_next(const unsigned char *hdr, size_t len,
                   const char *name, size_t name_len,
                   size_t *off, size_t *val_off, size_t *val_len);

/*
 * bv_base36: parse a base-36 number ([0-9a-zA-Z], 1 to 13 characters).
 * Returns -1 for an empty or longer input, an invalid character, or a value
 * past INT64_MAX (13 characters is the longest a non-negative int64 needs:
 * log36(2^63) ~ 12.27).  The proof-of-work nonce is carried this way.
 */
int64_t bv_base36(const unsigned char *s, size_t n);

/*
 * bv_leading_zero_bits: the number of consecutive zero bits from the most
 * significant bit of b[0] onward.  Matches leadingZeroBits() in challenge.js
 * and in the Go cookies package; the three MUST agree, since this is what a
 * proof-of-work is measured by.
 */
int bv_leading_zero_bits(const unsigned char *b, size_t n);

#endif /* UNMASK_BV_PARSER_H */
