/*
 * bv_parser.c — see bv_parser.h.  Mirrors the structural decode that used to
 * live inline in ngx_unmask_bv_verify_one(), using memchr() in place of
 * ngx_strlchr() so it builds without nginx.
 */
#include "bv_parser.h"

#include <string.h>      /* memchr, memcpy */
#include <arpa/inet.h>   /* inet_pton, AF_INET6 */

int64_t
bv_atoll(const unsigned char *s, size_t n)
{
    /* Cap at 18 digits: a 19-digit decimal can exceed INT64_MAX and overflow
     * the accumulator on the final v*10 (signed overflow = UB).  Legitimate
     * day / unix-second values are <= 10 digits, so 18 leaves ample headroom. */
    if (s == NULL || n == 0 || n > 18) {
        return -1;
    }
    int64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') {
            return -1;
        }
        v = v * 10 + (s[i] - '0');
    }
    return v;
}

int
bv_parse_entry(const unsigned char *data, size_t len, bv_fields_t *out)
{
    out->format = BV_FMT_NONE;

    if (data == NULL || len < 4 || len > 80) {
        return 0;
    }

    const unsigned char *end = data + len;

    /* Split on '.': CAPTCHA = "day.sig.kind" (3 seg); PoW = "day.sig.target.flags" (4 seg). */
    const unsigned char *dot1 = memchr(data, '.', len);
    if (dot1 == NULL) {
        return 0;
    }
    const unsigned char *dot2 = memchr(dot1 + 1, '.', (size_t)(end - (dot1 + 1)));
    if (dot2 == NULL) {
        return 0;
    }
    const unsigned char *dot3 = memchr(dot2 + 1, '.', (size_t)(end - (dot2 + 1)));

    if (dot3 != NULL) {
        /* PoW path (4 seg): only the "pow2" SHA-256 hashcash form is accepted;
         * a 4-segment entry whose parts[1] != "pow2" is rejected (the removed
         * v0.0 djb2 fallback verified an unkeyed checksum = offline mintable). */
        size_t day_n = (size_t)(dot1 - data);
        size_t sig_n = (size_t)(dot2 - (dot1 + 1));
        size_t tgt_n = (size_t)(dot3 - (dot2 + 1));
        if (day_n == 0 || day_n > 10) return 0;
        if (sig_n == 0 || sig_n > 13) return 0;
        if (tgt_n == 0 || tgt_n > 13) return 0;

        if (sig_n == 4
            && (dot1 + 1)[0] == 'p' && (dot1 + 1)[1] == 'o'
            && (dot1 + 1)[2] == 'w' && (dot1 + 1)[3] == '2') {
            out->format   = BV_FMT_POW2;
            out->day_off  = 0;                              out->day_len  = day_n;
            out->sig_off  = (size_t)((dot1 + 1) - data);    out->sig_len  = sig_n;
            out->tail_off = (size_t)((dot2 + 1) - data);    out->tail_len = tgt_n;  /* target */
            return 1;
        }
        return 0;
    }

    /* CAPTCHA path (3 seg): "day.sig.kind", sig = 16 hex of an HMAC. */
    size_t day_len  = (size_t)(dot1 - data);
    size_t sig_len  = (size_t)(dot2 - (dot1 + 1));
    size_t kind_len = (size_t)(end - (dot2 + 1));
    if (day_len == 0 || day_len > 10) return 0;
    if (sig_len != 16) return 0;
    if (kind_len == 0 || kind_len > 32) return 0;

    out->format   = BV_FMT_CAPTCHA;
    out->day_off  = 0;                              out->day_len  = day_len;
    out->sig_off  = (size_t)((dot1 + 1) - data);    out->sig_len  = sig_len;
    out->tail_off = (size_t)((dot2 + 1) - data);    out->tail_len = kind_len;  /* kind */
    return 1;
}

size_t
unmask_bind_ip_token(const char *ip, size_t len, char *out)
{
    /* IPv4 (no colon) and anything implausibly long pass through unchanged, so
     * v4 cookies stay byte-identical and we never overflow the parse buffer. */
    if (ip == NULL || len == 0 || len >= 46) return 0;
    if (memchr(ip, ':', len) == NULL) return 0;

    char buf[46];
    memcpy(buf, ip, len);
    buf[len] = '\0';

    unsigned char a[16];
    if (inet_pton(AF_INET6, buf, a) != 1) return 0;  /* unparseable -> as-is */

    /* IPv4-mapped ::ffff:a.b.c.d carries IPv4 semantics; leave it unchanged so
     * this matches Go's net.IP.To4() != nil branch exactly. */
    size_t i = 0;
    while (i < 10 && a[i] == 0) i++;
    if (i == 10 && a[10] == 0xff && a[11] == 0xff) return 0;

    /* /64 = first 8 bytes as 16 lowercase hex chars (matches Go hex.Encode). */
    static const char H[] = "0123456789abcdef";
    for (i = 0; i < 8; i++) {
        out[i * 2]     = H[(a[i] >> 4) & 0xF];
        out[i * 2 + 1] = H[a[i] & 0xF];
    }
    return 16;
}

int
bv_cookie_next(const unsigned char *hdr, size_t len,
               const char *name, size_t name_len,
               size_t *off, size_t *val_off, size_t *val_len)
{
    if (hdr == NULL || name == NULL || off == NULL) {
        return 0;
    }
    while (*off < len) {
        size_t name_start, name_end, vs, ve;
        int matched;

        /* Separators between pairs: ';' and the whitespace around it. */
        while (*off < len
               && (hdr[*off] == ' ' || hdr[*off] == '\t' || hdr[*off] == ';'))
        {
            (*off)++;
        }
        if (*off >= len) {
            return 0;
        }

        name_start = *off;
        while (*off < len && hdr[*off] != '=' && hdr[*off] != ';') {
            (*off)++;
        }
        name_end = *off;
        while (name_end > name_start
               && (hdr[name_end - 1] == ' ' || hdr[name_end - 1] == '\t'))
        {
            name_end--;
        }
        matched = (name_end - name_start == name_len)
                  && memcmp(hdr + name_start, name, name_len) == 0;

        if (*off < len && hdr[*off] == '=') {
            (*off)++;
            while (*off < len && (hdr[*off] == ' ' || hdr[*off] == '\t')) {
                (*off)++;
            }
            vs = *off;
            while (*off < len && hdr[*off] != ';') {
                (*off)++;
            }
            ve = *off;
            if (matched) {
                while (ve > vs && (hdr[ve - 1] == ' ' || hdr[ve - 1] == '\t')) {
                    ve--;
                }
                if (ve - vs >= 2 && hdr[vs] == '"' && hdr[ve - 1] == '"') {
                    vs++;
                    ve--;
                }
                *val_off = vs;
                *val_len = ve - vs;
                return 1;
            }
        }
        /* A bare name, or another cookie: on to the next ';'. */
    }
    return 0;
}

int64_t
bv_base36(const unsigned char *s, size_t n)
{
    int64_t v = 0;
    size_t i;

    if (s == NULL || n == 0 || n > 13) {
        return -1;
    }
    for (i = 0; i < n; i++) {
        unsigned char c = s[i];
        int d;
        if (c >= '0' && c <= '9')      d = c - '0';
        else if (c >= 'a' && c <= 'z') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'Z') d = c - 'A' + 10;
        else return -1;
        /* overflow guard: pre-check that 36 * v + d <= INT64_MAX. */
        if (v > (INT64_MAX - d) / 36) {
            return -1;
        }
        v = v * 36 + d;
    }
    return v;
}

int
bv_leading_zero_bits(const unsigned char *b, size_t n)
{
    int bits = 0;
    size_t i;

    if (b == NULL) {
        return 0;
    }
    for (i = 0; i < n; i++) {
        unsigned char v = b[i];
        unsigned char mask;
        if (v == 0) {
            bits += 8;
            continue;
        }
        for (mask = 0x80; mask != 0; mask >>= 1) {
            if (v & mask) {
                return bits;
            }
            bits++;
        }
        return bits;
    }
    return bits;
}
