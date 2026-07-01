/*
 * ja4_build.c — pure JA4 string assembler.  See ja4_build.h.
 *
 * Extracted from ngx_http_unmask_module.c's ngx_ja4_compute_and_store (the
 * JA4_a / JA4_b / JA4_c assembly), with the nginx wrappers swapped for libc
 * equivalents (ngx_snprintf -> snprintf, ngx_memcpy -> memcpy).  The byte
 * output is identical for any input the parser can produce; the module now
 * calls ja4_build_string() and keeps only the SSL ex_data storage.
 *
 * Defensive note: the parser caps ncipher / nexts / nsig_algs at JA4_MAX_*,
 * but because this is now a standalone, fuzzed entry point the counts are
 * re-clamped here too, so a hand-built or corrupt ja4_parsed_t can never push
 * a read or write past the scratch buffers.  The clamp is a no-op for every
 * struct the parser yields, so it does not change real output.
 */

#include "ja4_build.h"

#include <stdio.h>   /* snprintf */
#include <stdlib.h>  /* qsort */
#include <string.h>  /* memcpy */

#include <openssl/sha.h>

/* hex4: write the 4 lowercase-hex digits of a uint16 into out[0..3]. */
static void ja4_hex4(char *out, unsigned int v) {
    static const char hex[] = "0123456789abcdef";
    out[0] = hex[(v >> 12) & 0xF];
    out[1] = hex[(v >> 8) & 0xF];
    out[2] = hex[(v >> 4) & 0xF];
    out[3] = hex[v & 0xF];
}

/* qsort comparator: uint16 (stored in unsigned int) ascending. */
static int ja4_u16_cmp(const void *a, const void *b) {
    unsigned int x = *(const unsigned int *)a;
    unsigned int y = *(const unsigned int *)b;
    return (x < y) ? -1 : (x > y) ? 1 : 0;
}

/* sha12: first 6 bytes of SHA-256(in[:inlen]) as 12 lowercase-hex chars
 * (NOT NUL-terminated; the caller appends '\0'). */
static void ja4_sha12(const char *in, size_t inlen, char *out12) {
    static const char hex[] = "0123456789abcdef";
    unsigned char h[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)in, inlen, h);
    /* JA4 spec: take the first 6 bytes = 12 hex chars. */
    for (int i = 0; i < 6; i++) {
        out12[i * 2]     = hex[(h[i] >> 4) & 0xF];
        out12[i * 2 + 1] = hex[h[i] & 0xF];
    }
}

/* clampi: bound n into [0, hi]. */
static int ja4_clampi(int n, int hi) {
    if (n < 0)  return 0;
    if (n > hi) return hi;
    return n;
}

size_t ja4_build_string(const ja4_parsed_t *parsed, char *out, size_t outlen) {
    char tlscode[3];
    char ja4_a[16];
    char ja4_b[13];
    char ja4_c[13];
    char buf[2048];
    char *bp;
    int  i, nexts_c;
    int  tlsver, cipher_count_disp, ext_count_disp, n;
    int  ncipher, nexts, nsig_algs;
    unsigned int sorted[JA4_MAX_CIPHERS];
    unsigned int sorted_e[JA4_MAX_EXTENSIONS];

    if (outlen == 0) return 0;

    /* Defensive re-clamp (a no-op for parser output; guards hand-built /
     * corrupt structs against scratch-buffer overrun). */
    ncipher   = ja4_clampi(parsed->ncipher,   JA4_MAX_CIPHERS);
    nexts     = ja4_clampi(parsed->nexts,     JA4_MAX_EXTENSIONS);
    nsig_algs = ja4_clampi(parsed->nsig_algs, JA4_MAX_SIG_ALGS);

    /* JA4 spec: prefer the supported_versions value (= the maximum
     * presented); fall back to legacy_version if the extension is absent. */
    tlsver = (parsed->supported_versions_max != 0)
           ? (int)parsed->supported_versions_max
           : (int)parsed->legacy_version;
    switch (tlsver) {
    case 0x0304: memcpy(tlscode, "13", 2); break; /* TLS 1.3 */
    case 0x0303: memcpy(tlscode, "12", 2); break; /* TLS 1.2 */
    case 0x0302: memcpy(tlscode, "11", 2); break;
    case 0x0301: memcpy(tlscode, "10", 2); break;
    case 0x0300: memcpy(tlscode, "s3", 2); break;
    case 0xfeff: memcpy(tlscode, "d1", 2); break;
    case 0xfefd: memcpy(tlscode, "d2", 2); break;
    case 0xfefc: memcpy(tlscode, "d3", 2); break;
    default:     memcpy(tlscode, "00", 2); break;
    }
    tlscode[2] = '\0';

    /* === JA4_a (10 chars) === */
    cipher_count_disp = ncipher > 99 ? 99 : ncipher;
    ext_count_disp    = nexts   > 99 ? 99 : nexts;
    snprintf(ja4_a, sizeof(ja4_a), "t%s%c%02d%02d%c%c",
             tlscode,
             parsed->sni_present_domain ? 'd' : 'i',
             cipher_count_disp,
             ext_count_disp,
             parsed->alpn_first, parsed->alpn_last);

    /* === JA4_b: sorted ciphers in hex, comma-joined -> first 12 hex chars
     * of SHA-256 === */
    bp = buf;
    if (ncipher > 0) {
        memcpy(sorted, parsed->ciphers, (size_t)ncipher * sizeof(unsigned int));
        qsort(sorted, (size_t)ncipher, sizeof(unsigned int), ja4_u16_cmp);
        for (i = 0; i < ncipher; i++) {
            if (i) *bp++ = ',';
            ja4_hex4(bp, sorted[i]);
            bp += 4;
        }
    }
    ja4_sha12(buf, (size_t)(bp - buf), ja4_b);
    ja4_b[12] = '\0';

    /* === JA4_c: sorted extensions (excluding SNI=0, ALPN=16), then "_"
     * + sig_algs (= presentation order) === */
    bp = buf;
    nexts_c = 0;
    for (i = 0; i < nexts; i++) {
        if (parsed->extensions[i] == 0 || parsed->extensions[i] == 16) continue;
        sorted_e[nexts_c++] = parsed->extensions[i];
    }
    qsort(sorted_e, (size_t)nexts_c, sizeof(unsigned int), ja4_u16_cmp);
    for (i = 0; i < nexts_c; i++) {
        if (i) *bp++ = ',';
        ja4_hex4(bp, sorted_e[i]);
        bp += 4;
    }
    if (parsed->has_sig_algs) {
        /* JA4 spec: append "_" + sig_algs only if ext 13 was present in the
         * ClientHello.  The "_" itself is emitted even when sig_algs is empty
         * (= matches the prior implementation). */
        *bp++ = '_';
        for (i = 0; i < nsig_algs; i++) {
            if (i) *bp++ = ',';
            ja4_hex4(bp, parsed->sig_algs[i]);
            bp += 4;
        }
    }
    ja4_sha12(buf, (size_t)(bp - buf), ja4_c);
    ja4_c[12] = '\0';

    /* === Final JA4 === */
    n = snprintf(out, outlen, "%s_%s_%s", ja4_a, ja4_b, ja4_c);
    if (n < 0) {
        out[0] = '\0';
        return 0;
    }
    if ((size_t)n >= outlen) {
        return outlen - 1; /* truncated; snprintf already NUL-terminated out */
    }
    return (size_t)n;
}
