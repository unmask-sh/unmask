/*
 * ja4_parser_test.c — stand-alone unit test for ja4_parser.
 *
 * Goal: pin down the edge-case behavior of ja4_parse_client_hello() with
 * golden vectors.
 *   - GREASE filter (= cipher_suites / extensions / sig_algs / supported_versions)
 *   - SNI presence (= host_name entry detection)
 *   - ALPN first/last char extraction
 *   - supported_versions maximum extraction (= TLS 1.3 mixed with GREASE)
 *   - signature_algorithms ordering preserved
 *   - extensions list ordering preserved
 *   - Reject malformed input
 *
 * Scope: parser layer only. JA4 string construction inside module.c is
 *        out of scope (= production deployment has already verified
 *        byte-level identity against the previous callback).
 *
 * Build + run:
 *   gcc -std=gnu99 -Wall -Wextra \
 *       ja4_parser.c ja4_parser_test.c -o ja4_parser_test
 *   ./ja4_parser_test
 */

#include "ja4_parser.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_pass = 0;
static int g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_pass++; } \
    else { g_fail++; fprintf(stderr, "FAIL: %s:%d  %s\n", __FILE__, __LINE__, msg); } \
} while (0)

/*
 * helper: build a minimal TLS 1.3 ClientHello in a caller-provided buffer.
 * The caller picks the cipher_suites / extensions sets. random is filled
 * with the fixed byte 0xCC. Returns body length (= matches the uint24
 * length in the handshake header).
 */

/* extensions builder: TLV (type + length + body bytes). */
typedef struct {
    unsigned int  type;
    const unsigned char *body;
    size_t        body_len;
} ext_def_t;

/* build_ch: assemble structurally, write into `out`, return total length
 * including header. */
static size_t build_ch(unsigned char *out, size_t cap,
                       unsigned int legacy_ver,
                       const unsigned int *ciphers, size_t ncipher,
                       const ext_def_t *exts, size_t nexts)
{
    unsigned char *p = out;
    unsigned char *body_start;
    size_t body_len;
    size_t i, j;

    /* handshake header placeholder (1 + 3 bytes) */
    *p++ = 1; /* client_hello */
    *p++ = 0; *p++ = 0; *p++ = 0; /* length, filled in later */
    body_start = p;

    /* legacy_version */
    *p++ = (legacy_ver >> 8) & 0xFF;
    *p++ = legacy_ver & 0xFF;

    /* random (32 bytes, fixed pattern) */
    for (i = 0; i < 32; i++) *p++ = 0xCC;

    /* session_id length = 0 */
    *p++ = 0;

    /* cipher_suites */
    *p++ = (unsigned char)((ncipher * 2) >> 8);
    *p++ = (unsigned char)((ncipher * 2) & 0xFF);
    for (i = 0; i < ncipher; i++) {
        *p++ = (ciphers[i] >> 8) & 0xFF;
        *p++ = ciphers[i] & 0xFF;
    }

    /* compression methods: 1 byte = null(0) */
    *p++ = 1;
    *p++ = 0;

    /* extensions */
    {
        unsigned char *ext_block_len_pos = p;
        unsigned char *ext_block_start;
        size_t ext_block_len;
        p += 2; /* placeholder */
        ext_block_start = p;
        for (j = 0; j < nexts; j++) {
            *p++ = (exts[j].type >> 8) & 0xFF;
            *p++ = exts[j].type & 0xFF;
            *p++ = (exts[j].body_len >> 8) & 0xFF;
            *p++ = exts[j].body_len & 0xFF;
            memcpy(p, exts[j].body, exts[j].body_len);
            p += exts[j].body_len;
        }
        ext_block_len = (size_t)(p - ext_block_start);
        ext_block_len_pos[0] = (ext_block_len >> 8) & 0xFF;
        ext_block_len_pos[1] = ext_block_len & 0xFF;
    }

    body_len = (size_t)(p - body_start);
    out[1] = (body_len >> 16) & 0xFF;
    out[2] = (body_len >> 8) & 0xFF;
    out[3] = body_len & 0xFF;

    (void)cap;
    return (size_t)(p - out);
}

/* ====================================================================
 * Test case 1: TLS 1.3 ClientHello, SNI present, ALPN h2, GREASE filtered.
 * ==================================================================== */
static void test_basic_tls13_with_sni_and_alpn(void) {
    unsigned char buf[1024];
    ja4_parsed_t out;
    size_t total;

    /* cipher_suites: include one GREASE (0x0A0A); expect it filtered out
     * and 3 to remain. */
    unsigned int ciphers[] = {0x0A0A /*GREASE*/, 0x1301, 0x1302, 0x1303};

    /* SNI (= ext 0): list_len 2 + name_type 1 + host_len 2 + "example.com"
     * = 16 bytes total body.
     *   server_name_list_len = 14 (= u8 type + u16 len + 11 host bytes)
     *   body: [00 0E | 00 | 00 0B | 'e' 'x' 'a' 'm' 'p' 'l' 'e' '.' 'c' 'o' 'm']
     */
    static const unsigned char sni_body[] = {
        0x00, 0x0E,           /* server_name_list length */
        0x00,                 /* name_type: host_name */
        0x00, 0x0B,           /* host_name length */
        'e','x','a','m','p','l','e','.','c','o','m'
    };

    /* ALPN (= ext 16): list_len 2 + proto_len 1 + "h2" = 5 bytes total
     *   body: [00 03 | 02 | 'h' '2']
     */
    static const unsigned char alpn_body[] = {
        0x00, 0x03,           /* protocol_name_list length */
        0x02,                 /* proto length */
        'h', '2'
    };

    /* signature_algorithms (= ext 13): u16 list_len + GREASE(0x0A0A) +
     * 0x0403 + 0x0804. Include one GREASE and verify it is filtered out.
     *   body: [00 06 | 0A 0A | 04 03 | 08 04]
     */
    static const unsigned char sig_algs_body[] = {
        0x00, 0x06,           /* sig_algs length */
        0x0A, 0x0A,           /* GREASE */
        0x04, 0x03,           /* ecdsa_secp256r1_sha256 */
        0x08, 0x04            /* rsa_pss_rsae_sha256 */
    };

    /* supported_versions (= ext 43): u8 list_len + GREASE + 0x0304 + 0x0303.
     * Expect GREASE filtered and the max to be 0x0304.
     *   body: [06 | 0A 0A | 03 04 | 03 03]
     */
    static const unsigned char sup_ver_body[] = {
        0x06,                 /* sup_ver_list length (bytes) */
        0x0A, 0x0A,           /* GREASE */
        0x03, 0x04,           /* TLS 1.3 */
        0x03, 0x03            /* TLS 1.2 */
    };

    ext_def_t exts[] = {
        {0x0A0A, NULL, 0},                       /* GREASE ext -> expect filtered */
        {0,    sni_body,     sizeof(sni_body)},
        {16,   alpn_body,    sizeof(alpn_body)},
        {13,   sig_algs_body, sizeof(sig_algs_body)},
        {43,   sup_ver_body, sizeof(sup_ver_body)},
    };

    total = build_ch(buf, sizeof(buf), 0x0303, ciphers, 4, exts, 5);
    CHECK(ja4_parse_client_hello(buf, total, &out) == 0, "parse should succeed");

    /* Verify GREASE filtering. */
    CHECK(out.ncipher == 3, "cipher count after GREASE filter");
    CHECK(out.ciphers[0] == 0x1301 && out.ciphers[1] == 0x1302 && out.ciphers[2] == 0x1303,
          "cipher order preserved (presentation order)");

    /* extensions: 4 after GREASE filter (= SNI, ALPN, sig_algs, sup_ver),
     * in presentation order. */
    CHECK(out.nexts == 4, "extension count after GREASE filter");
    CHECK(out.extensions[0] == 0 &&  out.extensions[1] == 16 &&
          out.extensions[2] == 13 && out.extensions[3] == 43,
          "extension order preserved");

    /* SNI host_name detected */
    CHECK(out.sni_present_domain == 1, "SNI host_name detected");

    /* ALPN: first/last char of "h2" */
    CHECK(out.alpn_first == 'h' && out.alpn_last == '2', "ALPN first/last char");

    /* supported_versions max (GREASE excluded, TLS 1.3 is the maximum) */
    CHECK(out.supported_versions_max == 0x0304, "supported_versions max");

    /* sig_algs: GREASE excluded, presentation order (= 0x0403, 0x0804) */
    CHECK(out.has_sig_algs == 1, "sig_algs ext present flag");
    CHECK(out.nsig_algs == 2, "sig_algs count after GREASE filter");
    CHECK(out.sig_algs[0] == 0x0403 && out.sig_algs[1] == 0x0804, "sig_algs order preserved");

    /* legacy_version */
    CHECK(out.legacy_version == 0x0303, "legacy_version");
}

/* ====================================================================
 * Test case 2: no SNI (= no extension 0) -> sni_present_domain=0
 * ==================================================================== */
static void test_no_sni(void) {
    unsigned char buf[1024];
    ja4_parsed_t out;
    size_t total;

    unsigned int ciphers[] = {0x1301};
    ext_def_t exts[] = {
        {43, (const unsigned char *)"\x02\x03\x04", 3}, /* sup_ver: TLS 1.3 only */
    };

    total = build_ch(buf, sizeof(buf), 0x0303, ciphers, 1, exts, 1);
    CHECK(ja4_parse_client_hello(buf, total, &out) == 0, "parse should succeed");
    CHECK(out.sni_present_domain == 0, "SNI absent -> flag=0");
    CHECK(out.alpn_first == '0' && out.alpn_last == '0', "ALPN absent -> default '0'");
}

/* ====================================================================
 * Test case 3: TLS 1.2 ClientHello (= no supported_versions ext)
 *              -> legacy_version is used as-is
 * ==================================================================== */
static void test_tls12_no_supported_versions(void) {
    unsigned char buf[1024];
    ja4_parsed_t out;
    size_t total;

    unsigned int ciphers[] = {0xc02f, 0xc030};
    ext_def_t exts[] = {
        {0xff01, (const unsigned char *)"\x00", 1}, /* renegotiation_info dummy */
    };

    total = build_ch(buf, sizeof(buf), 0x0303, ciphers, 2, exts, 1);
    CHECK(ja4_parse_client_hello(buf, total, &out) == 0, "parse should succeed");
    CHECK(out.legacy_version == 0x0303, "legacy_version = TLS 1.2");
    CHECK(out.supported_versions_max == 0, "supported_versions absent -> 0");
}

/* ====================================================================
 * Test case 4: reject malformed input
 *   - msg_type != 1
 *   - body length exceeds buffer
 *   - odd cipher_suites_length
 * ==================================================================== */
static void test_malformed_rejected(void) {
    ja4_parsed_t out;

    /* (a) msg_type=2 (ServerHello) should return -1 */
    {
        unsigned char fake[] = {0x02, 0x00, 0x00, 0x00};
        CHECK(ja4_parse_client_hello(fake, sizeof(fake), &out) == -1,
              "non-client_hello message type rejected");
    }

    /* (b) body length exceeds buffer (= header only; body_len > remaining) */
    {
        unsigned char fake[] = {0x01, 0x00, 0x10, 0x00}; /* claim 4096 bytes body, only 0 follow */
        CHECK(ja4_parse_client_hello(fake, sizeof(fake), &out) == -1,
              "truncated body rejected");
    }

    /* (c) cipher_suites_length is odd -> reject */
    {
        unsigned char buf[256];
        size_t i, total;
        unsigned char *p = buf;
        *p++ = 1; *p++ = 0; *p++ = 0; *p++ = 0;  /* header placeholder */
        unsigned char *body = p;
        *p++ = 0x03; *p++ = 0x03;                 /* legacy_version */
        for (i = 0; i < 32; i++) *p++ = 0;        /* random */
        *p++ = 0;                                 /* session_id len = 0 */
        *p++ = 0; *p++ = 0x03;                    /* cipher_suites_len = 3 (= odd) */
        *p++ = 0x13; *p++ = 0x01; *p++ = 0xff;    /* odd bytes */
        *p++ = 1; *p++ = 0;                       /* comp_methods */
        *p++ = 0; *p++ = 0;                       /* extensions len = 0 */
        size_t body_len = (size_t)(p - body);
        buf[1] = (body_len >> 16) & 0xFF;
        buf[2] = (body_len >> 8) & 0xFF;
        buf[3] = body_len & 0xFF;
        total = (size_t)(p - buf);
        CHECK(ja4_parse_client_hello(buf, total, &out) == -1,
              "odd cipher_suites_length rejected");
    }
}

/* ====================================================================
 * Test case 5: no extensions block (= TLS 1.0 style) — parser still succeeds
 * ==================================================================== */
static void test_no_extensions_block(void) {
    unsigned char buf[256];
    ja4_parsed_t out;
    unsigned char *p = buf;
    size_t i, body_len, total;
    unsigned char *body;

    *p++ = 1; *p++ = 0; *p++ = 0; *p++ = 0;  /* header placeholder */
    body = p;
    *p++ = 0x03; *p++ = 0x01;                 /* legacy_version = TLS 1.0 */
    for (i = 0; i < 32; i++) *p++ = 0;        /* random */
    *p++ = 0;                                 /* session_id len = 0 */
    *p++ = 0; *p++ = 2;                       /* cipher_suites_len = 2 */
    *p++ = 0x00; *p++ = 0x05;                 /* SSL_RSA_WITH_RC4_128_SHA style */
    *p++ = 1; *p++ = 0;                       /* comp_methods */
    /* extensions block omitted (= optional in TLS 1.0) */

    body_len = (size_t)(p - body);
    buf[1] = (body_len >> 16) & 0xFF;
    buf[2] = (body_len >> 8) & 0xFF;
    buf[3] = body_len & 0xFF;
    total = (size_t)(p - buf);

    CHECK(ja4_parse_client_hello(buf, total, &out) == 0, "extensions-less CH parses");
    CHECK(out.legacy_version == 0x0301, "legacy_version = TLS 1.0");
    CHECK(out.ncipher == 1, "cipher count");
    CHECK(out.nexts == 0, "extension count = 0");
    CHECK(out.has_sig_algs == 0, "no sig_algs");
    CHECK(out.supported_versions_max == 0, "no supported_versions");
}

int main(void) {
    test_basic_tls13_with_sni_and_alpn();
    test_no_sni();
    test_tls12_no_supported_versions();
    test_malformed_rejected();
    test_no_extensions_block();

    printf("ja4_parser_test: %d pass / %d fail\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
