/*
 * ja4_build_test.c — known-answer tests for ja4_build_string.
 *
 * Each expected JA4 string is derived independently from the JA4 spec, and
 * its b/c SHA-256[:12] sections were computed with `sha256sum` (NOT with this
 * code), so a transcription bug in ja4_build.c cannot agree with the golden:
 *
 *   sha12("")                  = e3b0c44298fc
 *   sha12("1301,1302")         = 62ed6f6ca7ad
 *   sha12("1301")              = 0f2cb44170f4
 *   sha12("000d,002b_0403,0804") = ef5f37ab036a
 *
 * Build / run (SHA256 needs libcrypto):
 *   gcc -std=gnu99 -Wall -Wextra ja4_build.c ja4_build_test.c \
 *       -lcrypto -o ja4_build_test && ./ja4_build_test
 *
 * The parser->build integration and memory safety are covered separately by
 * ja4_build_fuzz.c (parse + build under ASan/UBSan) and e2e scenario 07.
 */

#include "ja4_build.h"

#include <stdio.h>
#include <string.h>

static int g_pass, g_fail;

#define CHECK_STR(got, want, msg) do {                                    \
    if (strcmp((got), (want)) == 0) { g_pass++; }                         \
    else { g_fail++; fprintf(stderr,                                      \
        "FAIL: %s:%d  %s\n  got:  %s\n  want: %s\n",                       \
        __FILE__, __LINE__, (msg), (got), (want)); }                      \
} while (0)

/* Reset to the parser's "all absent" baseline: ALPN chars default to '0'. */
static void zero(ja4_parsed_t *p) {
    memset(p, 0, sizeof(*p));
    p->alpn_first = '0';
    p->alpn_last  = '0';
}

int main(void) {
    ja4_parsed_t p;
    char out[JA4_STRING_MAX];

    /* V1: TLS 1.2, ciphers 1301+1302, SNI host_name present, ALPN "h2",
     * no signature_algorithms.  a="t12d0202h2". */
    zero(&p);
    p.legacy_version = 0x0303;
    p.ciphers[0] = 0x1301; p.ciphers[1] = 0x1302; p.ncipher = 2;
    p.extensions[0] = 0; p.extensions[1] = 16; p.nexts = 2; /* SNI + ALPN */
    p.sni_present_domain = 1;
    p.alpn_first = 'h'; p.alpn_last = '2';
    ja4_build_string(&p, out, sizeof(out));
    CHECK_STR(out, "t12d0202h2_62ed6f6ca7ad_e3b0c44298fc", "V1 typical TLS1.2");

    /* V2: TLS 1.2, single cipher 1301, no SNI / exts / ALPN.  a="t12i010000". */
    zero(&p);
    p.legacy_version = 0x0303;
    p.ciphers[0] = 0x1301; p.ncipher = 1;
    ja4_build_string(&p, out, sizeof(out));
    CHECK_STR(out, "t12i010000_0f2cb44170f4_e3b0c44298fc", "V2 ciphers only");

    /* V3: TLS 1.3 via supported_versions, cipher 1301, exts 43+13 (kept,
     * sorted -> 000d,002b), signature_algorithms 0403+0804 appended after
     * '_'.  c = sha12("000d,002b_0403,0804").  a="t13i010200". */
    zero(&p);
    p.legacy_version = 0x0303;
    p.supported_versions_max = 0x0304;
    p.ciphers[0] = 0x1301; p.ncipher = 1;
    p.extensions[0] = 43; p.extensions[1] = 13; p.nexts = 2;
    p.has_sig_algs = 1;
    p.sig_algs[0] = 0x0403; p.sig_algs[1] = 0x0804; p.nsig_algs = 2;
    ja4_build_string(&p, out, sizeof(out));
    CHECK_STR(out, "t13i010200_0f2cb44170f4_ef5f37ab036a", "V3 sig_algs path");

    /* V4: completely empty ClientHello (unknown version, nothing present).
     * version code falls back to "00"; both hashes are sha12(""). */
    zero(&p);
    ja4_build_string(&p, out, sizeof(out));
    CHECK_STR(out, "t00i000000_e3b0c44298fc_e3b0c44298fc", "V4 empty");

    printf("ja4_build_test: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail == 0 ? 0 : 1;
}
