/*
 * ja4_parser.h — pure-C TLS ClientHello parser for JA4 fingerprint.
 *
 * Purpose: decompose raw handshake message bytes delivered via
 *          SSL_CTX_set_msg_callback (= the stable API common to OpenSSL
 *          0.9.7+ across all ABIs) into the elements needed for JA4
 *          computation.
 *
 * This layer avoids OpenSSL-version-specific APIs (= SSL_client_hello_get0_*)
 * so the same source builds against OpenSSL 1.0 / 1.1 / 3.x / LibreSSL /
 * BoringSSL. Spec: RFC 5246 (TLS 1.2) / RFC 8446 (TLS 1.3) plus
 * https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md.
 * The BSL-licensed FoxIO reference implementation is not consulted
 * (= clean-room).
 */

#ifndef NGX_JA4_PARSER_H_INCLUDED_
#define NGX_JA4_PARSER_H_INCLUDED_

#include <stddef.h>

#define JA4_MAX_CIPHERS    256
#define JA4_MAX_EXTENSIONS 256
#define JA4_MAX_SIG_ALGS   64

typedef struct {
    /* legacy_version field (= ClientHello.legacy_version).
     * Fixed at 0x0303 for TLS 1.3; the real version lives in the
     * supported_versions extension. */
    unsigned int  legacy_version;

    /* Maximum value (GREASE excluded) from supported_versions (= ext 43).
     * 0 if the extension is absent. JA4 spec: prefer this over legacy
     * when present. */
    unsigned int  supported_versions_max;

    /* cipher_suites in presentation order with GREASE excluded.
     * Truncated past 256 entries. */
    unsigned int  ciphers[JA4_MAX_CIPHERS];
    int           ncipher;

    /* extensions in presentation order with GREASE excluded
     * (= IDs only; bodies parsed separately). */
    unsigned int  extensions[JA4_MAX_EXTENSIONS];
    int           nexts;

    /* signature_algorithms (= ext 13) in presentation order with GREASE
     * excluded. */
    unsigned int  sig_algs[JA4_MAX_SIG_ALGS];
    int           nsig_algs;
    int           has_sig_algs;       /* set if ext 13 itself was present */

    /* SNI (= ext 0): 1 if at least one host_name entry (name_type=0)
     * is present. */
    int           sni_present_domain;

    /* ALPN (= ext 16) first and last character of the first proto.
     * Both '0' if absent. */
    int           alpn_first;
    int           alpn_last;
} ja4_parsed_t;

/*
 * Parse a TLS handshake message that begins at the msg_type byte.
 *
 * Input: (buf, len) as delivered by SSL_CTX_set_msg_callback when
 *        content_type=SSL3_RT_HANDSHAKE (= 22) and write_p=0 (= receive).
 *        Expects msg[0] = SSL3_MT_CLIENT_HELLO (= 1).
 *
 * Return:
 *    0  = ClientHello parsed successfully (out is valid)
 *   -1  = malformed / not a ClientHello / insufficient buffer.
 *         The contents of `out` are undefined in this case.
 */
int ja4_parse_client_hello(const unsigned char *msg, size_t len,
                           ja4_parsed_t *out);

#endif /* NGX_JA4_PARSER_H_INCLUDED_ */
