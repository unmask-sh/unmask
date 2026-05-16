/*
 * ja4_parser.h — pure-C TLS ClientHello parser for JA4 fingerprint.
 *
 * 役割: SSL_CTX_set_msg_callback (= OpenSSL 0.9.7+ 全 ABI 共通の安定 API) 経由で
 *       渡される raw handshake message bytes を JA4 計算に必要な要素に分解.
 *
 * OpenSSL バージョン依存 API (= SSL_client_hello_get0_*) を排除し、 OpenSSL 1.0 /
 * 1.1 / 3.x / LibreSSL / BoringSSL いずれでも同 source から build 可能にする
 * ためのレイヤー.  spec は RFC 5246 (TLS 1.2) / RFC 8446 (TLS 1.3) +
 * https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md.
 * FoxIO の BSL ライセンス実装ソースは参照しない (= clean-room).
 */

#ifndef NGX_JA4_PARSER_H_INCLUDED_
#define NGX_JA4_PARSER_H_INCLUDED_

#include <stddef.h>

#define JA4_MAX_CIPHERS    256
#define JA4_MAX_EXTENSIONS 256
#define JA4_MAX_SIG_ALGS   64

typedef struct {
    /* legacy_version 欄 (= ClientHello.legacy_version).
     * TLS 1.3 では 0x0303 固定で、 実際の version は supported_versions ext へ. */
    unsigned int  legacy_version;

    /* supported_versions (= ext 43) の最大値 (GREASE 除外).
     * extension 不在なら 0.  JA4 spec: 値があれば legacy より優先. */
    unsigned int  supported_versions_max;

    /* cipher_suites を GREASE 除外し提示順で保持.  256 を超える場合は切捨て. */
    unsigned int  ciphers[JA4_MAX_CIPHERS];
    int           ncipher;

    /* extensions を GREASE 除外し提示順で保持 (= ID のみ, body は別解析). */
    unsigned int  extensions[JA4_MAX_EXTENSIONS];
    int           nexts;

    /* signature_algorithms (= ext 13) を GREASE 除外し提示順で保持. */
    unsigned int  sig_algs[JA4_MAX_SIG_ALGS];
    int           nsig_algs;
    int           has_sig_algs;       /* ext 13 自体が存在したか */

    /* SNI (= ext 0): host_name エントリ (name_type=0) が 1 つでもあれば 1. */
    int           sni_present_domain;

    /* ALPN (= ext 16) の最初の proto の先頭文字 / 末尾文字.  不在なら '0'. */
    int           alpn_first;
    int           alpn_last;
} ja4_parsed_t;

/*
 * Parse a TLS handshake message that begins at the msg_type byte.
 *
 * 入力: SSL_CTX_set_msg_callback が content_type=SSL3_RT_HANDSHAKE (= 22) +
 *       write_p=0 (= 受信) で呼ばれた際の (buf, len).
 *       msg[0] = SSL3_MT_CLIENT_HELLO (= 1) を期待.
 *
 * 返り値:
 *   0  = ClientHello を正常 parse できた (out 有効)
 *  -1  = malformed / 非 ClientHello / 容量不足.  out の中身は未定義.
 */
int ja4_parse_client_hello(const unsigned char *msg, size_t len,
                           ja4_parsed_t *out);

#endif /* NGX_JA4_PARSER_H_INCLUDED_ */
