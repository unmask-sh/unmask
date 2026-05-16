/*
 * ja4_parser.c — TLS ClientHello parser (no OpenSSL dependency).
 *
 * RFC 5246 §7.4.1.2 (TLS 1.2 ClientHello) + RFC 8446 §4.1.2 (TLS 1.3) +
 * JA4 spec の要件のみ実装.  decryption や handshake completion などは触らない.
 *
 * 設計上の不変条件:
 *   - 入力 buffer 外を 1 byte たりとも触らない (= 全 advance に bound check).
 *   - allocation は一切しない (= 全部 caller-provided struct に格納).
 *   - 失敗時は途中状態の out を caller に渡し得るが、 caller は返り値 0 のみ
 *     信用する規約とする (= ja4_parser.h の doc comment 参照).
 */

#include "ja4_parser.h"

#include <string.h>

/* GREASE pattern (RFC 8701): 0x?A?A で 上 nibble == 下 nibble の hex 1 字. */
static int ja4_is_grease(unsigned int v) {
    return ((v & 0x0F0F) == 0x0A0A)
        && (((v >> 4) & 0x0F) == ((v >> 12) & 0x0F));
}

/* 2 byte big-endian read.  bound check は呼出側. */
static unsigned int rd_u16(const unsigned char *p) {
    return ((unsigned int)p[0] << 8) | (unsigned int)p[1];
}

int ja4_parse_client_hello(const unsigned char *msg, size_t len,
                           ja4_parsed_t *out)
{
    const unsigned char *p;
    const unsigned char *end;
    unsigned int body_len;
    unsigned int sid_len;
    unsigned int cs_len;
    unsigned int comp_len;
    unsigned int ext_total_len;

    if (msg == NULL || out == NULL || len < 4) {
        return -1;
    }
    memset(out, 0, sizeof(*out));
    out->alpn_first = '0';
    out->alpn_last  = '0';

    /* handshake header: HandshakeType(1) + uint24 length. */
    if (msg[0] != 1 /* client_hello */) {
        return -1;
    }
    body_len = (((unsigned int)msg[1]) << 16)
             | (((unsigned int)msg[2]) << 8)
             |  ((unsigned int)msg[3]);
    if ((size_t)body_len + 4 > len) {
        return -1;
    }

    p   = msg + 4;
    end = msg + 4 + body_len;

    /* legacy_version (2) + random (32) */
    if ((size_t)(end - p) < 34) return -1;
    out->legacy_version = rd_u16(p);
    p += 34;

    /* session_id<0..32> */
    if ((size_t)(end - p) < 1) return -1;
    sid_len = p[0];
    p += 1;
    if ((size_t)(end - p) < sid_len) return -1;
    p += sid_len;

    /* cipher_suites<2..2^16-2> */
    if ((size_t)(end - p) < 2) return -1;
    cs_len = rd_u16(p);
    p += 2;
    if ((size_t)(end - p) < cs_len) return -1;
    if ((cs_len % 2) != 0) return -1;
    {
        const unsigned char *cp   = p;
        const unsigned char *cend = p + cs_len;
        while (cp + 2 <= cend) {
            unsigned int c = rd_u16(cp);
            cp += 2;
            if (ja4_is_grease(c)) continue;
            if (out->ncipher < JA4_MAX_CIPHERS) {
                out->ciphers[out->ncipher++] = c;
            }
        }
    }
    p += cs_len;

    /* legacy_compression_methods<1..2^8-1> */
    if ((size_t)(end - p) < 1) return -1;
    comp_len = p[0];
    p += 1;
    if ((size_t)(end - p) < comp_len) return -1;
    p += comp_len;

    /* extensions block (= TLS 1.0 では optional).  終端なら正常終了. */
    if (p == end) {
        return 0;
    }
    if ((size_t)(end - p) < 2) return -1;
    ext_total_len = rd_u16(p);
    p += 2;
    if ((size_t)(end - p) < ext_total_len) return -1;
    /* extensions ブロックに end を絞り込む (= 余剰 bytes は無視). */
    end = p + ext_total_len;

    while ((size_t)(end - p) >= 4) {
        unsigned int etype = rd_u16(p);
        unsigned int elen  = rd_u16(p + 2);
        const unsigned char *eptr;

        p += 4;
        if ((size_t)(end - p) < elen) return -1;
        eptr = p;

        if (!ja4_is_grease(etype) && out->nexts < JA4_MAX_EXTENSIONS) {
            out->extensions[out->nexts++] = etype;
        }

        switch (etype) {

        case 0: /* server_name (= SNI).
                 * 構造: u16 list_total_len, [u8 name_type, u16 host_len, bytes]*.
                 * host_name (= name_type 0) が 1 つでもあれば domain あり. */
            if (elen >= 5) {
                unsigned int list_len = rd_u16(eptr);
                if (list_len + 2 <= elen && list_len >= 3) {
                    if (eptr[2] == 0 /* host_name */) {
                        out->sni_present_domain = 1;
                    }
                }
            }
            break;

        case 13: /* signature_algorithms.
                  * 構造: u16 list_len_bytes, u16 sigscheme*. */
            out->has_sig_algs = 1;
            if (elen >= 2) {
                unsigned int sa_len = rd_u16(eptr);
                if (sa_len + 2 <= elen && (sa_len % 2) == 0) {
                    const unsigned char *sp   = eptr + 2;
                    const unsigned char *send = sp + sa_len;
                    while (sp + 2 <= send) {
                        unsigned int sa = rd_u16(sp);
                        sp += 2;
                        if (ja4_is_grease(sa)) continue;
                        if (out->nsig_algs < JA4_MAX_SIG_ALGS) {
                            out->sig_algs[out->nsig_algs++] = sa;
                        }
                    }
                }
            }
            break;

        case 16: /* application_layer_protocol_negotiation (= ALPN).
                  * 構造: u16 list_len_bytes, [u8 proto_len, bytes]*.
                  * 最初の proto の先頭 / 末尾文字を JA4 に使う. */
            if (elen >= 3) {
                unsigned int list_len = rd_u16(eptr);
                if (list_len + 2 <= elen && list_len >= 1) {
                    unsigned int proto_len = eptr[2];
                    if (proto_len >= 1
                        && (size_t)proto_len + 3 <= (size_t)elen) {
                        out->alpn_first = eptr[3];
                        out->alpn_last  = eptr[3 + proto_len - 1];
                    }
                }
            }
            break;

        case 43: /* supported_versions (ClientHello 形式).
                  * 構造: u8 list_len_bytes, u16 version*.
                  * GREASE 除外し最大値を採用. */
            if (elen >= 1) {
                unsigned int sv_len = eptr[0];
                if ((size_t)sv_len + 1 <= (size_t)elen
                    && (sv_len % 2) == 0) {
                    const unsigned char *sp   = eptr + 1;
                    const unsigned char *send = sp + sv_len;
                    unsigned int max_ver = 0;
                    while (sp + 2 <= send) {
                        unsigned int sv = rd_u16(sp);
                        sp += 2;
                        if (ja4_is_grease(sv)) continue;
                        if (sv > max_ver) max_ver = sv;
                    }
                    out->supported_versions_max = max_ver;
                }
            }
            break;

        default:
            break;
        }

        p += elen;
    }

    return 0;
}
