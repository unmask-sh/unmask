/*
 * ngx_http_unmask_module: nginx dynamic module that exposes:
 *
 *   $client_ja4         - JA4 fingerprint computed from TLS ClientHello
 *   $unmask_bv_valid    - "1" if the request's _bv cookie HMAC matches and
 *                         is within the validity window, else "0".
 *   $unmask_banned      - "1" if (remote_addr, client_ja4) is in the ban file,
 *                         else "0".  ban file is mtime-watched (= reload-free).
 *
 * License: Apache 2.0 (clean-room implementation from JA4 specification)
 * Reference: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
 *
 * JA4 format: <a>_<b>_<c>
 *   a (10 chars): protocol(t/q) + tlsver(2) + sni(d/i) + ciphers(2) + extensions(2) + alpn(2)
 *   b (12 chars): SHA256(sorted hex cipher list)[:12]
 *   c (12 chars): SHA256(sorted hex extensions, then signature_algorithms appended)[:12]
 *
 * BV cookie format: "<issued_unix>.<sig>.<kind>"
 *   issued_unix = decimal unix seconds, supplied by the admin at issuance
 *                 (= server clock; clients never compute it themselves)
 *   sig         = HMAC-SHA1("<issued_unix>:<remote_addr>:<host>:<kind>", BV_SECRET) hex[:16]
 *   kind = "captcha"
 *
 * Site binding: $host (lowercased + port-stripped by nginx) is folded into the
 * HMAC input, so a cookie minted while solving vhost A's challenge fails on
 * vhost B (different host -> different signature).  The admin issuer folds in
 * the same host (X-Original-Host, which nginx sets from $host), keeping the two
 * byte-identical.  Replaces the old $unmask_site kind-suffix scheme (the admin
 * only ever emitted "captcha", so that scheme never actually bound anything).
 *
 * Configuration:
 *   unmask_bv_secret <secret>;        # HTTP main scope. shared with admin app.
 *   unmask_bv_pow_valid_seconds <int>;      # PoW-issued cookies (default 259200 = 3d)
 *   unmask_bv_captcha_valid_seconds <int>;  # CAPTCHA-issued cookies (default 259200 = 3d)
 *   unmask_ban_file <path>;           # honeypot ban list (= "<ip>|<ja4>" per line)
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event_openssl.h>
#include <ngx_http_ssl_module.h>

#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "ja4_parser.h"

#define NGX_JA4_MAX 64

/* Per-connection JA4 storage.
 *
 * The JA4 string lives in a fixed buffer inside the ctx (= a single
 * OPENSSL_malloc covers everything, just for the ctx).  Because the
 * free_cb never frees `ja4.data` independently, the cleanup race that
 * occurs on early-abort handshake paths (= self-signed cert / cert
 * untrusted etc.) cannot produce double-free / heap corruption. */
typedef struct {
    u_char     ja4_buf[NGX_JA4_MAX]; /* full string; ngx_str_t.data points here */
    ngx_str_t  ja4;                  /* {data: ja4_buf, len: measured value}.  data is never freed */
} ngx_http_ja4_ctx_t;

/* ex_data index for storing JA4 string on SSL object */
static int ngx_http_ja4_ssl_ex_data_idx = -1;

/* Per-http main config: shared BV secret for $unmask_bv_valid */
typedef struct {
    ngx_str_t   bv_secret;
    /* Validity window in SECONDS applied to PoW-issued cookies (= 4-segment
     * "pow2" format).  Default 259200 (= 3 days).  Set via
     * unmask_bv_pow_valid_seconds. */
    ngx_int_t   bv_pow_valid_seconds;
    /* Validity window in SECONDS applied to CAPTCHA-issued cookies
     * (= 3-segment HMAC format).  Default 259200 (= 3 days).  Set via
     * unmask_bv_captcha_valid_seconds. */
    ngx_int_t   bv_captcha_valid_seconds;
    /* Target leading-zero bits for SHA-256 PoW. Must match challenge.js
     * and the Go cookies package.  Default 18.  Override via the
     * unmask_bv_pow_difficulty directive. */
    ngx_int_t   bv_pow_difficulty;
    ngx_str_t   ban_file_path;
} ngx_http_ja4_main_conf_t;

/* ban list entry: "<ip>|<ja4>|<source>|<action>" sorted ASC by the ip|ja4
 * prefix for binary search.  worker scope (= re-loaded on mtime change).
 * keys[i] points at "ip|ja4" (= NUL-terminated in-place where '|' before
 * source used to be).  actions[i] points at the action token after that
 * NUL ("deny" / "pow_only" / "pow_then_captcha" / "captcha_only"). */
typedef struct {
    char    *buf;       /* malloc'd, contains keys + NULs */
    char   **keys;      /* pointers into buf */
    char   **actions;   /* parallel array, same length as keys */
    size_t   nkeys;
    time_t   mtime;     /* last seen mtime to skip reloads */
} ngx_unmask_banlist_t;

/* per-worker ban list. Reloaded lazily on every variable evaluation if mtime changed. */
/* gcc 4.4 (= CentOS 6) warns on `= {0}` with a missing-initializer.
   The C standard zero-initializes static storage, so no explicit init
   is needed. */
static ngx_unmask_banlist_t ngx_unmask_banlist;

static ngx_int_t ngx_http_ja4_init(ngx_conf_t *cf);
static void *ngx_http_ja4_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_ja4_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_ja4_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_unmask_bv_kind_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_unmask_bv_captcha_valid_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_unmask_bv_pow_valid_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_unmask_banned_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_unmask_ban_action_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_unmask_has_signed_agent_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_command_t ngx_http_ja4_commands[] = {
    { ngx_string("unmask_bv_secret"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_ja4_main_conf_t, bv_secret),
      NULL },
    { ngx_string("unmask_bv_pow_valid_seconds"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_ja4_main_conf_t, bv_pow_valid_seconds),
      NULL },
    { ngx_string("unmask_bv_captcha_valid_seconds"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_ja4_main_conf_t, bv_captcha_valid_seconds),
      NULL },
    { ngx_string("unmask_bv_pow_difficulty"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_ja4_main_conf_t, bv_pow_difficulty),
      NULL },
    { ngx_string("unmask_ban_file"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_ja4_main_conf_t, ban_file_path),
      NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_unmask_module_ctx = {
    NULL,                              /* preconfiguration */
    ngx_http_ja4_init,                 /* postconfiguration */
    ngx_http_ja4_create_main_conf,     /* create main configuration */
    ngx_http_ja4_init_main_conf,       /* init main configuration */
    NULL, NULL, NULL, NULL
};

ngx_module_t ngx_http_unmask_module = {
    NGX_MODULE_V1,
    &ngx_http_unmask_module_ctx,
    ngx_http_ja4_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

/* Compatibility with nginx < 1.11.5 (= ngx_http_null_variable is undefined
 * on RHEL 6 EPEL's nginx 1.10 series).  Provide our own sentinel. */
#ifndef ngx_http_null_variable
#define ngx_http_null_variable  { ngx_null_string, NULL, NULL, 0, 0, 0 }
#endif

static ngx_http_variable_t ngx_http_ja4_vars[] = {
    { ngx_string("client_ja4"), NULL, ngx_http_ja4_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
    /* unmask_bv_kind: "captcha" (3-seg HMAC OK) / "pow" (4-seg djb2 OK) /
     * "" (= invalid / not presented).
     * Extending: when a future cookie path (= "signature" / "webauthn" /
     * "passkey" etc.) is added, just add a branch here and the dashboard
     * aggregation will automatically treat the new kind as one row. */
    { ngx_string("unmask_bv_kind"), NULL, ngx_http_unmask_bv_kind_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
    /* unmask_bv_captcha_valid: 1 if $bv_kind == "captcha". Used by the
     * $final_challenge / $rate_limit_key maps in nginx-rendered.conf to
     * decide "repeat visitors are exempt". */
    { ngx_string("unmask_bv_captcha_valid"), NULL, ngx_http_unmask_bv_captcha_valid_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
    /* unmask_bv_pow_valid: 1 if $bv_kind == "pow". */
    { ngx_string("unmask_bv_pow_valid"), NULL, ngx_http_unmask_bv_pow_valid_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("unmask_ban_action"), NULL, ngx_http_unmask_ban_action_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("unmask_banned"), NULL, ngx_http_unmask_banned_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
    /* unmask_has_signed_agent: "1" when the request carries RFC 9421
     * Signature-Input header (= Web Bot Auth candidate), "0" otherwise.
     * Used by the hybrid path in server.inc to route signed requests
     * through admin /_unmask/check for verification while keeping the
     * pure-native fast path for unsigned traffic (= subrequest 0). */
    { ngx_string("unmask_has_signed_agent"), NULL,
      ngx_http_unmask_has_signed_agent_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
    ngx_http_null_variable
};

/* GREASE detection moved into ja4_parser.c (= removed from module.c
 * when the old callback was retired). */

static void ngx_ja4_hex4(char *out, unsigned int v) {
    static const char hex[] = "0123456789abcdef";
    out[0] = hex[(v >> 12) & 0xF];
    out[1] = hex[(v >> 8) & 0xF];
    out[2] = hex[(v >> 4) & 0xF];
    out[3] = hex[v & 0xF];
}

/* qsort comparator for uint16 ascending */
static int u16_cmp(const void *a, const void *b) {
    unsigned int x = *(const unsigned int *)a;
    unsigned int y = *(const unsigned int *)b;
    return (x < y) ? -1 : (x > y) ? 1 : 0;
}

/* SHA256(hex) -> first 12 hex chars */
static void ngx_ja4_sha12(const char *in, size_t inlen, char *out12) {
    static const char hex[] = "0123456789abcdef";
    unsigned char h[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)in, inlen, h);
    /* JA4 spec: take first 6 bytes hex = 12 chars */
    for (int i = 0; i < 6; i++) {
        out12[i*2]     = hex[(h[i] >> 4) & 0xF];
        out12[i*2 + 1] = hex[h[i] & 0xF];
    }
}

/*
 * ngx_ja4_compute_and_store: build the JA4 string from ja4_parsed_t
 * (= our own parser output) and store it in SSL ex_data.
 *
 * The previous implementation relied on SSL_client_hello_get0_*
 * (= OpenSSL 1.1.1+ only). The current implementation parses the
 * TLS 1.2 / 1.3 ClientHello on its own in ja4_parser.c, so the same
 * source builds on OpenSSL 1.0 / 1.1 / 3.x / LibreSSL / BoringSSL.
 */
static void ngx_ja4_compute_and_store(SSL *ssl, const ja4_parsed_t *parsed) {
    ngx_http_ja4_ctx_t *ctx;
    int tlsver;
    char tlscode[3];
    char ja4_a[16];
    int  n_a;
    int  cipher_count_disp;
    int  ext_count_disp;
    char buf[2048];
    char *bp;
    int  i, nexts_c;
    unsigned int sorted[JA4_MAX_CIPHERS];
    unsigned int sorted_e[JA4_MAX_EXTENSIONS];
    char ja4_b[13];
    char ja4_c[13];
    int  outlen;

    if (ngx_http_ja4_ssl_ex_data_idx < 0) return;

    /* If already computed (= 2nd or later ClientHello on the same SSL
     * connection, e.g. an HRR path), do nothing.  Prevents double
     * allocation / double SSL_set_ex_data. */
    if (SSL_get_ex_data(ssl, ngx_http_ja4_ssl_ex_data_idx) != NULL) {
        return;
    }

    ctx = OPENSSL_malloc(sizeof(*ctx));
    if (!ctx) return;
    ngx_memzero(ctx, sizeof(*ctx));

    /* JA4 spec: prefer the supported_versions ext value (= the maximum
     * presented); fall back to legacy_version if absent. */
    tlsver = (parsed->supported_versions_max != 0)
           ? (int)parsed->supported_versions_max
           : (int)parsed->legacy_version;

    switch (tlsver) {
    case 0x0304: ngx_memcpy(tlscode, "13", 2); break; /* TLS 1.3 */
    case 0x0303: ngx_memcpy(tlscode, "12", 2); break; /* TLS 1.2 */
    case 0x0302: ngx_memcpy(tlscode, "11", 2); break;
    case 0x0301: ngx_memcpy(tlscode, "10", 2); break;
    case 0x0300: ngx_memcpy(tlscode, "s3", 2); break;
    case 0xfeff: ngx_memcpy(tlscode, "d1", 2); break;
    case 0xfefd: ngx_memcpy(tlscode, "d2", 2); break;
    case 0xfefc: ngx_memcpy(tlscode, "d3", 2); break;
    default:     ngx_memcpy(tlscode, "00", 2); break;
    }
    tlscode[2] = '\0';

    /* === JA4_a (10 chars) === */
    cipher_count_disp = parsed->ncipher > 99 ? 99 : parsed->ncipher;
    ext_count_disp    = parsed->nexts   > 99 ? 99 : parsed->nexts;
    n_a = ngx_snprintf((u_char *)ja4_a, sizeof(ja4_a), "t%s%c%02d%02d%c%c",
                       tlscode,
                       parsed->sni_present_domain ? 'd' : 'i',
                       cipher_count_disp,
                       ext_count_disp,
                       parsed->alpn_first, parsed->alpn_last)
        - (u_char *)ja4_a;
    if (n_a < (int)sizeof(ja4_a)) ja4_a[n_a] = '\0';
    else ja4_a[sizeof(ja4_a) - 1] = '\0';

    /* === JA4_b: sorted ciphers in hex, comma-joined -> first 12 hex chars
     * of SHA-256 === */
    bp = buf;
    if (parsed->ncipher > 0) {
        ngx_memcpy(sorted, parsed->ciphers,
                   parsed->ncipher * sizeof(unsigned int));
        qsort(sorted, parsed->ncipher, sizeof(unsigned int), u16_cmp);
        for (i = 0; i < parsed->ncipher; i++) {
            if (i) *bp++ = ',';
            ngx_ja4_hex4(bp, sorted[i]);
            bp += 4;
        }
    }
    ngx_ja4_sha12(buf, bp - buf, ja4_b);
    ja4_b[12] = '\0';

    /* === JA4_c: sorted extensions (excluding SNI=0, ALPN=16), then "_"
     * + sig_algs (= presentation order) === */
    bp = buf;
    nexts_c = 0;
    for (i = 0; i < parsed->nexts; i++) {
        if (parsed->extensions[i] == 0 || parsed->extensions[i] == 16) continue;
        sorted_e[nexts_c++] = parsed->extensions[i];
    }
    qsort(sorted_e, nexts_c, sizeof(unsigned int), u16_cmp);
    for (i = 0; i < nexts_c; i++) {
        if (i) *bp++ = ',';
        ngx_ja4_hex4(bp, sorted_e[i]);
        bp += 4;
    }
    if (parsed->has_sig_algs) {
        /* JA4 spec: append "_" + sig_algs only if ext 13 was present in
         * the ClientHello. The "_" itself is emitted even when sig_algs
         * is empty (= matches the prior implementation). */
        *bp++ = '_';
        for (i = 0; i < parsed->nsig_algs; i++) {
            if (i) *bp++ = ',';
            ngx_ja4_hex4(bp, parsed->sig_algs[i]);
            bp += 4;
        }
    }
    ngx_ja4_sha12(buf, bp - buf, ja4_c);
    ja4_c[12] = '\0';

    /* === Final JA4 ===
     * Write directly into ctx's ja4_buf (= no separate OPENSSL_malloc;
     * eliminates the double-free window). */
    outlen = ngx_snprintf(ctx->ja4_buf, NGX_JA4_MAX, "%s_%s_%s",
                          ja4_a, ja4_b, ja4_c) - ctx->ja4_buf;
    if (outlen >= NGX_JA4_MAX) outlen = NGX_JA4_MAX - 1;
    ctx->ja4.data = ctx->ja4_buf;
    ctx->ja4.len  = outlen;

    SSL_set_ex_data(ssl, ngx_http_ja4_ssl_ex_data_idx, ctx);
}

/*
 * SSL_CTX_set_msg_callback handler.
 *
 * The stable API common to OpenSSL 0.9.7+ across all ABIs. The callback
 * also fires for every record / application data during the handshake,
 * but the hot path early-returns those cases.
 *
 * `buf` arrives as a fully assembled handshake message (= record header
 * stripped). The first byte is HandshakeType (1 = client_hello); the
 * next 3 bytes are uint24 length.
 *
 * Note: write_p == 1 is server->client (= ServerHello etc.), so ignored.
 */
static void ngx_ja4_msg_cb(int write_p, int version, int content_type,
                           const void *buf, size_t len,
                           SSL *ssl, void *arg) {
    const unsigned char *m;
    ja4_parsed_t parsed;

    (void)version; (void)arg;

    if (write_p != 0) return;
    if (content_type != 22 /* SSL3_RT_HANDSHAKE */) return;
    if (buf == NULL || len < 5) return; /* type(1) + len(3) + minimum body */

    m = (const unsigned char *)buf;
    if (m[0] != 1 /* client_hello */) return;

    /* If already computed, skip the parse entirely. */
    if (ngx_http_ja4_ssl_ex_data_idx >= 0
        && SSL_get_ex_data(ssl, ngx_http_ja4_ssl_ex_data_idx) != NULL) {
        return;
    }

    if (ja4_parse_client_hello(m, len, &parsed) != 0) return;
    ngx_ja4_compute_and_store(ssl, &parsed);
}

/* Free callback for ex_data.
 *
 * ctx is a single OPENSSL_malloc, single allocation. The JA4 string lives
 * in the ctx's fixed buffer, so it is never freed independently
 * (= eliminates the double-free window). */
static void ngx_ja4_ssl_free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                                int idx, long argl, void *argp) {
    (void)parent; (void)ad; (void)idx; (void)argl; (void)argp;
    if (ptr) OPENSSL_free(ptr);
}

static ngx_int_t ngx_http_ja4_variable(ngx_http_request_t *r,
                                       ngx_http_variable_value_t *v,
                                       uintptr_t data) {
    (void)data;
    if (r->connection == NULL || r->connection->ssl == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }
    if (ngx_http_ja4_ssl_ex_data_idx < 0) {
        v->not_found = 1;
        return NGX_OK;
    }
    SSL *ssl_obj = r->connection->ssl->connection;
    if (ssl_obj == NULL) {
        v->not_found = 1;
        return NGX_OK;
    }
    ngx_http_ja4_ctx_t *ctx = SSL_get_ex_data(ssl_obj,
                                              ngx_http_ja4_ssl_ex_data_idx);
    if (!ctx || ctx->ja4.len == 0) {
        v->not_found = 1;
        return NGX_OK;
    }
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->len = ctx->ja4.len;
    v->data = ctx->ja4.data;
    return NGX_OK;
}

static ngx_int_t ngx_http_ja4_init(ngx_conf_t *cf) {
    /* Register $client_ja4 variable */
    for (ngx_http_variable_t *v = ngx_http_ja4_vars; v->name.len; v++) {
        ngx_http_variable_t *var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (!var) return NGX_ERROR;
        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    /* Register ex_data slot once */
    if (ngx_http_ja4_ssl_ex_data_idx < 0) {
        ngx_http_ja4_ssl_ex_data_idx = SSL_get_ex_new_index(
            0, (void *)"ja4", NULL, NULL, ngx_ja4_ssl_free_cb);
        if (ngx_http_ja4_ssl_ex_data_idx < 0) return NGX_ERROR;
    }

    /* Attach the msg_callback to each server block's SSL_CTX (= what
     * http_ssl_module allocated). SSL_CTX_set_msg_callback is the stable
     * API common to OpenSSL 0.9.7+ across all ABIs.
     *
     * Previously: SSL_CTX_set_client_hello_cb (= OpenSSL 1.1.1+ only;
     * unavailable on CentOS 7 / LibreSSL etc.) -> replaced with our own
     * parse in ja4_parser.c. */
    ngx_http_core_main_conf_t *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if (!cmcf) return NGX_OK;

    ngx_http_core_srv_conf_t **cscfp = cmcf->servers.elts;
    extern ngx_module_t ngx_http_ssl_module;
    for (ngx_uint_t i = 0; i < cmcf->servers.nelts; i++) {
        void **ctxconf = cscfp[i]->ctx->srv_conf;
        ngx_http_ssl_srv_conf_t *sscf =
            ctxconf[ngx_http_ssl_module.ctx_index];
        if (sscf && sscf->ssl.ctx) {
            SSL_CTX_set_msg_callback(sscf->ssl.ctx, ngx_ja4_msg_cb);
        }
    }
    return NGX_OK;
}

/* ----------------------------------------------------------------------
 * Main conf
 * -------------------------------------------------------------------- */

static void *
ngx_http_ja4_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_ja4_main_conf_t *cnf =
        ngx_pcalloc(cf->pool, sizeof(ngx_http_ja4_main_conf_t));
    if (cnf == NULL) return NULL;
    cnf->bv_pow_valid_seconds = NGX_CONF_UNSET;
    cnf->bv_captcha_valid_seconds = NGX_CONF_UNSET;
    cnf->bv_pow_difficulty = NGX_CONF_UNSET;
    /* bv_secret left zero-init: empty ngx_str_t */
    return cnf;
}

static char *
ngx_http_ja4_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_ja4_main_conf_t *cnf = conf;
    if (cnf->bv_pow_valid_seconds == NGX_CONF_UNSET) {
        cnf->bv_pow_valid_seconds = 86400 * 3;
    }
    if (cnf->bv_captcha_valid_seconds == NGX_CONF_UNSET) {
        cnf->bv_captcha_valid_seconds = 86400 * 3;
    }
    if (cnf->bv_pow_difficulty == NGX_CONF_UNSET
        || cnf->bv_pow_difficulty < 8 || cnf->bv_pow_difficulty > 24) {
        cnf->bv_pow_difficulty = 18;
    }
    return NGX_CONF_OK;
}

/* Forward skew tolerance: a cookie whose issued_unix is up to this many
 * seconds ahead of ngx_time() is still accepted (= small clock drift between
 * the admin host that minted the cookie and the nginx host verifying it). */
#define UNMASK_BV_FUTURE_SKEW_SECONDS 60

/* ----------------------------------------------------------------------
 * $unmask_bv_valid: parse _bv cookie and verify HMAC-SHA1 signature.
 *
 * Cookie value form: "<day>.<sig16>.<kind>"
 *   sig16 = HMAC-SHA1("<day>:<remote_addr>:<host>:<kind>", BV_SECRET) hex[:16]
 *   (JA4 is NOT in the input -- it diverges across an LB; host binds the vhost.)
 *
 * Returns "1" if signature matches and day is within [today-bv_valid_days, today],
 * otherwise "0". Also returns "0" if bv_secret was not configured.
 * -------------------------------------------------------------------- */

/* Read decimal int from `s` (length n). Negative on parse failure. */
static int64_t
ngx_unmask_atoll(const u_char *s, size_t n)
{
    if (n == 0 || n > 19) return -1;
    int64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        if (s[i] < '0' || s[i] > '9') return -1;
        v = v * 10 + (s[i] - '0');
    }
    return v;
}

/* hex-encode a byte buffer into `dst` (must be 2*n bytes). */
static void
ngx_unmask_hex(char *dst, const unsigned char *src, size_t n)
{
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        dst[i*2]   = H[(src[i] >> 4) & 0xF];
        dst[i*2+1] = H[src[i] & 0xF];
    }
}

/* Constant-time memcmp wrapper. Returns 0 iff equal. */
static int
ngx_unmask_ct_memcmp(const void *a, const void *b, size_t n)
{
    return CRYPTO_memcmp(a, b, n);
}

/* base36 parse: accepts only [0-9a-zA-Z]. Returns -1 for n>13, empty,
 * invalid char, or overflow.  13 chars is the safe upper bound for an
 * int64 base36 value (= log36(2^63) ~ 12.27). */
static int64_t
ngx_unmask_base36(const u_char *s, size_t n)
{
    if (n == 0 || n > 13) return -1;
    int64_t v = 0;
    for (size_t i = 0; i < n; i++) {
        u_char c = s[i];
        int d;
        if (c >= '0' && c <= '9')      d = c - '0';
        else if (c >= 'a' && c <= 'z') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'Z') d = c - 'A' + 10;
        else return -1;
        /* overflow guard: pre-check that 36 * v + d <= INT64_MAX. */
        if (v > (INT64_MAX - d) / 36) return -1;
        v = v * 36 + d;
    }
    return v;
}

/* leading_zero_bits: count consecutive 0 bits starting from the MSB of
 * a byte sequence.  Matches challenge.js leadingZeroBits() and Go
 * cookies.leadingZeroBits(). */
static int
ngx_unmask_leading_zero_bits(const unsigned char *b, size_t n)
{
    int bits = 0;
    for (size_t i = 0; i < n; i++) {
        if (b[i] == 0) { bits += 8; continue; }
        unsigned char v = b[i];
        for (unsigned char mask = 0x80; mask != 0; mask >>= 1) {
            if (v & mask) return bits;
            bits++;
        }
        return bits;
    }
    return bits;
}

/* ngx_unmask_get_host: read nginx's built-in $host (lowercased + port-stripped)
 * for this request.  Folded into the _bv HMAC / PoW seed so a cookie minted on
 * vhost A fails verification on vhost B.  The admin issuer uses the same value
 * (X-Original-Host, which nginx sets from $host), keeping the two byte-identical.
 * Returns an empty string when $host is unavailable (= same as the admin's "").*/
static ngx_str_t
ngx_unmask_get_host(ngx_http_request_t *r)
{
    ngx_str_t out = ngx_null_string;
    static ngx_str_t host_var = ngx_string("host");
    ngx_uint_t hash = ngx_hash_key(host_var.data, host_var.len);
    ngx_http_variable_value_t *vv = ngx_http_get_variable(r, &host_var, hash);
    if (vv != NULL && !vv->not_found && vv->len > 0) {
        out.data = vv->data;
        out.len = vv->len;
    }
    return out;
}

/* verify_pow_sha256_cookie: v0.1+ SHA-256 hashcash format.
 *   format: "<issued_unix>.pow2.<nonce_b36>.<flags_b36>"  (= parts[1]="pow2" marker already detected)
 *   seed   = hex(HMAC-SHA1(bv_secret, "<issued_unix>:<remote>:<host>:pow_seed"))
 *   input  = seed + ":" + nonce_dec
 *   valid  = leading-zero-bits of SHA-256(input) >= difficulty
 * Bit-identical logic to challenge.js and Go cookies.verifyPowSHA256.
 * Returns 1 if valid, 0 otherwise. */
static int
ngx_unmask_verify_pow_sha256_cookie(const u_char *day_s, size_t day_n,
                                    const u_char *nonce_s, size_t nonce_n,
                                    int valid_seconds, int difficulty,
                                    ngx_str_t bv_secret, ngx_str_t remote,
                                    ngx_str_t host)
{
    if (nonce_n == 0 || nonce_n > 13) return 0;
    if (difficulty < 8 || difficulty > 32) difficulty = 18;

    int64_t cookie_unix = ngx_unmask_atoll(day_s, day_n);
    if (cookie_unix < 0) return 0;
    int64_t now = (int64_t)ngx_time();
    if (cookie_unix > now + UNMASK_BV_FUTURE_SKEW_SECONDS) return 0;
    if (now - cookie_unix > (int64_t)valid_seconds) return 0;

    int64_t nonce = ngx_unmask_base36(nonce_s, nonce_n);
    if (nonce < 0) return 0;

    /* seed = hex(HMAC-SHA1(bv_secret, "<issued_unix>:<remote>:pow_seed")).  MUST
     * stay byte-identical to cookies.PowSeed() (Go admin) and the value the
     * admin injects as window.UNMASK.pow_seed (challenge.js).  Binding the seed
     * to the secret makes the PoW impossible to precompute offline; binding it
     * to the client IP makes a solved cookie non-transferable across IPs. */
    /* "<unix>:<remote>:<host>:pow_seed".  host (= $host) can be a 253-char DNS
     * name, so size generously; snprintf truncation returns 0 (= fail closed). */
    char seed_msg[384];
    int sm = snprintf(seed_msg, sizeof(seed_msg), "%lld:%.*s:%.*s:pow_seed",
                      (long long)cookie_unix, (int)remote.len, remote.data,
                      (int)host.len, host.data);
    if (sm <= 0 || sm >= (int)sizeof(seed_msg)) return 0;
    unsigned char seed_mac[20];
    unsigned int seed_mac_len = sizeof(seed_mac);
    if (HMAC(EVP_sha1(), bv_secret.data, bv_secret.len,
             (const unsigned char *)seed_msg, (size_t)sm,
             seed_mac, &seed_mac_len) == NULL || seed_mac_len != 20) {
        return 0;
    }
    char seed_hex[41];
    ngx_unmask_hex(seed_hex, seed_mac, 20);
    seed_hex[40] = '\0';

    /* input = "<seed_hex(40)>:<nonce>".  Max = 40 + 1 + 19 = 60. */
    char input[80];
    int ilen = snprintf(input, sizeof(input), "%s:%lld",
                        seed_hex, (long long)nonce);
    if (ilen <= 0 || ilen >= (int)sizeof(input)) return 0;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)input, (size_t)ilen, hash);

    return ngx_unmask_leading_zero_bits(hash, SHA256_DIGEST_LENGTH) >= difficulty;
}

/* bv_kind: cookie-form determination plus verification result.
 *   UNMASK_BV_KIND_NONE    : not presented / malformed / verification failed
 *   UNMASK_BV_KIND_CAPTCHA : 3-segment HMAC verification OK (= CAPTCHA-passed repeat visitor)
 *   UNMASK_BV_KIND_POW     : 4-segment djb2 verification OK (= PoW-passed repeat visitor)
 *
 * Extending: when a future cookie path (= signature / webauthn / passkey
 * etc.) is added, just add an enum + decision branch + variable expose
 * and the dashboard aggregation will automatically treat the new kind
 * as one row (= unmask_cookie_minute is normalized on kind/cnt). */
typedef enum {
    UNMASK_BV_KIND_NONE    = 0,
    UNMASK_BV_KIND_CAPTCHA = 1,
    UNMASK_BV_KIND_POW     = 2,
} ngx_unmask_bv_kind_t;

/* Yield the next `_bv=value` pair in `header` starting at `*off`.  Used by
 * bv_kind_compute to iterate duplicate cookies — `ngx_http_parse_multi_header_lines`
 * only returns the first match, so a stale invalid `_bv` (= old cookie at a
 * different path shadowing the freshly-set one) would otherwise wedge the
 * caller into an endless challenge loop. */
static int
ngx_unmask_next_bv_value(ngx_str_t header, size_t *off, ngx_str_t *value)
{
    static const char NAME[] = "_bv";
    const size_t name_len = sizeof(NAME) - 1;

    while (*off < header.len) {
        /* Skip ' ', '\t', ';' separators between cookie pairs. */
        while (*off < header.len &&
               (header.data[*off] == ' ' || header.data[*off] == '\t' ||
                header.data[*off] == ';')) {
            (*off)++;
        }
        if (*off >= header.len) return 0;

        size_t name_start = *off;
        while (*off < header.len &&
               header.data[*off] != '=' && header.data[*off] != ';') {
            (*off)++;
        }
        size_t name_end = *off;
        int matched = (name_end - name_start == name_len) &&
            (ngx_strncmp(header.data + name_start, NAME, name_len) == 0);

        if (*off < header.len && header.data[*off] == '=') {
            (*off)++;
            size_t val_start = *off;
            while (*off < header.len && header.data[*off] != ';') (*off)++;
            size_t val_end = *off;
            if (matched) {
                value->data = header.data + val_start;
                value->len = val_end - val_start;
                return 1;
            }
        }
        /* No '=' (= bare name) or non-match: continue past ';'. */
    }
    return 0;
}

/* Verify a single `_bv` cookie value.  Returns the cookie kind on success
 * (POW / CAPTCHA) or NONE on parse / verify failure.  Called once per
 * candidate cookie by bv_kind_compute. */
static ngx_unmask_bv_kind_t
ngx_unmask_bv_verify_one(ngx_http_request_t *r,
                         ngx_http_ja4_main_conf_t *mcf,
                         ngx_str_t cookie)
{
    if (cookie.len < 4 || cookie.len > 80) {
        return UNMASK_BV_KIND_NONE;
    }

    /* Split: CAPTCHA path = "day.sig.kind" (3 seg); PoW path = "day.sig.target.flags" (4 seg). */
    u_char *dot1 = ngx_strlchr(cookie.data, cookie.data + cookie.len, '.');
    if (dot1 == NULL) return UNMASK_BV_KIND_NONE;
    u_char *dot2 = ngx_strlchr(dot1 + 1, cookie.data + cookie.len, '.');
    if (dot2 == NULL) return UNMASK_BV_KIND_NONE;
    u_char *dot3 = ngx_strlchr(dot2 + 1, cookie.data + cookie.len, '.');

    /* PoW path (4 seg): "day.sig.target.flags".  Issued client-side by
     * challenge.js after PoW passes.  No HMAC secret needed (= public
     * hash + verify).
     *
     * Supports two formats:
     *   parts[1]="pow2"  : SHA-256 hashcash (= v0.1+; challenge.js v0.1+)
     *   parts[1]=base36  : legacy djb2 (= v0.0 deprecated; expires in 1 cycle)
     * The server re-runs the same logic to decide. */
    if (dot3 != NULL) {
        size_t day_n = (size_t)(dot1 - cookie.data);
        size_t sig_n = (size_t)(dot2 - (dot1 + 1));
        size_t tgt_n = (size_t)(dot3 - (dot2 + 1));
        if (day_n == 0 || day_n > 10) return UNMASK_BV_KIND_NONE;
        if (sig_n == 0 || sig_n > 13) return UNMASK_BV_KIND_NONE;
        if (tgt_n == 0 || tgt_n > 13) return UNMASK_BV_KIND_NONE;

        int valid_seconds = (mcf->bv_pow_valid_seconds > 0)
            ? (int)mcf->bv_pow_valid_seconds : 86400 * 3;

        /* SHA-256 path detection: parts[1] == "pow2" (= 4 bytes) */
        if (sig_n == 4
            && (dot1 + 1)[0] == 'p' && (dot1 + 1)[1] == 'o'
            && (dot1 + 1)[2] == 'w' && (dot1 + 1)[3] == '2') {
            int difficulty = (int)mcf->bv_pow_difficulty;
            if (ngx_unmask_verify_pow_sha256_cookie(
                    cookie.data, day_n,
                    dot2 + 1, tgt_n,
                    valid_seconds, difficulty,
                    mcf->bv_secret, r->connection->addr_text,
                    ngx_unmask_get_host(r)) == 1) {
                return UNMASK_BV_KIND_POW;
            }
            return UNMASK_BV_KIND_NONE;
        }

        /* A 4-segment _bv that is NOT "pow2" is rejected.  The removed v0.0 djb2
         * fallback verified an UNKEYED checksum with no difficulty check, so an
         * attacker could mint a valid PoW cookie offline = full native-mode
         * bypass.  challenge.js only ever emits the pow2 form, so nothing legit
         * relied on it (no back-compat needed pre-GA). */
        return UNMASK_BV_KIND_NONE;
    }

    size_t day_len  = dot1 - cookie.data;
    size_t sig_len  = dot2 - (dot1 + 1);
    size_t kind_len = (cookie.data + cookie.len) - (dot2 + 1);

    if (day_len == 0 || day_len > 10) return UNMASK_BV_KIND_NONE;
    if (sig_len != 16) return UNMASK_BV_KIND_NONE;
    if (kind_len == 0 || kind_len > 32) return UNMASK_BV_KIND_NONE;

    int64_t cookie_unix = ngx_unmask_atoll(cookie.data, day_len);
    if (cookie_unix < 0) return NGX_OK;

    /* Validity window in seconds.  Small forward tolerance absorbs clock
     * drift between the admin host that issued the cookie and this nginx
     * host. */
    int64_t now = (int64_t)ngx_time();
    if (cookie_unix > now + UNMASK_BV_FUTURE_SKEW_SECONDS) return UNMASK_BV_KIND_NONE;
    if (now - cookie_unix > mcf->bv_captcha_valid_seconds) return UNMASK_BV_KIND_NONE;

    /* Read remote_addr.  After realip module application this is the
     * actual client IP even behind an upstream LB / proxy (= matches
     * admin-side clientIP()). */
    ngx_str_t remote = r->connection->addr_text;

    /* $host (lowercased + port-stripped) binds the cookie to the vhost: a cookie
     * minted while solving site A's challenge fails on site B (different host ->
     * different signature).  The admin issuer folds in the same value
     * (X-Original-Host = $host), so the two stay byte-identical.  This replaces
     * the old $unmask_site kind-suffix scheme, which the admin never emitted. */
    ngx_str_t host = ngx_unmask_get_host(r);

    /* Build "<day>:<remote>:<host>:<kind>" in a pool buffer.  JA4 is deliberately
     * NOT included (behind an LB the issuer's forwarded JA4 and the verifier's
     * handshake JA4 diverge); remote_ip + host binding carry the replay defense. */
    size_t msg_len = day_len + 1 + remote.len + 1 + host.len + 1 + kind_len;
    u_char *msg = ngx_pnalloc(r->pool, msg_len);
    if (msg == NULL) return UNMASK_BV_KIND_NONE;
    u_char *p = msg;
    p = ngx_cpymem(p, cookie.data, day_len);  *p++ = ':';
    p = ngx_cpymem(p, remote.data, remote.len); *p++ = ':';
    if (host.len) { p = ngx_cpymem(p, host.data, host.len); } *p++ = ':';
    p = ngx_cpymem(p, dot2 + 1, kind_len);

    /* HMAC-SHA1. */
    unsigned char mac[20];
    unsigned int mac_len = sizeof(mac);
    if (HMAC(EVP_sha1(),
             mcf->bv_secret.data, mcf->bv_secret.len,
             msg, msg_len,
             mac, &mac_len) == NULL || mac_len != 20) {
        return UNMASK_BV_KIND_NONE;
    }

    char expected[40];
    ngx_unmask_hex(expected, mac, 20);
    /* Compare first 16 hex chars (= 8 bytes of mac, but we compare hex). */
    if (ngx_unmask_ct_memcmp(expected, dot1 + 1, 16) == 0) {
        return UNMASK_BV_KIND_CAPTCHA;
    }
    return UNMASK_BV_KIND_NONE;
}

/* Verify a `_bv` cookie VALUE, which may be a "~"-joined list of up to
 * MaxBVEntries per-IP signatures (= a roaming client accumulates one per
 * network it solved on, so 5G<->wifi switching doesn't re-challenge).  Splits
 * on '~' and returns the first entry whose kind verifies for the current IP;
 * the per-entry 80-byte / format / HMAC / PoW checks live in verify_one.  Caps
 * inspected entries so an oversized hostile cookie can't force unbounded
 * hashing.  MUST mirror cookies.Verify's any-match in the Go package. */
static ngx_unmask_bv_kind_t
ngx_unmask_bv_verify_value(ngx_http_request_t *r,
                           ngx_http_ja4_main_conf_t *mcf,
                           ngx_str_t value)
{
    u_char *p   = value.data;
    u_char *end = value.data + value.len;
    int     n   = 0;

    while (p < end && n < 16) {
        u_char   *tilde = ngx_strlchr(p, end, '~');
        ngx_str_t entry;
        entry.data = p;
        entry.len  = (size_t)((tilde ? tilde : end) - p);
        ngx_unmask_bv_kind_t k = ngx_unmask_bv_verify_one(r, mcf, entry);
        if (k != UNMASK_BV_KIND_NONE) {
            return k;
        }
        if (tilde == NULL) break;
        p = tilde + 1;
        n++;
    }
    return UNMASK_BV_KIND_NONE;
}

/* Iterate every `_bv=...` pair the client sent (= across all Cookie header
 * lines).  Returns the first kind that verifies; NONE if none do.  The
 * iteration matters because browsers can carry multiple `_bv` cookies at
 * once (= stale entry at a different path / domain alongside the
 * freshly-set one), and stopping at the first match would lock such
 * visitors into a permanent challenge loop. */
static ngx_unmask_bv_kind_t
ngx_unmask_bv_kind_compute(ngx_http_request_t *r)
{
    ngx_http_ja4_main_conf_t *mcf =
        ngx_http_get_module_main_conf(r, ngx_http_unmask_module);
    if (mcf == NULL || mcf->bv_secret.len == 0) {
        return UNMASK_BV_KIND_NONE;
    }

#if (nginx_version >= 1023000)
    ngx_table_elt_t *elt = r->headers_in.cookie;
#else
    ngx_table_elt_t **cookie_elts = r->headers_in.cookies.elts;
    ngx_uint_t cookie_nelts = r->headers_in.cookies.nelts;
    ngx_uint_t cookie_idx = 0;
#endif

    for (;;) {
        ngx_str_t header;
#if (nginx_version >= 1023000)
        if (elt == NULL) break;
        header = elt->value;
        elt = elt->next;
#else
        if (cookie_idx >= cookie_nelts) break;
        header = cookie_elts[cookie_idx]->value;
        cookie_idx++;
#endif
        size_t off = 0;
        ngx_str_t cookie;
        while (ngx_unmask_next_bv_value(header, &off, &cookie)) {
            ngx_unmask_bv_kind_t k = ngx_unmask_bv_verify_value(r, mcf, cookie);
            if (k != UNMASK_BV_KIND_NONE) {
                return k;
            }
        }
    }
    return UNMASK_BV_KIND_NONE;
}

/* $unmask_bv_kind: expose kind as a string.  Use directly from log_format / map. */
static ngx_int_t
ngx_http_unmask_bv_kind_variable(ngx_http_request_t *r,
                                 ngx_http_variable_value_t *v,
                                 uintptr_t data)
{
    (void)data;
    static const u_char captcha[] = "captcha";
    static const u_char pow[]     = "pow";
    static const u_char empty[]   = "";

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    switch (ngx_unmask_bv_kind_compute(r)) {
    case UNMASK_BV_KIND_CAPTCHA:
        v->data = (u_char *)captcha;
        v->len  = sizeof(captcha) - 1;
        break;
    case UNMASK_BV_KIND_POW:
        v->data = (u_char *)pow;
        v->len  = sizeof(pow) - 1;
        break;
    default:
        v->data = (u_char *)empty;
        v->len  = 0;
        break;
    }
    return NGX_OK;
}

static ngx_int_t
ngx_unmask_bv_one_kind_variable(ngx_http_request_t *r,
                                ngx_http_variable_value_t *v,
                                ngx_unmask_bv_kind_t want)
{
    static const u_char zero[] = "0";
    static const u_char one[]  = "1";

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->len = 1;
    v->data = (ngx_unmask_bv_kind_compute(r) == want)
        ? (u_char *)one : (u_char *)zero;
    return NGX_OK;
}

static ngx_int_t
ngx_http_unmask_bv_captcha_valid_variable(ngx_http_request_t *r,
                                          ngx_http_variable_value_t *v,
                                          uintptr_t data)
{
    (void)data;
    return ngx_unmask_bv_one_kind_variable(r, v, UNMASK_BV_KIND_CAPTCHA);
}

static ngx_int_t
ngx_http_unmask_bv_pow_valid_variable(ngx_http_request_t *r,
                                      ngx_http_variable_value_t *v,
                                      uintptr_t data)
{
    (void)data;
    return ngx_unmask_bv_one_kind_variable(r, v, UNMASK_BV_KIND_POW);
}


/* ============================================================================
 * $unmask_banned / $unmask_ban_action: ban file lookup.
 *
 * file format example:
 *   # comments and blank lines OK
 *   192.0.2.10|t13d3515h2_8daaf6152771_xxx|honeypot|pow_then_captcha
 *   2001:db8::1|t13d1517h2_yyy_zzz|manual|deny
 *
 * Four pipe-separated fields per line: ip | ja4 | source | action.
 * Lines with only two fields (legacy ip|ja4) are treated as action="deny"
 * so an unmigrated file degrades safely.
 *
 * $unmask_banned is "1" on hit, "0" otherwise.
 * $unmask_ban_action is the action token on hit, "" otherwise -- the
 * server-block render switches on it (= return 403 vs rewrite challenge).
 *
 * mtime watch: each variable evaluation calls stat() and reloads if mtime changed.
 * stat() per request adds ~1-2us; small enough vs proxy_pass cost.
 * Sorted ASC by "ip|ja4"; lookup is bsearch O(log N).
 * ============================================================================ */

#include <sys/stat.h>

static int unmask_strcmp_ptr(const void *a, const void *b) {
    return strcmp(*(const char **)a, *(const char **)b);
}

/* free old buffers, parse new file content into sorted keys[] */
static int ngx_unmask_load_banlist(const char *path) {
    FILE *fp;
    long  size;
    char *buf;
    size_t cap = 0;

    if (path == NULL || *path == '\0') {
        return -1;
    }
    fp = fopen(path, "rb");
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) { fclose(fp); return -1; }
    size = ftell(fp);
    if (size < 0) { fclose(fp); return -1; }
    if (fseek(fp, 0, SEEK_SET) != 0) { fclose(fp); return -1; }
    buf = (char *)malloc((size_t)size + 1);
    if (!buf) { fclose(fp); return -1; }
    if (size > 0 && fread(buf, 1, (size_t)size, fp) != (size_t)size) {
        free(buf); fclose(fp); return -1;
    }
    buf[size] = '\0';
    fclose(fp);

    /* count newlines as upper bound */
    size_t maxk = 0;
    for (long i = 0; i < size; i++) if (buf[i] == '\n') maxk++;
    char **keys = (char **)malloc((maxk + 1) * sizeof(char *));
    if (!keys) { free(buf); return -1; }
    char **actions = (char **)malloc((maxk + 1) * sizeof(char *));
    if (!actions) { free(keys); free(buf); return -1; }
    cap = maxk;
    (void)cap;

    /* split by '\n' in-place */
    size_t nk = 0;
    char *p = buf;
    char *end = buf + size;
    while (p < end) {
        char *nl = (char *)memchr(p, '\n', (size_t)(end - p));
        char *ln_end = (nl != NULL) ? nl : end;
        /* trim trailing whitespace */
        while (ln_end > p && (ln_end[-1] == '\r' || ln_end[-1] == ' ' || ln_end[-1] == '\t')) ln_end--;
        /* trim leading whitespace */
        char *ln_start = p;
        while (ln_start < ln_end && (*ln_start == ' ' || *ln_start == '\t')) ln_start++;
        if (ln_start < ln_end && *ln_start != '#') {
            *ln_end = '\0';
            /* parse "ip|ja4|source|action".  Cut the line at the 2nd '|'
             * so keys[i] is the "ip|ja4" bsearch handle, then walk one
             * more '|' to reach the action field.  Two-field legacy
             * lines (= ip|ja4) flush as action="deny" (= safe default). */
            char *p1 = (char *)memchr(ln_start, '|', (size_t)(ln_end - ln_start));
            const char *act = "deny";
            if (p1 != NULL) {
                char *p2 = (char *)memchr(p1 + 1, '|', (size_t)(ln_end - (p1 + 1)));
                if (p2 != NULL) {
                    *p2 = '\0';
                    char *p3 = (char *)memchr(p2 + 1, '|', (size_t)(ln_end - (p2 + 1)));
                    if (p3 != NULL && p3 + 1 < ln_end) {
                        act = p3 + 1;
                    }
                }
            }
            keys[nk] = ln_start;
            actions[nk] = (char *)act;
            nk++;
        }
        if (nl == NULL) break;
        p = nl + 1;
    }
    /* sort ASC by key (= ip|ja4).  Keep actions[] aligned via an index
     * permutation so the parallel array tracks the sort. */
    {
        size_t *idx = (size_t *)malloc(nk * sizeof(size_t));
        if (idx) {
            for (size_t i = 0; i < nk; i++) idx[i] = i;
            /* simple insertion sort over idx -- nk is small for this
             * file (= thousands at most) and we avoid an extra qsort
             * trampoline.  For larger lists swap in a comparator-based
             * qsort over a {key,action} struct array. */
            for (size_t i = 1; i < nk; i++) {
                size_t cur = idx[i];
                size_t j = i;
                while (j > 0 && strcmp(keys[idx[j-1]], keys[cur]) > 0) {
                    idx[j] = idx[j-1];
                    j--;
                }
                idx[j] = cur;
            }
            char **sk = (char **)malloc(nk * sizeof(char *));
            char **sa = (char **)malloc(nk * sizeof(char *));
            if (sk && sa) {
                for (size_t i = 0; i < nk; i++) {
                    sk[i] = keys[idx[i]];
                    sa[i] = actions[idx[i]];
                }
                free(keys); free(actions);
                keys = sk; actions = sa;
            } else {
                free(sk); free(sa);
            }
            free(idx);
        } else {
            /* fall back to qsort on keys alone (= actions[] may end up
             * mis-aligned; better than leaving keys[] unsorted which
             * would break bsearch). */
            qsort(keys, nk, sizeof(char *), unmask_strcmp_ptr);
        }
    }

    /* swap into global */
    char *old_buf = ngx_unmask_banlist.buf;
    char **old_keys = ngx_unmask_banlist.keys;
    char **old_actions = ngx_unmask_banlist.actions;
    ngx_unmask_banlist.buf = buf;
    ngx_unmask_banlist.keys = keys;
    ngx_unmask_banlist.actions = actions;
    ngx_unmask_banlist.nkeys = nk;
    free(old_buf);
    free(old_keys);
    free(old_actions);
    return 0;
}

/* binary search for "<ip>|<ja4>" in sorted keys[].  On hit, returns 1
 * and (when action_out != NULL) hands back the parallel action slot. */
static int ngx_unmask_banlist_lookup(const char *key, const char **action_out) {
    if (action_out) *action_out = "";
    if (ngx_unmask_banlist.nkeys == 0) return 0;
    size_t lo = 0, hi = ngx_unmask_banlist.nkeys;
    while (lo < hi) {
        size_t mid = (lo + hi) / 2;
        int c = strcmp(ngx_unmask_banlist.keys[mid], key);
        if (c == 0) {
            if (action_out && ngx_unmask_banlist.actions) {
                *action_out = ngx_unmask_banlist.actions[mid];
            }
            return 1;
        }
        if (c < 0) lo = mid + 1; else hi = mid;
    }
    return 0;
}

static int ngx_unmask_banlist_has(const char *key) {
    return ngx_unmask_banlist_lookup(key, NULL);
}

/* lazy reload if mtime changed (= called per req but cheap stat()). */
static void ngx_unmask_maybe_reload_banlist(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) {
        /* file gone -> empty list */
        if (ngx_unmask_banlist.nkeys != 0) {
            free(ngx_unmask_banlist.buf);
            free(ngx_unmask_banlist.keys);
            free(ngx_unmask_banlist.actions);
            ngx_unmask_banlist.buf = NULL;
            ngx_unmask_banlist.keys = NULL;
            ngx_unmask_banlist.actions = NULL;
            ngx_unmask_banlist.nkeys = 0;
            ngx_unmask_banlist.mtime = 0;
        }
        return;
    }
    if (st.st_mtime == ngx_unmask_banlist.mtime) return;
    if (ngx_unmask_load_banlist(path) == 0) {
        ngx_unmask_banlist.mtime = st.st_mtime;
    }
}

static ngx_int_t ngx_http_unmask_banned_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    static const char zero[] = "0";
    static const char one[]  = "1";

    (void)data;
    v->len = 1;
    v->data = (u_char *)zero;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    ngx_http_ja4_main_conf_t *mcf = ngx_http_get_module_main_conf(r,
        ngx_http_unmask_module);
    if (!mcf || mcf->ban_file_path.len == 0) {
        return NGX_OK;
    }

    /* Make a NUL-terminated path (= ngx_str_t is not NUL-terminated). */
    char path[1024];
    if (mcf->ban_file_path.len >= sizeof(path)) return NGX_OK;
    ngx_memcpy(path, mcf->ban_file_path.data, mcf->ban_file_path.len);
    path[mcf->ban_file_path.len] = '\0';

    ngx_unmask_maybe_reload_banlist(path);
    if (ngx_unmask_banlist.nkeys == 0) return NGX_OK;

    /* Build key = "<remote_addr>|<client_ja4>".  ja4 is per-request via context. */
    const u_char *ip = r->connection->addr_text.data;
    size_t iplen = r->connection->addr_text.len;
    if (iplen == 0 || iplen > 80) return NGX_OK;

    /* fetch ja4 string (= same pattern as $unmask_bv_valid). */
    u_char *ja4_data = (u_char *)"";
    size_t  ja4_len  = 0;
    if (r->connection && r->connection->ssl) {
        SSL *ssl_obj = r->connection->ssl->connection;
        if (ssl_obj && ngx_http_ja4_ssl_ex_data_idx >= 0) {
            ngx_http_ja4_ctx_t *jctx = SSL_get_ex_data(
                ssl_obj, ngx_http_ja4_ssl_ex_data_idx);
            if (jctx && jctx->ja4.len > 0) {
                ja4_data = jctx->ja4.data;
                ja4_len  = jctx->ja4.len;
            }
        }
    }

    char key[256];
    if (iplen + 1 + ja4_len + 1 > sizeof(key)) return NGX_OK;
    ngx_memcpy(key, ip, iplen);
    key[iplen] = '|';
    if (ja4_len) ngx_memcpy(key + iplen + 1, ja4_data, ja4_len);
    key[iplen + 1 + ja4_len] = '\0';

    if (ngx_unmask_banlist_has(key)) {
        v->len = 1;
        v->data = (u_char *)one;
        return NGX_OK;
    }

    /* JA4-only entries (= scope=ja4_only) are stored as keys of the form
     * "|<ja4>" in the ban file.  Pass 2 retries with this shape so a
     * single (ip="", ja4=X) row bans every visitor with that fingerprint
     * regardless of source IP. */
    if (ja4_len > 0 && 1 + ja4_len + 1 <= sizeof(key)) {
        key[0] = '|';
        ngx_memcpy(key + 1, ja4_data, ja4_len);
        key[1 + ja4_len] = '\0';
        if (ngx_unmask_banlist_has(key)) {
            v->len = 1;
            v->data = (u_char *)one;
            return NGX_OK;
        }
    }

    /* IP-only entries (= scope=ip_only) are stored as keys "<ip>|" with an
     * empty JA4 column.  Pass 3 retries with this shape so a single
     * (ip=X, ja4="") row bans every visitor from that IP regardless of
     * which JA4 fingerprint they present (= compromised host / scraper
     * farm across changing TLS stacks). */
    if (iplen + 1 + 1 <= sizeof(key)) {
        ngx_memcpy(key, ip, iplen);
        key[iplen] = '|';
        key[iplen + 1] = '\0';
        if (ngx_unmask_banlist_has(key)) {
            v->len = 1;
            v->data = (u_char *)one;
        }
    }
    return NGX_OK;
}

/* $unmask_ban_action: returns the per-row action token on hit
 * (= "deny" / "pow_only" / "pow_then_captcha" / "captcha_only") so the
 * server-block render can switch the response (= return 403 vs rewrite
 * to /unmask/challenge/).  Empty string when not banned. */
static ngx_int_t ngx_http_unmask_ban_action_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    static const char empty[] = "";

    (void)data;
    v->len = 0;
    v->data = (u_char *)empty;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    ngx_http_ja4_main_conf_t *mcf = ngx_http_get_module_main_conf(r,
        ngx_http_unmask_module);
    if (!mcf || mcf->ban_file_path.len == 0) {
        return NGX_OK;
    }

    char path[1024];
    if (mcf->ban_file_path.len >= sizeof(path)) return NGX_OK;
    ngx_memcpy(path, mcf->ban_file_path.data, mcf->ban_file_path.len);
    path[mcf->ban_file_path.len] = '\0';

    ngx_unmask_maybe_reload_banlist(path);
    if (ngx_unmask_banlist.nkeys == 0) return NGX_OK;

    const u_char *ip = r->connection->addr_text.data;
    size_t iplen = r->connection->addr_text.len;
    if (iplen == 0 || iplen > 80) return NGX_OK;

    u_char *ja4_data = (u_char *)"";
    size_t  ja4_len  = 0;
    if (r->connection && r->connection->ssl) {
        SSL *ssl_obj = r->connection->ssl->connection;
        if (ssl_obj && ngx_http_ja4_ssl_ex_data_idx >= 0) {
            ngx_http_ja4_ctx_t *jctx = SSL_get_ex_data(
                ssl_obj, ngx_http_ja4_ssl_ex_data_idx);
            if (jctx && jctx->ja4.len > 0) {
                ja4_data = jctx->ja4.data;
                ja4_len  = jctx->ja4.len;
            }
        }
    }

    char key[256];
    if (iplen + 1 + ja4_len + 1 > sizeof(key)) return NGX_OK;
    ngx_memcpy(key, ip, iplen);
    key[iplen] = '|';
    if (ja4_len) ngx_memcpy(key + iplen + 1, ja4_data, ja4_len);
    key[iplen + 1 + ja4_len] = '\0';

    const char *action = "";
    int hit = ngx_unmask_banlist_lookup(key, &action);
    if (!hit && ja4_len > 0 && 1 + ja4_len + 1 <= sizeof(key)) {
        /* JA4-only fallback "|<ja4>" -- mirrors ngx_http_unmask_banned_variable. */
        key[0] = '|';
        ngx_memcpy(key + 1, ja4_data, ja4_len);
        key[1 + ja4_len] = '\0';
        hit = ngx_unmask_banlist_lookup(key, &action);
    }
    if (!hit && iplen + 1 + 1 <= sizeof(key)) {
        /* IP-only fallback "<ip>|" -- bans every JA4 from this source IP. */
        ngx_memcpy(key, ip, iplen);
        key[iplen] = '|';
        key[iplen + 1] = '\0';
        hit = ngx_unmask_banlist_lookup(key, &action);
    }
    if (hit && action && *action) {
        size_t alen = strlen(action);
        u_char *p = ngx_pnalloc(r->pool, alen);
        if (!p) return NGX_OK;
        ngx_memcpy(p, (const u_char *)action, alen);
        v->data = p;
        v->len = alen;
    }
    return NGX_OK;
}

/* unmask_has_signed_agent: walk the inbound headers for "Signature-Input".
 * Returns "1" when present (non-empty), "0" otherwise.  Header name match
 * is case-insensitive per HTTP, so we use ngx_strncasecmp.  No allocation
 * on the hot path -- the two output strings are static. */
static ngx_int_t
ngx_http_unmask_has_signed_agent_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    static u_char zero[] = "0";
    static u_char one[]  = "1";
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;
    ngx_uint_t        i;

    (void) data;

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = zero;
    v->len = 1;

    part = &r->headers_in.headers.part;
    h = part->elts;
    for (i = 0; ; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }
            part = part->next;
            h = part->elts;
            i = 0;
        }
        if (h[i].key.len == sizeof("Signature-Input") - 1
            && ngx_strncasecmp(h[i].key.data,
                               (u_char *) "Signature-Input",
                               sizeof("Signature-Input") - 1) == 0
            && h[i].value.len > 0) {
            v->data = one;
            v->len = 1;
            return NGX_OK;
        }
    }
    return NGX_OK;
}
