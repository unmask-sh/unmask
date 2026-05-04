/*
 * ngx_http_ja4_module: nginx dynamic module that exposes:
 *
 *   $client_ja4         - JA4 fingerprint computed from TLS ClientHello
 *   $unmask_bv_valid    - "1" if the request's _bv cookie HMAC matches and
 *                         is within the validity window, else "0".
 *
 * License: Apache 2.0 (clean-room implementation from JA4 specification)
 * Reference: https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md
 *
 * JA4 format: <a>_<b>_<c>
 *   a (10 chars): protocol(t/q) + tlsver(2) + sni(d/i) + ciphers(2) + extensions(2) + alpn(2)
 *   b (12 chars): SHA256(sorted hex cipher list)[:12]
 *   c (12 chars): SHA256(sorted hex extensions, then signature_algorithms appended)[:12]
 *
 * BV cookie format: "<day>.<sig>.<kind>"
 *   day  = floor(unix / 86400) as decimal string
 *   sig  = HMAC-SHA1("<day>:<remote_addr>:<client_ja4>:<kind>", BV_SECRET) hex[:16]
 *   kind = free-form ASCII (e.g. "captcha")
 *
 * Configuration:
 *   unmask_bv_secret <secret>;        # HTTP main scope. shared with admin app.
 *   unmask_bv_valid_days <int>;       # default 3
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_event_openssl.h>
#include <ngx_http_ssl_module.h>

#include <openssl/ssl.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#define NGX_JA4_MAX 64

/* Per-connection JA4 storage */
typedef struct {
    ngx_str_t  ja4;       /* full string e.g. t13d1517h2_8daaf6152771_b0da82dd1658 */
} ngx_http_ja4_ctx_t;

/* ex_data index for storing JA4 string on SSL object */
static int ngx_http_ja4_ssl_ex_data_idx = -1;

/* Per-http main config: shared BV secret for $unmask_bv_valid */
typedef struct {
    ngx_str_t   bv_secret;
    ngx_int_t   bv_valid_days;
} ngx_http_ja4_main_conf_t;

static ngx_int_t ngx_http_ja4_init(ngx_conf_t *cf);
static void *ngx_http_ja4_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_ja4_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_ja4_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_unmask_bv_valid_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_command_t ngx_http_ja4_commands[] = {
    { ngx_string("unmask_bv_secret"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_ja4_main_conf_t, bv_secret),
      NULL },
    { ngx_string("unmask_bv_valid_days"),
      NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_ja4_main_conf_t, bv_valid_days),
      NULL },
    ngx_null_command
};

static ngx_http_module_t ngx_http_ja4_module_ctx = {
    NULL,                              /* preconfiguration */
    ngx_http_ja4_init,                 /* postconfiguration */
    ngx_http_ja4_create_main_conf,     /* create main configuration */
    ngx_http_ja4_init_main_conf,       /* init main configuration */
    NULL, NULL, NULL, NULL
};

ngx_module_t ngx_http_ja4_module = {
    NGX_MODULE_V1,
    &ngx_http_ja4_module_ctx,
    ngx_http_ja4_commands,
    NGX_HTTP_MODULE,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL,
    NGX_MODULE_V1_PADDING
};

static ngx_http_variable_t ngx_http_ja4_vars[] = {
    { ngx_string("client_ja4"), NULL, ngx_http_ja4_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
    { ngx_string("unmask_bv_valid"), NULL, ngx_http_unmask_bv_valid_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
    ngx_http_null_variable
};

/* GREASE values that JA4 spec says to ignore. */
static int ngx_ja4_is_grease(unsigned int v) {
    /* GREASE pattern: 0x?A0A where ? is any hex digit, both bytes 0x?A */
    return ((v & 0x0F0F) == 0x0A0A) && (((v >> 4) & 0x0F) == ((v >> 12) & 0x0F));
}

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

/* SHA256(hex) → first 12 hex chars */
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
 * client_hello_cb: called by OpenSSL during TLS handshake before any reply.
 * We parse the raw extension data here because OpenSSL exposes it via
 * SSL_client_hello_get0_*() APIs (1.1.1+).
 */
static int ngx_ja4_client_hello_cb(SSL *ssl, int *al, void *arg) {
    ngx_http_ja4_ctx_t *ctx;
    (void)al; (void)arg;

    /* Allocate ctx */
    ctx = OPENSSL_malloc(sizeof(*ctx));
    if (!ctx) return SSL_CLIENT_HELLO_SUCCESS;
    ngx_memzero(ctx, sizeof(*ctx));

    /* TLS version (legacy_version field, e.g. 0x0303 = TLS 1.2). The "real"
     * version is in the supported_versions extension (43). Spec says use
     * highest TLS version from supported_versions if present, else legacy. */
    int tlsver = SSL_client_hello_get0_legacy_version(ssl);

    /* SNI: extension 0 present + has any name */
    int has_sni_domain = 0;

    /* ALPN: extension 16, take first protocol's first+last char */
    char alpn_first = '0', alpn_last = '0';

    /* Parse cipher suites */
    const unsigned char *ciphers_p = NULL;
    size_t ciphers_len = SSL_client_hello_get0_ciphers(ssl, &ciphers_p);
    unsigned int ciphers[256];
    int ncipher = 0;
    for (size_t i = 0; i + 1 < ciphers_len && ncipher < 256; i += 2) {
        unsigned int c = (ciphers_p[i] << 8) | ciphers_p[i+1];
        if (ngx_ja4_is_grease(c)) continue;
        ciphers[ncipher++] = c;
    }

    /* Parse extensions list: collect ext IDs (skip GREASE), find SNI/ALPN/sig_algs/supported_versions */
    int *extlist = NULL;
    size_t extlist_len = 0;
    if (SSL_client_hello_get1_extensions_present(ssl, &extlist, &extlist_len) != 1) {
        extlist = NULL; extlist_len = 0;
    }
    unsigned int exts[256];
    int nexts = 0;
    int has_sig_algs = 0;
    for (size_t i = 0; i < extlist_len && nexts < 256; i++) {
        unsigned int e = (unsigned int)extlist[i];
        if (ngx_ja4_is_grease(e)) continue;
        /* JA4 spec: exclude SNI(0x00) and ALPN(0x10) from ext-list hash. But
         * we still count them for the count field. */
        exts[nexts++] = e;
        if (e == 13) has_sig_algs = 1;
    }
    if (extlist) OPENSSL_free(extlist);

    /* Pull SNI extension data */
    const unsigned char *ext_data;
    size_t ext_dlen;
    if (SSL_client_hello_get0_ext(ssl, 0 /*SNI*/, &ext_data, &ext_dlen) == 1) {
        /* Detect at least one server_name (type 0 = host_name) */
        if (ext_dlen >= 5) {
            /* skip 2-byte server_name_list length */
            const unsigned char *p = ext_data + 2;
            if (ext_dlen >= 7 && p[0] == 0) {
                has_sni_domain = 1;
            }
        }
    }

    /* Pull ALPN: list of length-prefixed protos */
    if (SSL_client_hello_get0_ext(ssl, 16 /*ALPN*/, &ext_data, &ext_dlen) == 1
        && ext_dlen >= 3) {
        unsigned int list_len = (ext_data[0] << 8) | ext_data[1];
        if (list_len + 2 <= ext_dlen) {
            unsigned int proto_len = ext_data[2];
            if (proto_len >= 1 && (proto_len + 3) <= ext_dlen) {
                const unsigned char *proto = ext_data + 3;
                alpn_first = proto[0];
                alpn_last  = proto[proto_len - 1];
            }
        }
    }

    /* Pull supported_versions (43) for real TLS version */
    if (SSL_client_hello_get0_ext(ssl, 43, &ext_data, &ext_dlen) == 1
        && ext_dlen >= 3) {
        unsigned int sv_len = ext_data[0];
        const unsigned char *p = ext_data + 1;
        unsigned int max = 0;
        for (size_t i = 0; i + 1 < sv_len && (i + 1 + 1) < ext_dlen; i += 2) {
            unsigned int sv = (p[i] << 8) | p[i+1];
            if (ngx_ja4_is_grease(sv)) continue;
            if (sv > max) max = sv;
        }
        if (max != 0) tlsver = max;
    }

    /* Map TLS version to 2-char code */
    char tlscode[3];
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

    /* === Build JA4_a (10 chars) === */
    char ja4_a[16];
    int n_a;
    int cipher_count_disp = ncipher > 99 ? 99 : ncipher;
    int ext_count_disp    = nexts   > 99 ? 99 : nexts;
    n_a = ngx_snprintf((u_char *)ja4_a, sizeof(ja4_a), "t%s%c%02d%02d%c%c",
                       tlscode,
                       has_sni_domain ? 'd' : 'i',
                       cipher_count_disp,
                       ext_count_disp,
                       alpn_first, alpn_last) - (u_char *)ja4_a;

    /* === Build JA4_b: sorted ciphers as hex, comma-joined === */
    char buf[2048];
    char *bp = buf;
    if (ncipher > 0) {
        unsigned int sorted[256];
        ngx_memcpy(sorted, ciphers, ncipher * sizeof(unsigned int));
        qsort(sorted, ncipher, sizeof(unsigned int), u16_cmp);
        for (int i = 0; i < ncipher; i++) {
            if (i) *bp++ = ',';
            ngx_ja4_hex4(bp, sorted[i]);
            bp += 4;
        }
    }
    char ja4_b[13];
    ngx_ja4_sha12(buf, bp - buf, ja4_b);
    ja4_b[12] = '\0';

    /* === Build JA4_c: sorted exts (excl SNI=0, ALPN=16) hex, comma-joined,
     * then "_" + signature_algorithms (TLS ext 13) raw values comma-joined === */
    bp = buf;
    int nexts_c = 0;
    unsigned int sorted_e[256];
    for (int i = 0; i < nexts; i++) {
        if (exts[i] == 0 || exts[i] == 16) continue;
        sorted_e[nexts_c++] = exts[i];
    }
    qsort(sorted_e, nexts_c, sizeof(unsigned int), u16_cmp);
    for (int i = 0; i < nexts_c; i++) {
        if (i) *bp++ = ',';
        ngx_ja4_hex4(bp, sorted_e[i]);
        bp += 4;
    }
    /* Append signature_algorithms list: "_" then 16-bit IDs as hex,
     * IN ORIGINAL ORDER per JA4 spec. */
    if (has_sig_algs &&
        SSL_client_hello_get0_ext(ssl, 13, &ext_data, &ext_dlen) == 1
        && ext_dlen >= 2) {
        unsigned int sa_len = (ext_data[0] << 8) | ext_data[1];
        if (sa_len + 2 <= ext_dlen) {
            *bp++ = '_';
            const unsigned char *p = ext_data + 2;
            int first = 1;
            for (size_t i = 0; i + 1 < sa_len; i += 2) {
                unsigned int sa = (p[i] << 8) | p[i+1];
                if (ngx_ja4_is_grease(sa)) continue;
                if (!first) *bp++ = ',';
                first = 0;
                ngx_ja4_hex4(bp, sa);
                bp += 4;
            }
        }
    }
    char ja4_c[13];
    ngx_ja4_sha12(buf, bp - buf, ja4_c);
    ja4_c[12] = '\0';

    /* === Final JA4 string === */
    char *out = OPENSSL_malloc(NGX_JA4_MAX);
    if (!out) {
        OPENSSL_free(ctx);
        return SSL_CLIENT_HELLO_SUCCESS;
    }
    int outlen = ngx_snprintf((u_char *)out, NGX_JA4_MAX, "%*s_%s_%s",
                              n_a, ja4_a, ja4_b, ja4_c) - (u_char *)out;
    ctx->ja4.data = (u_char *)out;
    ctx->ja4.len  = outlen;

    /* Stash on SSL object via ex_data */
    if (ngx_http_ja4_ssl_ex_data_idx >= 0) {
        SSL_set_ex_data(ssl, ngx_http_ja4_ssl_ex_data_idx, ctx);
    }

    return SSL_CLIENT_HELLO_SUCCESS;
}

/* Free callback for ex_data */
static void ngx_ja4_ssl_free_cb(void *parent, void *ptr, CRYPTO_EX_DATA *ad,
                                int idx, long argl, void *argp) {
    ngx_http_ja4_ctx_t *ctx = ptr;
    if (!ctx) return;
    if (ctx->ja4.data) OPENSSL_free(ctx->ja4.data);
    OPENSSL_free(ctx);
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

    /* Hook all SSL_CTX created by the http_ssl module to call our cb. We do
     * this by walking the http core srv_conf list at this stage and patching
     * each SSL_CTX. Simpler: install via http_ssl postconfiguration is not
     * directly accessible from another module, so we use a bind-time trick:
     * register a server-rewrite phase handler that sets the cb on first
     * request? Better: walk the ssl module config tree. */
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
            SSL_CTX_set_client_hello_cb(sscf->ssl.ctx,
                                        ngx_ja4_client_hello_cb, NULL);
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
    cnf->bv_valid_days = NGX_CONF_UNSET;
    /* bv_secret left zero-init: empty ngx_str_t */
    return cnf;
}

static char *
ngx_http_ja4_init_main_conf(ngx_conf_t *cf, void *conf)
{
    ngx_http_ja4_main_conf_t *cnf = conf;
    if (cnf->bv_valid_days == NGX_CONF_UNSET) {
        cnf->bv_valid_days = 3;
    }
    return NGX_CONF_OK;
}

/* ----------------------------------------------------------------------
 * $unmask_bv_valid: parse _bv cookie and verify HMAC-SHA1 signature.
 *
 * Cookie value form: "<day>.<sig16>.<kind>"
 *   sig16 = HMAC-SHA1("<day>:<remote_addr>:<client_ja4>:<kind>", BV_SECRET)
 *           hex[:16]
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

/* Find _bv cookie value. Sets `out` to the value bytes (within r pool space)
 * and returns NGX_OK; returns NGX_DECLINED if not present. */
static ngx_int_t
ngx_unmask_get_bv_cookie(ngx_http_request_t *r, ngx_str_t *out)
{
    static ngx_str_t name = ngx_string("_bv");
#if (nginx_version >= 1023000)
    ngx_table_elt_t *elt = ngx_http_parse_multi_header_lines(r, r->headers_in.cookie, &name, out);
    if (elt == NULL) return NGX_DECLINED;
#else
    if (ngx_http_parse_multi_header_lines(&r->headers_in.cookies, &name, out) == NGX_DECLINED) {
        return NGX_DECLINED;
    }
#endif
    return NGX_OK;
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

static ngx_int_t
ngx_http_unmask_bv_valid_variable(ngx_http_request_t *r,
                                  ngx_http_variable_value_t *v,
                                  uintptr_t data)
{
    (void)data;

    static const u_char zero[] = "0";
    static const u_char one[]  = "1";

    /* Default: 0 (= invalid). */
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->len = 1;
    v->data = (u_char *)zero;

    ngx_http_ja4_main_conf_t *mcf =
        ngx_http_get_module_main_conf(r, ngx_http_ja4_module);
    if (mcf == NULL || mcf->bv_secret.len == 0) {
        return NGX_OK;
    }

    /* Read cookie. */
    ngx_str_t cookie;
    if (ngx_unmask_get_bv_cookie(r, &cookie) != NGX_OK) {
        return NGX_OK;
    }
    if (cookie.len < 4 || cookie.len > 80) {
        return NGX_OK;
    }

    /* Split "day.sig.kind". */
    u_char *dot1 = ngx_strlchr(cookie.data, cookie.data + cookie.len, '.');
    if (dot1 == NULL) return NGX_OK;
    u_char *dot2 = ngx_strlchr(dot1 + 1, cookie.data + cookie.len, '.');
    if (dot2 == NULL) return NGX_OK;

    size_t day_len  = dot1 - cookie.data;
    size_t sig_len  = dot2 - (dot1 + 1);
    size_t kind_len = (cookie.data + cookie.len) - (dot2 + 1);

    if (day_len == 0 || day_len > 10) return NGX_OK;
    if (sig_len != 16) return NGX_OK;
    if (kind_len == 0 || kind_len > 32) return NGX_OK;

    int64_t cookie_day = ngx_unmask_atoll(cookie.data, day_len);
    if (cookie_day < 0) return NGX_OK;

    /* Validity window. */
    int64_t today = (int64_t)(ngx_time() / 86400);
    if (cookie_day > today) return NGX_OK;
    if (today - cookie_day > mcf->bv_valid_days) return NGX_OK;

    /* Read remote_addr and client_ja4 ($effective_ja4 might not be available
     * here — we use $client_ja4 only). */
    ngx_str_t remote = r->connection->addr_text;

    /* Get $client_ja4 from SSL ex_data. If TLS not present, ja4="" — that
     * still matches admin-issued cookies for non-TLS test clients, but in
     * production every challenge target should be TLS. */
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

    /* Build "<day>:<remote>:<ja4>:<kind>" in a pool buffer. */
    size_t msg_len = day_len + 1 + remote.len + 1 + ja4_len + 1 + kind_len;
    u_char *msg = ngx_pnalloc(r->pool, msg_len);
    if (msg == NULL) return NGX_OK;
    u_char *p = msg;
    p = ngx_cpymem(p, cookie.data, day_len);  *p++ = ':';
    p = ngx_cpymem(p, remote.data, remote.len); *p++ = ':';
    p = ngx_cpymem(p, ja4_data, ja4_len); *p++ = ':';
    p = ngx_cpymem(p, dot2 + 1, kind_len);

    /* HMAC-SHA1. */
    unsigned char mac[20];
    unsigned int mac_len = sizeof(mac);
    if (HMAC(EVP_sha1(),
             mcf->bv_secret.data, mcf->bv_secret.len,
             msg, msg_len,
             mac, &mac_len) == NULL || mac_len != 20) {
        return NGX_OK;
    }

    char expected[40];
    ngx_unmask_hex(expected, mac, 20);
    /* Compare first 16 hex chars (= 8 bytes of mac, but we compare hex). */
    if (ngx_unmask_ct_memcmp(expected, dot1 + 1, 16) == 0) {
        v->len = 1;
        v->data = (u_char *)one;
    }
    return NGX_OK;
}
