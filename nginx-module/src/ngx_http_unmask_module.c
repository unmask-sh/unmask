/*
 * ngx_http_unmask_module: nginx dynamic module that exposes:
 *
 *   $client_ja4         - JA4 fingerprint computed from TLS ClientHello
 *   $unmask_bv_kind     - the kind of the request's valid _bv cookie ("" when
 *                         none verifies); $unmask_bv_pow_valid /
 *                         $unmask_bv_captcha_valid ("1"/"0") derive from it.
 *   $unmask_bv_id       - the identity of the pass that verified (16 hex: a
 *                         CAPTCHA-form entry's signature, or the seed a
 *                         proof-of-work answers), "" when none did.
 *   $unmask_module_id   - the module file this nginx loaded, by content hash
 *                         (16 hex), so the daemon can tell from the access
 *                         log that a newer file waits for a restart.
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
 *   sig         = HMAC("<issued_unix>:<remote_addr>:<host>:<kind>", BV_SECRET) hex[:16]
 *                 (HMAC-SHA256 or HMAC-SHA1: ngx_unmask_sig_hashes)
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
#include <dlfcn.h>

#include "ja4_parser.h"
#include "bv_parser.h"
#include "ja4_build.h"

#define NGX_JA4_MAX 64

/* Per-connection JA4 storage.
 *
 * The ctx is allocated from the connection's pool and hangs off the SSL
 * object through an ex_data slot.  nginx frees the SSL object (ngx_ssl_shutdown)
 * before it destroys the connection pool, so the slot is registered with NO
 * callbacks: a free callback would live in this module's text, and OpenSSL
 * keeps a registered callback for the life of the process and calls it on
 * every SSL_free -- after a reload that dropped load_module (the package's
 * own removal advice) the pointer would dangle and every new worker would
 * crash on its first TLS close.  The JA4 string lives in a fixed buffer
 * inside the ctx, so nothing is ever freed by hand. */
typedef struct {
    u_char     ja4_buf[NGX_JA4_MAX]; /* full string; ngx_str_t.data points here */
    ngx_str_t  ja4;                  /* {data: ja4_buf, len: measured value}.  data is never freed */
} ngx_http_ja4_ctx_t;

/* ex_data index for storing the JA4 ctx on the SSL object.  Registered once
 * per process (OpenSSL never unregisters an index); the static resets only
 * when the module is mapped afresh, which registers a new, equally
 * callback-free index. */
static int ngx_http_ja4_ssl_ex_data_idx = -1;

/* Rate-limited error_log line: at most one per message slot per minute per
 * worker.  The module used to say nothing at all -- a ban file nginx could
 * not read silently banned nobody, an empty secret silently rejected every
 * cookie -- and a per-request line would flood the log the moment either
 * happened.  Slots are small integers chosen by the caller. */
#define UNMASK_LOG_SLOTS 8
static time_t ngx_unmask_log_last[UNMASK_LOG_SLOTS];

static int
ngx_unmask_log_due(int slot)
{
    time_t now;
    if (slot < 0 || slot >= UNMASK_LOG_SLOTS) {
        return 1;
    }
    now = ngx_time();
    if (ngx_unmask_log_last[slot] != 0 && now - ngx_unmask_log_last[slot] < 60) {
        return 0;
    }
    ngx_unmask_log_last[slot] = now;
    return 1;
}

enum {
    UNMASK_LOG_SECRET_EMPTY = 0,
    UNMASK_LOG_BAN_STAT,
    UNMASK_LOG_BAN_LOAD,
    UNMASK_LOG_JA4_PARSE,
    UNMASK_LOG_JA4_ALLOC,
    UNMASK_LOG_BAN_MISSING,
    UNMASK_LOG_H3_NOJA4,
    UNMASK_LOG_TLS_NOJA4
};

/* Per-http main config: shared BV secret for the _bv cookie variables */
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
    /* Index of $unmask_bind_key (set in ngx_http_ja4_init; NGX_ERROR when the
     * variable could not be registered).  See ngx_unmask_bind_key. */
    ngx_int_t   bind_key_index;
} ngx_http_ja4_main_conf_t;

/* ban list entry: "<ip>|<ja4>|<source>|<action>" sorted ASC by the ip|ja4
 * prefix for binary search.  worker scope (= re-loaded on mtime change).
 * keys[i] points at "ip|ja4" (= NUL-terminated in-place where '|' before
 * source used to be).  actions[i] points at the action token after that
 * NUL ("deny" / "pow_only" / "pow_then_captcha" / "captcha_only"). */
/* A prefix ban: an ip-only line whose address carries a /len (the daemon's
 * /64 escalation of IPv6 bans; an operator's CIDR).  Kept apart from the
 * exact keys and matched after them, so a more specific line wins. */
typedef struct {
    ngx_cidr_t  cidr;
    char       *action;
} ngx_unmask_ban_cidr_t;

typedef struct {
    char    *buf;       /* malloc'd, contains keys + NULs */
    char   **keys;      /* pointers into buf */
    char   **actions;   /* parallel array, same length as keys */
    size_t   nkeys;
    ngx_unmask_ban_cidr_t *cidrs;   /* prefix rows, in file order */
    size_t   ncidrs;
    /* Identity of the file last loaded, to skip reloads.  mtime alone is a
     * whole second, and the admin flushes the file on every ban it places
     * (tmp + rename, so a new inode each time): two bans in the same second
     * left the second one unapplied until some later write landed in a
     * different second.  Size and inode tell those apart. */
    time_t   mtime;
    off_t    size;
    ino_t    ino;
} ngx_unmask_banlist_t;

/* per-worker ban list. Reloaded lazily on every variable evaluation if mtime changed. */
/* gcc 4.4 (= CentOS 6) warns on `= {0}` with a missing-initializer.
   The C standard zero-initializes static storage, so no explicit init
   is needed. */
static ngx_unmask_banlist_t ngx_unmask_banlist;

static ngx_int_t ngx_http_ja4_init(ngx_conf_t *cf);
static ngx_int_t ngx_http_unmask_init_process(ngx_cycle_t *cycle);
static void *ngx_http_ja4_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_ja4_init_main_conf(ngx_conf_t *cf, void *conf);
static ngx_int_t ngx_http_ja4_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_unmask_bv_kind_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_unmask_bv_id_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_unmask_module_id_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static void ngx_unmask_module_id_compute(void);
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
static ngx_int_t ngx_http_unmask_client_net_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_unmask_compose_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_unmask_bind_key_variable(ngx_http_request_t *r,
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
    NULL,                              /* init master */
    NULL,                              /* init module */
    ngx_http_unmask_init_process,      /* init process */
    NULL, NULL, NULL, NULL,
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
    /* unmask_bv_id: the pass that verified, by identity (see the variable
     * function) -- the per-pass reuse cap's key. */
    { ngx_string("unmask_bv_id"), NULL, ngx_http_unmask_bv_id_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
    /* unmask_module_id: the module file this nginx loaded, by content hash
     * (ngx_unmask_module_id_compute); the access log carries it (mo=). */
    { ngx_string("unmask_module_id"), NULL, ngx_http_unmask_module_id_variable, 0,
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
    /* unmask_client_net: the rate-limit key -- the client IP folded to a
     * network granularity (IPv4 = /32, IPv6 = /64) so a v6 client can't
     * multiply its rate budget by rotating privacy addresses within its /64.
     * Used by the limit_req_zone key in native mode (= rendered server.inc). */
    { ngx_string("unmask_client_net"), NULL,
      ngx_http_unmask_client_net_variable, 0,
      NGX_HTTP_VAR_NOCACHEABLE, 0 },
    /* unmask_compose: the render's protect.inc emits `set $unmask_compose 1`
     * only in compose-mode protected locations.  We ALSO register it here with a
     * default get_handler so the variable resolves cleanly (= not_found, "off")
     * on every other location and every foreign vhost -- otherwise the ACCESS
     * handler's read of an unset `set` variable makes nginx's rewrite module log
     * "using uninitialized \"unmask_compose\" variable" at WARN on each such
     * request (uninitialized_variable_warn defaults on).  Registration runs at
     * postconfiguration, after the `set` directive is parsed, so it OVERRIDES the
     * rewrite module's get_handler for this index (ngx_http_rewrite_set only
     * installs its own when get_handler == NULL).  CHANGEABLE lets `set` reuse
     * the variable; it is deliberately NOT NOCACHEABLE, so a location where `set`
     * ran keeps its cached "1" (the get_handler is never consulted there). */
    { ngx_string("unmask_compose"), NULL,
      ngx_http_unmask_compose_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE, 0 },
    /* unmask_bind_key: what a client's _bv / PoW seed is bound to (read by
     * ngx_unmask_bind_key in the verifier).  The render's http.inc defines it
     * as a geo block -- a relay's published egress range for a client inside
     * one, "" for everyone else.  This registration only gives the name a
     * resolver (not_found = "") when no http.inc defines it, so a server.inc
     * that forwards the variable to the daemon still loads.  CHANGEABLE so a
     * geo / map can take it over; unlike $unmask_compose, an existing
     * definition must WIN here, so ngx_http_ja4_init leaves a get_handler it
     * finds in place (see there). */
    { ngx_string("unmask_bind_key"), NULL,
      ngx_http_unmask_bind_key_variable, 0,
      NGX_HTTP_VAR_CHANGEABLE, 0 },
    ngx_http_null_variable
};

/* GREASE detection moved into ja4_parser.c (= removed from module.c
 * when the old callback was retired). */

/* The JA4 string assembly (hex4 / uint16 sort / SHA-256[:12] + the
 * JA4_a / JA4_b / JA4_c builder) moved to ja4_build.c so it can be
 * unit-tested + ASan/UBSan fuzzed without nginx / SSL.  See
 * ja4_build_string(), called from ngx_ja4_compute_and_store() below. */

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
    ngx_connection_t   *c;

    if (ngx_http_ja4_ssl_ex_data_idx < 0) return;

    /* If already computed (= 2nd or later ClientHello on the same SSL
     * connection, e.g. an HRR path), do nothing.  Prevents double
     * allocation / double SSL_set_ex_data. */
    if (SSL_get_ex_data(ssl, ngx_http_ja4_ssl_ex_data_idx) != NULL) {
        return;
    }

    /* Pool memory: freed with the connection, after nginx freed the SSL
     * object, so the ex_data slot needs no free callback (see the ctx
     * comment above). */
    c = ngx_ssl_get_connection(ssl);
    if (c == NULL) return;
    ctx = ngx_pcalloc(c->pool, sizeof(*ctx));
    if (ctx == NULL) {
        if (ngx_unmask_log_due(UNMASK_LOG_JA4_ALLOC)) {
            ngx_log_error(NGX_LOG_ERR, c->log, 0,
                          "unmask: no memory for the JA4 fingerprint; "
                          "the connection gets none");
        }
        return;
    }

    /* Build the JA4 string directly into ctx's fixed buffer.  The assembly
     * logic lives in ja4_build.c so it is unit-tested + ASan/UBSan fuzzed
     * without nginx / SSL; this function keeps only the ex_data storage. */
    ctx->ja4.len  = ja4_build_string(parsed, (char *)ctx->ja4_buf, NGX_JA4_MAX);
    ctx->ja4.data = ctx->ja4_buf;

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

    if (ja4_parse_client_hello(m, len, &parsed) != 0) {
        /* A ClientHello the parser would not take.  INFO, not WARN: odd
         * clients exist and each one is a line a minute at most. */
        ngx_connection_t *c = ngx_ssl_get_connection(ssl);
        if (c != NULL && ngx_unmask_log_due(UNMASK_LOG_JA4_PARSE)) {
            ngx_log_error(NGX_LOG_INFO, c->log, 0,
                          "unmask: ClientHello not parsed; "
                          "the connection gets no JA4");
        }
        return;
    }
    ngx_ja4_compute_and_store(ssl, &parsed);
}

/*
 * JA4 transport prefix.  ja4_build emits 't' (TCP/TLS); HTTP/3 requests get 'q'.
 *
 * The SSL msg_callback that computes the JA4 runs on the QUIC *connection* (whose
 * c->quic is NULL), so the transport is unknown at build time.  By the time a
 * request is processed it rides a QUIC *stream* -- r->connection->quic != NULL is
 * the marker nginx itself uses for HTTP/3, and the stream inherits the
 * connection's ->ssl (ngx_event_quic_streams.c: sc->ssl = c->ssl), so the same
 * per-connection JA4 ctx is reached.  Flip the first byte in place: the ctx is
 * per-connection and every stream on a QUIC connection is HTTP/3, so the flip is
 * connection-consistent and idempotent.  The rest of the JA4 (ciphers / exts /
 * alpn) is transport-independent and already reflects the QUIC ClientHello's
 * quic_transport_parameters (0x39) extension.
 *
 * Guarded: ngx_connection_t.quic exists only on nginx >= 1.25 built with QUIC or
 * --with-compat (the plugin's build mode).  On older nginx the field is absent
 * and HTTP/3 cannot be served, so 't' is always correct -- compile the flip out.
 */
static void
ngx_unmask_ja4_apply_transport(ngx_http_request_t *r, ngx_http_ja4_ctx_t *ctx) {
#if (nginx_version >= 1025000) && (NGX_QUIC || NGX_COMPAT)
    if (ctx != NULL && ctx->ja4.len > 0
        && r->connection->quic != NULL
        && ctx->ja4.data[0] == 't')
    {
        ctx->ja4.data[0] = 'q';
    }
#else
    (void) r; (void) ctx;
#endif
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
        int quic = 0;
#if (nginx_version >= 1025000) && (NGX_QUIC || NGX_COMPAT)
        /* nginx's QUIC compatibility layer (OpenSSL older than 3.5) sets its
         * own message callback on every QUIC SSL object, over the one this
         * module put on the SSL_CTX, so no ClientHello reaches the parser:
         * every HTTP/3 request then runs without a JA4 and the JA4 axis
         * and the ip|ja4 bans never see it.  Said once a minute. */
        if (r->connection->quic != NULL) {
            quic = 1;
            if (ngx_unmask_log_due(UNMASK_LOG_H3_NOJA4)) {
                ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                              "unmask: no JA4 for an HTTP/3 connection; with "
                              "OpenSSL older than 3.5 nginx's QUIC compatibility "
                              "layer replaces the TLS message callback, so "
                              "JA4-based decisions do not apply to HTTP/3 "
                              "(build nginx with OpenSSL 3.5 or newer, or QuicTLS)");
            }
        }
#endif
        /* No context at all on a TLS connection: the ClientHello never
         * reached this module's callback.  SSL_CTX_set_msg_callback holds
         * one function per context, so a module (or an nginx debug build)
         * that sets it after this one replaces it, and every request then
         * runs without a JA4 while nothing else looks wrong.  A context
         * whose JA4 is empty is a ClientHello the parser refused (its own
         * line, UNMASK_LOG_JA4_PARSE), not this.  Said once a minute;
         * `unmask doctor` reads the line. */
        if (ctx == NULL && !quic
            && ngx_unmask_log_due(UNMASK_LOG_TLS_NOJA4))
        {
            ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                          "unmask: no JA4 for a TLS connection: the ClientHello "
                          "never reached this module's callback. Another module "
                          "that calls SSL_CTX_set_msg_callback on the same "
                          "server replaces it (one callback per SSL_CTX), so "
                          "JA4-based decisions do not apply; load one of the "
                          "two, or report which module it is");
        }
        v->not_found = 1;
        return NGX_OK;
    }
    ngx_unmask_ja4_apply_transport(r, ctx);   /* 't' -> 'q' for HTTP/3 */
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->len = ctx->ja4.len;
    v->data = ctx->ja4.data;
    return NGX_OK;
}

/* read an nginx flag variable: true when its value starts with '1'. */
static ngx_uint_t
ngx_unmask_var_is_one(ngx_http_request_t *r, ngx_str_t *name)
{
    ngx_http_variable_value_t *v =
        ngx_http_get_variable(r, name, ngx_hash_key(name->data, name->len));
    return (v && !v->not_found && v->len && v->data[0] == '1') ? 1 : 0;
}

/* ---------------------------------------------------------------------------
 * ngx_http_request_t ABI -- READ THIS BEFORE ADDING ANY r->FIELD ACCESS
 *
 * Distributions patch nginx.  AlmaLinux / RHEL 8 ship
 * 0014-Added-max_headers-directive.patch, which inserts
 *
 *     ngx_uint_t count;
 *
 * at the TOP of ngx_http_headers_in_t, immediately after `headers`.  That struct
 * is embedded BY VALUE in ngx_http_request_t, so on those hosts every member
 * from headers_in.host onward -- r->uri, r->args, r->unparsed_uri, r->main,
 * r->headers_in.cookie ... -- sits 8 bytes further along than a module compiled
 * against vanilla nginx sources computes.  The patch changes neither
 * nginx_version nor NGX_MODULE_SIGNATURE, so nginx's load-time compatibility
 * check passes and loads the module anyway; it then reads the neighbouring field
 * instead of the one it asked for, silently.  Measured on AlmaLinux 8 (nginx
 * 1.24.0): offsetof(main) is 1008 there and 1000 in a vanilla build, so r->main
 * read back as NULL and the compose ACCESS handler took its "not the main
 * request" exit on every request.  A compose protect.inc carries no
 * error_page/rewrite and runs limit_req in dry-run, so protected locations then
 * served bots straight through -- a total, silent fail-open.  (Caught by
 * distro-check on 2026-07-14, before 0.1.5 shipped.)
 *
 * The rule that follows: reach request state through nginx's OWN functions --
 * ngx_http_get_variable(), ngx_http_internal_redirect(), ngx_http_get_module_ctx()
 * -- which live in the nginx binary and therefore use the host's real offsets.
 * Direct r->FIELD access is only safe for members that sit BEFORE headers_in:
 *
 *     connection ctx main_conf srv_conf loc_conf read_event_handler
 *     write_event_handler cache upstream upstream_states pool header_in
 *
 * r->headers_in.headers is at offset 0 of headers_in, so walking the header list
 * is still safe; every other headers_in member is not.
 * ------------------------------------------------------------------------- */

/* Read a variable's value as a string.  Returns NGX_DECLINED (and an empty out)
 * when the variable is unset or unknown. */
static ngx_int_t
ngx_unmask_var_str(ngx_http_request_t *r, ngx_str_t *name, ngx_str_t *out)
{
    ngx_http_variable_value_t *v =
        ngx_http_get_variable(r, name, ngx_hash_key(name->data, name->len));
    if (v == NULL || v->not_found) {
        out->len = 0;
        out->data = NULL;
        return NGX_DECLINED;
    }
    out->len = v->len;
    out->data = v->data;
    return NGX_OK;
}

/* What a verified _bv cookie turned out to be.  Declared here because the
 * request ctx below carries one; the field-by-field story is with the cookie
 * verifier further down. */
typedef enum {
    UNMASK_BV_KIND_NONE        = 0,
    UNMASK_BV_KIND_CAPTCHA     = 1,
    UNMASK_BV_KIND_POW         = 2,
    UNMASK_BV_KIND_REBIND      = 3,
    UNMASK_BV_KIND_PASSTHROUGH = 4,
} ngx_unmask_bv_kind_t;

/* Per-request state, kept in this module's ctx slot.
 *
 * Two things are computed at most once per request here.  The _bv cookie kind:
 * every $unmask_bv_* variable is NOCACHEABLE (the maps that read them are
 * evaluated in several phases, and a cached value would survive an internal
 * redirect's variable reset), so before this ctx existed each of the five maps
 * reading a kind re-walked the Cookie header and re-ran its HMACs -- six or
 * seven times the sixteen-entry budget per request, which is the per-request
 * cost the budget was meant to bound.  And the ban-file lookup: a stat() plus
 * three bsearches per evaluation, evaluated a dozen times across http.inc and
 * server.inc.  Neither input (the Cookie header, the file) changes within a
 * request, so the first evaluation's answer is the request's answer.
 *
 * `main` is the "arrived from the wire" marker the POST_READ handler drops
 * (see ngx_http_unmask_mark_main_handler); it has to be a flag, not the
 * mere presence of the ctx, because a subrequest or an internally redirected
 * request (nginx zeroes r->ctx on redirect) gets a ctx of its own the first
 * time it reads a variable, and that ctx must not read as "main". */
typedef struct {
    unsigned              main:1;
    unsigned              bv_done:1;
    unsigned              ban_done:1;
    unsigned              ban_hit:1;
    ngx_unmask_bv_kind_t  bv_kind;
    ngx_str_t             bv_id;       /* the verified pass's identity (16 hex) */
    ngx_str_t             ban_action;  /* copy in r->pool; empty when no hit */
} ngx_http_unmask_req_ctx_t;

/* The request's ctx, created on first use.  NULL only when r->pool is
 * exhausted; every caller then falls back to computing without a cache. */
static ngx_http_unmask_req_ctx_t *
ngx_unmask_req_ctx(ngx_http_request_t *r)
{
    ngx_http_unmask_req_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_unmask_module);
    if (ctx == NULL) {
        ctx = ngx_pcalloc(r->pool, sizeof(*ctx));
        if (ctx == NULL) {
            return NULL;
        }
        ngx_http_set_ctx(r, ctx, ngx_http_unmask_module);
    }
    return ctx;
}

/* POST_READ runs only for a request that arrived from the wire: ngx_http_handler
 * enters an internal request (subrequest / internal redirect) at
 * phase_engine.server_rewrite_index, which is past this phase.  Marking the
 * ctx here therefore yields an ABI-safe "is this the main request?" --
 * r->ctx sits at offset 16, ahead of headers_in, and a subrequest gets a
 * freshly zeroed ctx array of its own. */
static ngx_int_t
ngx_http_unmask_mark_main_handler(ngx_http_request_t *r)
{
    ngx_http_unmask_req_ctx_t *ctx = ngx_unmask_req_ctx(r);
    if (ctx != NULL) {
        ctx->main = 1;
    }
    return NGX_DECLINED;
}

/* Stands in for `r == r->main`, which is unreadable on a layout-shifted host. */
static ngx_int_t
ngx_unmask_is_main_request(ngx_http_request_t *r)
{
    ngx_http_unmask_req_ctx_t *ctx =
        ngx_http_get_module_ctx(r, ngx_http_unmask_module);
    return ctx != NULL && ctx->main;
}

/* $unmask_gate is "<final_challenge>:<failopen>"; the field after the colon
 * is "1" when server.inc found the daemon down.  Read that field, not the
 * string's length: "longer than two characters" (what this replaces) would
 * have read any two-character verdict as fail-open the day a map grew one. */
static int
ngx_unmask_gate_failopen(ngx_http_variable_value_t *gv)
{
    size_t i;
    for (i = 0; i < gv->len; i++) {
        if (gv->data[i] == ':') {
            return (i + 1 < gv->len && gv->data[i + 1] == '1');
        }
    }
    return 0;
}


/* Default get_handler for $unmask_compose.  Only consulted where protect.inc did
 * NOT `set $unmask_compose 1` (non-compose locations, /unmask/ machinery, foreign
 * vhosts): resolves to not_found = the classic flow, with no uninitialized-var
 * WARN.  In compose locations the REWRITE-phase `set` writes r->variables[index]
 * (valid, cached) and this never runs. */
static ngx_int_t
ngx_http_unmask_compose_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    (void) r;
    (void) data;
    v->not_found = 1;
    return NGX_OK;
}

/* $unmask_bind_key when the rendered http.inc does not define it: not_found,
 * which the verifier reads as "no key, bind to the address". */
static ngx_int_t
ngx_http_unmask_bind_key_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    (void) r;
    (void) data;
    v->not_found = 1;
    return NGX_OK;
}

/* ----------------------------------------------------------------------
 * Rate-limit / protected composition (ACCESS phase).  On "compose" locations
 * (the render switches a protected location to the unified flow when a deny
 * zone exists), this replaces the REWRITE-phase captcha gate + the
 * error_page-429 trigger with a single post-limit_req decision -- so a "deny"
 * rate-zone can take precedence over the protected captcha (the REWRITE rewrite
 * would otherwise pre-empt limit_req).  ACCESS phase runs after the whole
 * preaccess phase, so r->main->limit_req_status (set by limit_req_dry_run) is
 * available; a PREACCESS handler is NOT reliably ordered after limit_req.
 *
 *   over the cap  -> /unmask/_rl<uri>  (daemon decides deny vs challenge from
 *                    the matched zone; a deny zone yields a hard 403)
 *   within, gate  -> /unmask/challenge/?_orig=<uri>  (protected captcha)
 *   within, ok    -> DECLINED (pass)
 *
 * Unmask-internal, NOT a public directive: gated on the render-emitted
 * $unmask_compose.  Redirect loops are prevented by an explicit /unmask/ URI
 * guard -- the compose flag is a cacheable `set` variable that persists across
 * the internal_redirect, so it cannot be relied on for that.
 * -------------------------------------------------------------------- */

/* Internal-redirect from this ACCESS-phase handler, balancing the request
 * reference count.  ngx_http_internal_redirect() takes a reference
 * (r->main->count++) that the caller must release by passing its NGX_DONE on
 * to ngx_http_finalize_request().  The CONTENT-phase checker does exactly that
 * with a content handler's return value, which is why ngx_http_index_module
 * may return the redirect's value bare -- but the ACCESS-phase checker maps
 * NGX_DONE to "waiting for an event" WITHOUT finalizing, so returning it bare
 * from here strands one reference: the redirected response completes,
 * r->count stays 1, ngx_http_set_keepalive() is never reached, and the
 * connection is orphaned holding its fd until the worker exits.  That leaked
 * one fd per composed request and took every native fleet node down by
 * worker_connections/RLIMIT_NOFILE exhaustion within ~2h of the first compose
 * rollout (2026-07-15).  Pair the redirect with an explicit finalize instead
 * -- the idiom nginx itself uses for X-Accel-Redirect
 * (ngx_http_upstream_process_headers), which likewise runs outside the
 * CONTENT checker's finalize.  The finalize either merely drops the reference
 * (redirect target still in flight, count > 1) or performs the
 * keepalive/close transition itself (target already completed synchronously,
 * count == 1) -- both exactly what the CONTENT checker would have done. */
static ngx_int_t
ngx_unmask_access_redirect(ngx_http_request_t *r, ngx_str_t *uri,
    ngx_str_t *args)
{
    ngx_http_internal_redirect(r, uri, args);
    ngx_http_finalize_request(r, NGX_DONE);
    return NGX_DONE;
}

static ngx_int_t
ngx_http_unmask_ratedeny_handler(ngx_http_request_t *r)
{
    /* No `r == r->main` test: ngx_http_core_access_phase already skips
     * subrequests before calling us, and r->main is one of the fields a
     * distro-patched ngx_http_request_t moves out from under this module (see
     * the ABI note above -- it read back NULL on AlmaLinux 8, which turned this
     * handler into an unconditional pass). */

    static ngx_str_t uri_var     = ngx_string("uri");
    static ngx_str_t args_var    = ngx_string("args");
    static ngx_str_t requri_var  = ngx_string("request_uri");
    static ngx_str_t lrs_var     = ngx_string("limit_req_status");
    static ngx_str_t compose_var = ngx_string("unmask_compose");
    static ngx_str_t gate_var    = ngx_string("unmask_gate");

    ngx_str_t uri;
    if (ngx_unmask_var_str(r, &uri_var, &uri) != NGX_OK) {
        return NGX_DECLINED;
    }

    /* loop prevention: decline on the internal-redirect TARGETS only --
     * /unmask/_rl<uri> and /unmask/challenge/.  $unmask_compose is a cacheable
     * `set` var that persists "1" across the redirect, so this URI guard (not
     * the compose flag) is what stops re-entry.  Scoped to the two targets, NOT
     * all of /unmask/, so a protected path under /unmask/ (e.g. /unmask/admin/)
     * still gets composed.  Other /unmask/ machinery never sets $unmask_compose,
     * so the compose gate below declines it. */
    if ((uri.len >= (sizeof("/unmask/_rl") - 1)
         && ngx_strncmp(uri.data, "/unmask/_rl", sizeof("/unmask/_rl") - 1) == 0)
        || (uri.len >= (sizeof("/unmask/challenge/") - 1)
            && ngx_strncmp(uri.data, "/unmask/challenge/",
                           sizeof("/unmask/challenge/") - 1) == 0))
    {
        return NGX_DECLINED;
    }

    if (!ngx_unmask_var_is_one(r, &compose_var)) {
        return NGX_DECLINED;            /* not a unified-flow location */
    }

    /* $unmask_gate = "<final_challenge>:<failopen>".  When the daemon is down
     * server.inc sets failopen=1 (gate "X:1", len 3): the /unmask/ routes we'd
     * redirect to are served by that dead daemon, so fail open = pass everything
     * (the classic flow's exact "1:" rewrite match likewise misses on "1:1"). */
    ngx_http_variable_value_t *gv = ngx_http_get_variable(
        r, &gate_var, ngx_hash_key(gate_var.data, gate_var.len));
    if (gv != NULL && !gv->not_found && ngx_unmask_gate_failopen(gv)) {
        return NGX_DECLINED;            /* fail open (daemon down) */
    }

    /* Over the rate cap?  $limit_req_status carries what limit_req_dry_run
     * decided; "REJECTED_DRY_RUN" = would have been rejected.  Route to
     * /unmask/_rl<uri> -- the daemon resolves deny vs challenge from the matched
     * zone (a deny zone yields a hard 403).
     *
     * This variable landed in nginx 1.17.6, the same release that added the
     * r->main->limit_req_status field it mirrors and that ComposeCapable gates
     * compose on Go-side; on anything older the lookup resolves to not-found and
     * we fall through to the challenge branch, exactly as the previously
     * #if-compiled-out code did.  Reading the VARIABLE rather than the struct
     * field is what keeps this working on a patched-nginx host (ABI note above). */
    ngx_str_t lrs;
    if (ngx_unmask_var_str(r, &lrs_var, &lrs) == NGX_OK
        && lrs.len == sizeof("REJECTED_DRY_RUN") - 1
        && ngx_strncmp(lrs.data, "REJECTED_DRY_RUN",
                       sizeof("REJECTED_DRY_RUN") - 1) == 0)
    {
        static const u_char rl_prefix[] = "/unmask/_rl";
        ngx_str_t rl_uri, args;
        u_char *p;

        (void) ngx_unmask_var_str(r, &args_var, &args);

        rl_uri.len = (sizeof(rl_prefix) - 1) + uri.len;
        rl_uri.data = ngx_pnalloc(r->pool, rl_uri.len);
        if (rl_uri.data == NULL) {
            return NGX_ERROR;
        }
        p = ngx_cpymem(rl_uri.data, rl_prefix, sizeof(rl_prefix) - 1);
        if (uri.len) {
            ngx_memcpy(p, uri.data, uri.len);
        }
        return ngx_unmask_access_redirect(r, &rl_uri, &args);
    }

    /* within the cap: captcha gate exactly "1:" -> protected challenge. */
    if (gv != NULL && !gv->not_found && gv->len == 2
        && gv->data[0] == '1' && gv->data[1] == ':')
    {
        static ngx_str_t chal = ngx_string("/unmask/challenge/");
        static const u_char orig_prefix[] = "_orig=";
        ngx_str_t orig, args;
        u_char *p;

        (void) ngx_unmask_var_str(r, &requri_var, &orig);

        args.len = (sizeof(orig_prefix) - 1) + orig.len;
        args.data = ngx_pnalloc(r->pool, args.len);
        if (args.data == NULL) {
            return NGX_ERROR;
        }
        p = ngx_cpymem(args.data, orig_prefix, sizeof(orig_prefix) - 1);
        if (orig.len) {
            ngx_memcpy(p, orig.data, orig.len);
        }
        return ngx_unmask_access_redirect(r, &chal, &args);
    }

    return NGX_DECLINED;                /* within cap, no challenge -> pass */
}

/* Worker start: the two conditions under which the module enforces nothing
 * are checked once, as the worker user, and said at the "error" level the
 * distributions' nginx.conf ships with.  The per-request paths repeat them
 * once a minute; this is the line an operator finds after a restart. */
static ngx_int_t ngx_http_unmask_init_process(ngx_cycle_t *cycle)
{
    ngx_http_ja4_main_conf_t *mcf;
    char path[1024];

    mcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_unmask_module);
    if (mcf == NULL) {
        return NGX_OK;
    }
    if (mcf->bv_secret.len == 0) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0,
                      "unmask: unmask_bv_secret is empty; every _bv cookie "
                      "is rejected and every visitor is challenged again");
    }
    if (mcf->ban_file_path.len > 0 && mcf->ban_file_path.len < sizeof(path)) {
        ngx_memcpy(path, mcf->ban_file_path.data, mcf->ban_file_path.len);
        path[mcf->ban_file_path.len] = '\0';
        if (access(path, R_OK) != 0) {
            int err = errno;
            if (err == ENOENT) {
                ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0,
                              "unmask: ban file \"%s\" does not exist; no ban "
                              "is enforced until the daemon writes it", path);
            } else {
                ngx_log_error(NGX_LOG_ERR, cycle->log, err,
                              "unmask: ban file \"%s\" is not readable by this "
                              "worker; no ban is enforced (check the directory "
                              "and file permissions: unmask doctor)", path);
            }
        }
    }
    return NGX_OK;
}

static ngx_int_t ngx_http_ja4_init(ngx_conf_t *cf) {
    /* The module's own identity, once per process image (see the function). */
    ngx_unmask_module_id_compute();

    /* Register $client_ja4 variable */
    for (ngx_http_variable_t *v = ngx_http_ja4_vars; v->name.len; v++) {
        ngx_http_variable_t *var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (!var) return NGX_ERROR;
        /* $unmask_bind_key: the geo block the render puts in http.inc is parsed
         * before this hook runs and is the definition that must stand; the
         * module's own handler is only the fallback for a config without one. */
        if (v->get_handler == ngx_http_unmask_bind_key_variable
            && var->get_handler != NULL)
        {
            continue;
        }
        var->get_handler = v->get_handler;
        var->data = v->data;
    }
    {
        ngx_str_t bk = ngx_string("unmask_bind_key");
        ngx_http_ja4_main_conf_t *mcf =
            ngx_http_conf_get_module_main_conf(cf, ngx_http_unmask_module);
        if (mcf != NULL) {
            mcf->bind_key_index = ngx_http_get_variable_index(cf, &bk);
        }
    }

    /* Register the ex_data slot once, with no callbacks (see the ctx
     * comment: a callback in module text outlives the module).  nginx
     * registers its own slots the same way (ngx_ssl_connection_index). */
    if (ngx_http_ja4_ssl_ex_data_idx < 0) {
        ngx_http_ja4_ssl_ex_data_idx = SSL_get_ex_new_index(
            0, NULL, NULL, NULL, NULL);
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

    /* Rate-deny composition handler: ACCESS phase, so it runs after the ENTIRE
     * preaccess phase -- where limit_req sets r->main->limit_req_status.  (A
     * PREACCESS handler is NOT reliably ordered after limit_req: this dynamic
     * module's handler lands *before* limit_req there, observed empirically as
     * lrs=0.)  access_phase's checker returns NGX_OK on our NGX_DONE (from
     * ngx_http_internal_redirect), and skips subrequests, both of which suit us.
     * Unmask-internal -- no public directive (gates on $unmask_compose). */
    ngx_http_handler_pt *rdh =
        ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (rdh == NULL) return NGX_ERROR;
    *rdh = ngx_http_unmask_ratedeny_handler;

    /* POST_READ marker: gives every later hook an ABI-safe "is this the main
     * request?" (= ngx_unmask_is_main_request).  This phase runs only for
     * requests that arrived from the wire, never for subrequests. */
    ngx_http_handler_pt *mrh =
        ngx_array_push(&cmcf->phases[NGX_HTTP_POST_READ_PHASE].handlers);
    if (mrh == NULL) return NGX_ERROR;
    *mrh = ngx_http_unmask_mark_main_handler;

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
    cnf->bind_key_index = NGX_ERROR;
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
 * $unmask_bv_kind and the variables derived from it: parse the _bv cookie
 * (a "~"-separated list of entries) and verify each entry's HMAC.
 *
 * Entry form: "<issued_unix>.<sig16>.<kind>"
 *   sig16 = HMAC("<issued_unix>:<bind key>:<host>:<kind>", BV_SECRET) hex[:16]
 *   (JA4 is NOT in the input -- it diverges across an LB; host binds the vhost;
 *   the bind key is the client address, /64 for IPv6, or a relay-wide key.)
 *
 * An entry verifies when its signature matches and issued_unix lies within
 * the kind's validity window (pow / captcha seconds from the main conf, plus
 * a small forward skew).  Nothing verifies when bv_secret is empty.
 * -------------------------------------------------------------------- */

/* Decimal day / unix parsing lives in bv_parser.c as bv_atoll() so the
 * fuzz harness (bv_parser_fuzz.c) exercises it; see the #include above. */

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

/* $unmask_module_id: the identity of the module file nginx loaded -- the
 * first 16 hex digits of the SHA-256 of the .so, read from its own path
 * (dladdr on this module's descriptor) once per process image.  The value
 * names the bytes that are RUNNING, not the file on disk right now: on a
 * reload the module is not loaded again (its image stays mapped in the
 * master, and the workers fork from it), and the static below keeps what was
 * computed when it was loaded; a restart loads the file afresh and computes
 * it again.  http.inc logs it on every line (mo=), and the daemon compares
 * it with the hash of the file at load_module's path: a line naming another
 * module after a package placed a new file is an nginx that needs a restart
 * -- which the daemon cannot otherwise tell, since its unit hides other
 * users' processes (ProtectProc=invisible).  "" when the file cannot be read;
 * a static build hashes the nginx binary, which the daemon never compares
 * against (it finds no load_module to read a path from). */
#define UNMASK_MODULE_ID_LEN 16
static u_char ngx_unmask_module_id[UNMASK_MODULE_ID_LEN + 1];

static void
ngx_unmask_module_id_compute(void)
{
    Dl_info        info;
    FILE          *f;
    unsigned char *buf;
    unsigned char  digest[SHA256_DIGEST_LENGTH];
    char           hex[SHA256_DIGEST_LENGTH * 2 + 1];
    long           n;

    if (ngx_unmask_module_id[0] != 0) {
        return;
    }
    if (dladdr((void *)&ngx_http_unmask_module, &info) == 0
        || info.dli_fname == NULL || info.dli_fname[0] == '\0')
    {
        return;
    }
    f = fopen(info.dli_fname, "rb");
    if (f == NULL) {
        return;
    }
    if (fseek(f, 0, SEEK_END) != 0 || (n = ftell(f)) <= 0
        || n > 64L * 1024 * 1024 || fseek(f, 0, SEEK_SET) != 0)
    {
        fclose(f);
        return;
    }
    buf = malloc((size_t)n);
    if (buf == NULL) {
        fclose(f);
        return;
    }
    if (fread(buf, 1, (size_t)n, f) != (size_t)n) {
        free(buf);
        fclose(f);
        return;
    }
    fclose(f);
    SHA256(buf, (size_t)n, digest);
    free(buf);
    ngx_unmask_hex(hex, digest, SHA256_DIGEST_LENGTH);
    ngx_memcpy(ngx_unmask_module_id, hex, UNMASK_MODULE_ID_LEN);
    ngx_unmask_module_id[UNMASK_MODULE_ID_LEN] = '\0';
}

static ngx_int_t
ngx_http_unmask_module_id_variable(ngx_http_request_t *r,
                                   ngx_http_variable_value_t *v, uintptr_t data)
{
    (void)r;
    (void)data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    v->data = ngx_unmask_module_id;
    v->len  = ngx_strlen(ngx_unmask_module_id);
    return NGX_OK;
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

/* UNMASK_BV_ID_LEN: $unmask_bv_id's length -- the 16 hex digits of a
 * CAPTCHA-form entry's signature, and as many of a proof-of-work's seed. */
#define UNMASK_BV_ID_LEN 16

/* The MACs the daemon may have signed with (settings.secret.sig_hash):
 * HMAC-SHA256, then HMAC-SHA1, which every release before the move used.
 * A signature is the MAC's first 16 hex digits and a proof-of-work seed its
 * first 40 whatever the hash, so one wire format carries both; the verifier
 * tries each in this order, and so does the daemon's (cookies.SigHashes --
 * the two MUST agree, and MUST stay byte-identical in what they hash).  The
 * cost of the second try falls on a cookie that does not verify at all. */
typedef const EVP_MD *(*ngx_unmask_md_fn)(void);
static const ngx_unmask_md_fn ngx_unmask_sig_hashes[] = { EVP_sha256, EVP_sha1 };
static const size_t ngx_unmask_sig_hash_count =
    sizeof(ngx_unmask_sig_hashes) / sizeof(ngx_unmask_sig_hashes[0]);

/* verify_pow_sha256_cookie: v0.1+ SHA-256 hashcash format.
 *   format: "<issued_unix>.pow2.<nonce_b36>.<flags_b36>"  (= parts[1]="pow2" marker already detected)
 *   seed   = hex(HMAC-SHA1(bv_secret, "<issued_unix>:<remote>:<host>:pow_seed"))
 *   input  = seed + ":" + nonce_dec
 *   valid  = leading-zero-bits of SHA-256(input) >= difficulty
 * Bit-identical logic to challenge.js and Go cookies.verifyPowSHA256.  The
 * seed is derived with every hash the daemon may have signed it with
 * (ngx_unmask_sig_hashes: HMAC-SHA256 cut to 160 bits, then HMAC-SHA1 -- 40
 * hex digits either way), so a cookie solved against the seed of an install
 * that has since moved stays good for its window.
 * Returns 1 if valid, 0 otherwise.  On 1, id_out (UNMASK_BV_ID_LEN bytes;
 * may be NULL) receives the verifying seed's first hex digits -- the pass's
 * identity for $unmask_bv_id, the same for every nonce that answers the seed. */
static int
ngx_unmask_verify_pow_sha256_cookie(const u_char *day_s, size_t day_n,
                                    const u_char *nonce_s, size_t nonce_n,
                                    int valid_seconds, int difficulty,
                                    ngx_str_t bv_secret, ngx_str_t remote,
                                    ngx_str_t host, u_char *id_out)
{
    if (nonce_n == 0 || nonce_n > 13) return 0;
    if (difficulty < 8 || difficulty > 32) difficulty = 18;

    int64_t cookie_unix = bv_atoll(day_s, day_n);
    if (cookie_unix < 0) return 0;
    int64_t now = (int64_t)ngx_time();
    if (cookie_unix > now + UNMASK_BV_FUTURE_SKEW_SECONDS) return 0;
    if (now - cookie_unix > (int64_t)valid_seconds) return 0;

    int64_t nonce = ngx_unmask_base36(nonce_s, nonce_n);
    if (nonce < 0) return 0;

    /* seed = hex(HMAC(bv_secret, "<issued_unix>:<remote>:<host>:pow_seed"))[:40].
     * MUST stay byte-identical to cookies.PowSeedH() (Go admin) and the value
     * the admin injects as window.UNMASK.pow_seed (challenge.js).  Binding the
     * seed to the secret makes the PoW impossible to precompute offline;
     * binding it to the client IP makes a solved cookie non-transferable
     * across IPs. */
    /* "<unix>:<remote>:<host>:pow_seed".  host (= $host) can be a 253-char DNS
     * name, so size generously; snprintf truncation returns 0 (= fail closed). */
    char seed_msg[384];
    int sm = snprintf(seed_msg, sizeof(seed_msg), "%lld:%.*s:%.*s:pow_seed",
                      (long long)cookie_unix,
                      (int)remote.len, remote.len ? (const char *)remote.data : "",
                      (int)host.len, host.len ? (const char *)host.data : "");
    if (sm <= 0 || sm >= (int)sizeof(seed_msg)) return 0;

    for (size_t hi = 0; hi < ngx_unmask_sig_hash_count; hi++) {
        unsigned char seed_mac[EVP_MAX_MD_SIZE];
        unsigned int seed_mac_len = sizeof(seed_mac);
        if (HMAC(ngx_unmask_sig_hashes[hi](), bv_secret.data, bv_secret.len,
                 (const unsigned char *)seed_msg, (size_t)sm,
                 seed_mac, &seed_mac_len) == NULL || seed_mac_len < 20) {
            continue;
        }
        char seed_hex[41];
        ngx_unmask_hex(seed_hex, seed_mac, 20);   /* the first 160 bits, whatever the hash */
        seed_hex[40] = '\0';

        /* input = "<seed_hex(40)>:<nonce>".  Max = 40 + 1 + 19 = 60. */
        char input[80];
        int ilen = snprintf(input, sizeof(input), "%s:%lld",
                            seed_hex, (long long)nonce);
        if (ilen <= 0 || ilen >= (int)sizeof(input)) return 0;

        unsigned char hash[SHA256_DIGEST_LENGTH];
        SHA256((const unsigned char *)input, (size_t)ilen, hash);

        if (ngx_unmask_leading_zero_bits(hash, SHA256_DIGEST_LENGTH) >= difficulty) {
            if (id_out != NULL) {
                ngx_memcpy(id_out, seed_hex, UNMASK_BV_ID_LEN);
            }
            return 1;
        }
    }
    return 0;
}

/* bv_kind: cookie-form determination plus verification result.
 *   UNMASK_BV_KIND_NONE    : not presented / malformed / verification failed
 *   UNMASK_BV_KIND_CAPTCHA : 3-segment HMAC OK, kind segment "captcha" (= solved one)
 *   UNMASK_BV_KIND_REBIND  : 3-segment HMAC OK, kind "rebind"      (= roamed onto a new IP)
 *   UNMASK_BV_KIND_PASSTHROUGH : 3-segment HMAC OK, kind "passthrough" (= handed out while
 *                            monitoring mode / the over-block breaker suspended enforcement;
 *                            nobody proved anything for it)
 *   UNMASK_BV_KIND_POW     : 4-segment SHA-256 PoW verification OK (= PoW-passed repeat
 *                            visitor), or the 3-segment kind "pow" the admin signs for the
 *                            math fallback's downgraded pass
 *
 * A 3-segment entry whose kind is none of those does NOT verify, even with a
 * genuine signature.  The kind segment is the tail of the HMAC input, and one
 * other message this secret signs has exactly that shape: the PoW seed is
 * HMAC(secret, "<issued>:<ip>:<host>:pow_seed"), and the challenge page hands
 * it to every visitor in the clear.  Read as a kind, the seed's first 16 hex
 * digits were a valid signature of kind "pow_seed" -- a pass with no hashing
 * done, for the CAPTCHA validity window.  Refusing unknown kinds closes that
 * without touching the seed derivation (which the admin would have to change
 * in the same breath, and a daemon upgraded ahead of an nginx reload would
 * then mint seeds the running plugin cannot verify).  The admin's verifier
 * (cookies.issuedKinds) keeps the same list; a new kind goes into both or
 * neither.
 *
 * The 3-segment forms are told apart by the kind segment the admin signed
 * into the cookie, because the difference is not cosmetic: a rebind entry
 * means "this client solved once and has since been silently re-bound onto
 * another address", which is exactly the population an operator hunting a
 * distributed crawler is looking for.  Reporting both as "captcha" hid it --
 * measured on a production install, a crawler passing entirely by re-binding
 * showed up as CAPTCHA passes (1-3 per five minutes, steady) while the
 * proof-of-work figures it never touched read zero, so the dashboard said the
 * challenge was unbroken while 137k requests a day walked through it.
 *
 * Both still pass: the kind is an observation, not a gate.  $bv_any_valid
 * treats every non-empty kind as a valid pass exactly as before, so nothing
 * about who gets challenged changes here.  $bv_captcha_valid narrows to a
 * genuine CAPTCHA pass, which is what its name always claimed.
 *
 * Extending: when a future cookie path (= signature / webauthn / passkey
 * etc.) is added, just add an enum + decision branch + variable expose
 * and the dashboard aggregation will automatically treat the new kind
 * as one row (= unmask_cookie_minute is normalized on kind/cnt). */
/* ngx_unmask_bv_kind_t itself is declared next to the request ctx above,
 * which carries one as a member. */

/* Compare the parsed kind segment against a literal.  The segment is bounded
 * to 32 bytes by the parser and covered by the HMAC verified above, so this
 * only ever reads server-authored bytes. */
#define UNMASK_TAIL_IS(f, c, lit)                                       \
    ((f).tail_len == sizeof(lit) - 1 &&                                 \
     ngx_strncmp((c).data + (f).tail_off, lit, sizeof(lit) - 1) == 0)

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

/* ngx_unmask_bind_ip: the per-request client IP folded for the _bv HMAC seed.
 * The pure logic lives in unmask_bind_ip_token (bv_parser.c, fuzz/parity-tested);
 * this wraps it with a pool allocation.  IPv4 / IPv4-mapped / unparseable -> the
 * original addr_text (so v4 cookies stay byte-identical); pure IPv6 -> its /64
 * as 16 hex chars, so a client's rotating privacy addresses within one /64
 * don't each re-challenge.  MUST mirror cookies.bindIP() in the Go admin. */
static ngx_str_t
ngx_unmask_bind_ip(ngx_str_t in, ngx_pool_t *pool)
{
    char tok[16];
    if (unmask_bind_ip_token((const char *)in.data, in.len, tok) == 16) {
        u_char *out = ngx_pnalloc(pool, 16);
        if (out != NULL) {
            ngx_memcpy(out, tok, 16);
            ngx_str_t r = { 16, out };
            return r;
        }
    }
    return in;
}

/* ngx_unmask_bind_key: what this client's _bv / PoW seed is bound to.  The
 * rendered http.inc gives $unmask_bind_key a relay's published egress range
 * for a client inside one (such a relay moves the address within the range
 * from one request to the next); for everyone else it is empty and the
 * address, folded as before, is the key.  The daemon issues against the same
 * variable (forwarded as X-Unmask-Bind-Key), so the two never disagree. */
static ngx_str_t
ngx_unmask_bind_key(ngx_http_request_t *r, ngx_http_ja4_main_conf_t *mcf)
{
    if (mcf != NULL && mcf->bind_key_index != NGX_ERROR) {
        ngx_http_variable_value_t *vv =
            ngx_http_get_indexed_variable(r, (ngx_uint_t) mcf->bind_key_index);
        if (vv != NULL && vv->valid && !vv->not_found && vv->len > 0) {
            ngx_str_t k = { vv->len, vv->data };
            return k;
        }
    }
    return ngx_unmask_bind_ip(r->connection->addr_text, r->pool);
}

/* Verify a single `_bv` cookie value.  Returns the cookie kind on success
 * (POW / CAPTCHA) or NONE on parse / verify failure.  Called once per
 * candidate cookie by bv_kind_compute. */
/* The PoW difficulty this request's cookie is held to.  The daemon serves
 * each site the difficulty that site configured (Challenge.Resolve(site)) and
 * renders the same per-host values into the $unmask_pow_difficulty map; the
 * directive is the install-wide default the map falls back to.  Reading the
 * map keeps the verifier on the page's number: a site set below the default
 * used to produce a PoW the directive rejected, and its visitors looped. */
static int
ngx_unmask_pow_difficulty(ngx_http_request_t *r, ngx_http_ja4_main_conf_t *mcf)
{
    static ngx_str_t diff_var = ngx_string("unmask_pow_difficulty");
    ngx_str_t s;
    int d = (int)mcf->bv_pow_difficulty;
    if (ngx_unmask_var_str(r, &diff_var, &s) == NGX_OK && s.len > 0 && s.len <= 2) {
        int n = 0;
        size_t i;
        for (i = 0; i < s.len; i++) {
            if (s.data[i] < '0' || s.data[i] > '9') return d;
            n = n * 10 + (s.data[i] - '0');
        }
        if (n >= 1 && n <= 64) d = n;
    }
    return d;
}

/* verify_one: the kind one entry verifies as, NONE when it does not.  With a
 * kind, *id_out (when given) is the pass's identity for $unmask_bv_id: the
 * signature of a CAPTCHA-form entry, the seed a proof-of-work answers -- 16
 * hex digits either way, in memory that lives as long as the request. */
static ngx_unmask_bv_kind_t
ngx_unmask_bv_verify_one(ngx_http_request_t *r,
                         ngx_http_ja4_main_conf_t *mcf,
                         ngx_str_t cookie, ngx_str_t *id_out)
{
    /* Structural decode (dot-splitting + per-segment length bounds) lives in
     * the pure, fuzzed bv_parse_entry (see bv_parser.c / bv_parser_fuzz.c) so
     * the untrusted-input path that handles a fully client-controlled cookie is
     * exercised under ASan exactly as it runs here. */
    bv_fields_t fields;
    if (!bv_parse_entry(cookie.data, cookie.len, &fields)) {
        return UNMASK_BV_KIND_NONE;
    }

    /* The bind key -- the client IP folded for the HMAC seed (IPv6 -> /64), or
     * the relay range $unmask_bind_key names.  Computed once and used by both
     * the PoW and CAPTCHA branches so they bind identically. */
    ngx_str_t remote = ngx_unmask_bind_key(r, mcf);

    /* PoW path: bv_parse_entry only accepts the "pow2" SHA-256 hashcash form
     * (a 4-segment _bv whose parts[1] != "pow2" is rejected -- the removed v0.0
     * djb2 fallback verified an UNKEYED checksum = offline-mintable bypass).
     * Issued client-side by challenge.js after PoW passes; no HMAC secret. */
    if (fields.format == BV_FMT_POW2) {
        int valid_seconds = (mcf->bv_pow_valid_seconds > 0)
            ? (int)mcf->bv_pow_valid_seconds : 86400 * 3;
        int difficulty = ngx_unmask_pow_difficulty(r, mcf);
        u_char seed_id[UNMASK_BV_ID_LEN];
        if (ngx_unmask_verify_pow_sha256_cookie(
                cookie.data + fields.day_off,  fields.day_len,
                cookie.data + fields.tail_off, fields.tail_len,
                valid_seconds, difficulty,
                mcf->bv_secret, remote,
                ngx_unmask_get_host(r),
                id_out != NULL ? seed_id : NULL) == 1) {
            if (id_out != NULL) {
                /* The seed names the pass, not the nonce: any number of
                 * nonces answer one seed, one hashing run each, while a new
                 * seed costs a challenge served at a new second.  The
                 * cookie's own bytes hold no such string, so it is copied. */
                u_char *p = ngx_pnalloc(r->pool, UNMASK_BV_ID_LEN);
                if (p != NULL) {
                    ngx_memcpy(p, seed_id, UNMASK_BV_ID_LEN);
                    id_out->data = p;
                    id_out->len  = UNMASK_BV_ID_LEN;
                }
            }
            return UNMASK_BV_KIND_POW;
        }
        return UNMASK_BV_KIND_NONE;
    }

    /* CAPTCHA path: "day.sig.kind", sig = 16 hex of an HMAC. */
    int64_t cookie_unix = bv_atoll(cookie.data + fields.day_off, fields.day_len);
    if (cookie_unix < 0) return UNMASK_BV_KIND_NONE;

    /* Validity window in seconds.  Small forward tolerance absorbs clock
     * drift between the admin host that issued the cookie and this nginx
     * host. */
    int64_t now = (int64_t)ngx_time();
    if (cookie_unix > now + UNMASK_BV_FUTURE_SKEW_SECONDS) return UNMASK_BV_KIND_NONE;
    if (now - cookie_unix > mcf->bv_captcha_valid_seconds) return UNMASK_BV_KIND_NONE;

    /* `remote` (= client IP folded to /64 for IPv6) was computed once at the top
     * of this function from r->connection->addr_text -- after realip this is the
     * real client IP behind an LB, and matches the admin issuer's bindIP(). */

    /* $host (lowercased + port-stripped) binds the cookie to the vhost: a cookie
     * minted while solving site A's challenge fails on site B (different host ->
     * different signature).  The admin issuer folds in the same value
     * (X-Original-Host = $host), so the two stay byte-identical.  This replaces
     * the old $unmask_site kind-suffix scheme, which the admin never emitted. */
    ngx_str_t host = ngx_unmask_get_host(r);

    /* Build "<day>:<remote>:<host>:<kind>" in a pool buffer.  JA4 is deliberately
     * NOT included (behind an LB the issuer's forwarded JA4 and the verifier's
     * handshake JA4 diverge); remote_ip + host binding carry the replay defense. */
    size_t msg_len = fields.day_len + 1 + remote.len + 1 + host.len + 1 + fields.tail_len;
    u_char *msg = ngx_pnalloc(r->pool, msg_len);
    if (msg == NULL) return UNMASK_BV_KIND_NONE;
    u_char *p = msg;
    p = ngx_cpymem(p, cookie.data + fields.day_off, fields.day_len);  *p++ = ':';
    p = ngx_cpymem(p, remote.data, remote.len); *p++ = ':';
    if (host.len) { p = ngx_cpymem(p, host.data, host.len); } *p++ = ':';
    p = ngx_cpymem(p, cookie.data + fields.tail_off, fields.tail_len);

    /* The MAC, with every hash the daemon may have signed with
     * (ngx_unmask_sig_hashes); the signature is its first 16 hex digits. */
    int sig_ok = 0;
    for (size_t hi = 0; hi < ngx_unmask_sig_hash_count && !sig_ok; hi++) {
        unsigned char mac[EVP_MAX_MD_SIZE];
        unsigned int mac_len = sizeof(mac);
        if (HMAC(ngx_unmask_sig_hashes[hi](),
                 mcf->bv_secret.data, mcf->bv_secret.len,
                 msg, msg_len,
                 mac, &mac_len) == NULL || mac_len < 8) {
            continue;
        }
        char expected[16];
        ngx_unmask_hex(expected, mac, 8);
        /* Constant-time over the 16 hex digits the cookie carries. */
        if (ngx_unmask_ct_memcmp(expected, cookie.data + fields.sig_off, 16) == 0) {
            sig_ok = 1;
        }
    }
    if (sig_ok) {
        /* Which 3-segment form is it?  The kind segment is inside the HMAC
         * input above, so by the time we are here it is the admin's own word
         * for how this entry was earned -- a client cannot rewrite it without
         * invalidating the signature.  Read it rather than assuming CAPTCHA;
         * see the enum for what that assumption cost.
         *
         * A kind this plugin does not know does not verify at all.  An
         * earlier shape read it as "other" (verified, grade unknown), which
         * was honest about the grade but still a pass -- and the PoW seed,
         * signed over the same message shape with "pow_seed" in the kind
         * slot, is exactly such an unknown kind (see the enum comment).  The
         * list below is the admin's issuing vocabulary; it refuses the rest. */
        ngx_unmask_bv_kind_t k = UNMASK_BV_KIND_NONE;
        if (UNMASK_TAIL_IS(fields, cookie, "rebind"))           k = UNMASK_BV_KIND_REBIND;
        else if (UNMASK_TAIL_IS(fields, cookie, "passthrough")) k = UNMASK_BV_KIND_PASSTHROUGH;
        else if (UNMASK_TAIL_IS(fields, cookie, "captcha"))     k = UNMASK_BV_KIND_CAPTCHA;
        else if (UNMASK_TAIL_IS(fields, cookie, "pow"))         k = UNMASK_BV_KIND_POW;
        if (k != UNMASK_BV_KIND_NONE && id_out != NULL) {
            /* The signature is the pass's identity: 16 hex digits over the
             * issue time, the bind key, the host and the kind, minted by
             * the daemon alone. */
            id_out->data = cookie.data + fields.sig_off;
            id_out->len  = UNMASK_BV_ID_LEN;
        }
        return k;
    }
    return UNMASK_BV_KIND_NONE;
}

/* Verify a `_bv` cookie VALUE, which may be a "~"-joined list of up to
 * MaxBVEntries per-IP signatures (= a roaming client accumulates one per
 * network it solved on, so 5G<->wifi switching doesn't re-challenge).  Splits
 * on '~' and returns the first entry whose kind verifies for the current IP;
 * the per-entry 80-byte / format / HMAC / PoW checks live in verify_one.
 * `budget` is how many entries this REQUEST may still verify, shared across
 * every `_bv=` pair the client sent (kind_compute below): the cap used to be
 * per value, and the number of values was unbounded, so a Cookie header of
 * a few KB of `_bv=` pairs cost the worker one HMAC and SHA-256 per 35 bytes,
 * two or three times per request as the templates read the variable.  MUST
 * mirror cookies.Verify's any-match in the Go package. */
#define UNMASK_BV_VERIFY_BUDGET 16

static ngx_unmask_bv_kind_t
ngx_unmask_bv_verify_value(ngx_http_request_t *r,
                           ngx_http_ja4_main_conf_t *mcf,
                           ngx_str_t value, int *budget, ngx_str_t *id_out)
{
    u_char *p   = value.data;
    u_char *end = value.data + value.len;

    while (p < end && *budget > 0) {
        u_char   *tilde = ngx_strlchr(p, end, '~');
        ngx_str_t entry;
        entry.data = p;
        entry.len  = (size_t)((tilde ? tilde : end) - p);
        (*budget)--;
        /* id_out: the pass's identity, set with the kind -- what
         * $unmask_bv_id names, so the per-pass rate key follows the pass
         * rather than the address it arrives from. */
        ngx_unmask_bv_kind_t k = ngx_unmask_bv_verify_one(r, mcf, entry, id_out);
        if (k != UNMASK_BV_KIND_NONE) {
            return k;
        }
        if (tilde == NULL) break;
        p = tilde + 1;
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
ngx_unmask_bv_kind_compute(ngx_http_request_t *r, ngx_str_t *id_out)
{
    ngx_http_ja4_main_conf_t *mcf =
        ngx_http_get_module_main_conf(r, ngx_http_unmask_module);
    if (mcf == NULL) {
        return UNMASK_BV_KIND_NONE;
    }
    if (mcf->bv_secret.len == 0) {
        /* Nothing can verify.  Said once a minute: the module used to reject
         * every cookie in silence, and the only symptom was a challenge
         * loop. */
        if (ngx_unmask_log_due(UNMASK_LOG_SECRET_EMPTY)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                          "unmask: unmask_bv_secret is empty; "
                          "every _bv cookie is rejected and every visitor "
                          "is challenged again");
        }
        return UNMASK_BV_KIND_NONE;
    }

    /* $http_cookie is nginx's own join of every Cookie header line ("; "
     * separated, both before and after the 1.23 header-list rework), so a single
     * scan still sees every `_bv` the client sent.  Read the VARIABLE, not
     * r->headers_in.cookie / .cookies: on a host whose nginx has a patched
     * ngx_http_request_t (ABI note above) those members resolve to a neighbouring
     * header, `_bv` is never found, and a visitor who solved the challenge is
     * challenged again on every request. */
    static ngx_str_t cookie_var = ngx_string("http_cookie");
    ngx_str_t header;

    if (ngx_unmask_var_str(r, &cookie_var, &header) != NGX_OK
        || header.len == 0) {
        return UNMASK_BV_KIND_NONE;
    }

    size_t off = 0;
    ngx_str_t cookie;
    int budget = UNMASK_BV_VERIFY_BUDGET;
    while (budget > 0 && ngx_unmask_next_bv_value(header, &off, &cookie)) {
        ngx_unmask_bv_kind_t k = ngx_unmask_bv_verify_value(r, mcf, cookie, &budget, id_out);
        if (k != UNMASK_BV_KIND_NONE) {
            return k;
        }
    }
    return UNMASK_BV_KIND_NONE;
}

/* The request's kind, computed once (see ngx_http_unmask_req_ctx_t). */
static ngx_unmask_bv_kind_t
ngx_unmask_bv_kind(ngx_http_request_t *r)
{
    ngx_http_unmask_req_ctx_t *ctx = ngx_unmask_req_ctx(r);
    ngx_str_t id = ngx_null_string;
    ngx_unmask_bv_kind_t k;

    if (ctx != NULL && ctx->bv_done) {
        return ctx->bv_kind;
    }
    k = ngx_unmask_bv_kind_compute(r, &id);
    if (ctx != NULL) {
        ctx->bv_kind = k;
        ctx->bv_done = 1;
        if (k != UNMASK_BV_KIND_NONE && id.len == UNMASK_BV_ID_LEN) {
            u_char *p = ngx_pnalloc(r->pool, id.len);
            if (p != NULL) {
                ngx_memcpy(p, id.data, id.len);
                ctx->bv_id.data = p;
                ctx->bv_id.len  = id.len;
            }
        }
    }
    return k;
}

/* $unmask_bv_id: the identity of the pass that verified, 16 hex digits --
 * the signature of a CAPTCHA-form entry (CAPTCHA, re-bound, passthrough,
 * the math fallback's "pow"), or for a proof-of-work entry the first digits
 * of the seed it answers -- and "" when none did.  The per-pass reuse cap
 * keys on it (http.inc): that cap is about how much one pass is used for,
 * and keyed by the address a pass was issued on it counted an office or a
 * carrier NAT as one holder.  The seed and not the nonce, because any number
 * of nonces answer one seed, one hashing run each, while a new seed costs a
 * challenge served at a new second; the daemon derives the same string
 * (cookies.PassID), and the two MUST stay byte-identical. */
static ngx_int_t
ngx_http_unmask_bv_id_variable(ngx_http_request_t *r,
                               ngx_http_variable_value_t *v, uintptr_t data)
{
    static const u_char empty[] = "";
    ngx_http_unmask_req_ctx_t *ctx;
    (void)data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    (void)ngx_unmask_bv_kind(r);
    ctx = ngx_http_get_module_ctx(r, ngx_http_unmask_module);
    if (ctx != NULL && ctx->bv_id.len > 0) {
        v->data = ctx->bv_id.data;
        v->len  = ctx->bv_id.len;
    } else {
        v->data = (u_char *)empty;
        v->len  = 0;
    }
    return NGX_OK;
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
    static const u_char rebind[]  = "rebind";
    static const u_char passth[]  = "passthrough";
    static const u_char empty[]   = "";

    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    switch (ngx_unmask_bv_kind(r)) {
    case UNMASK_BV_KIND_CAPTCHA:
        v->data = (u_char *)captcha;
        v->len  = sizeof(captcha) - 1;
        break;
    case UNMASK_BV_KIND_POW:
        v->data = (u_char *)pow;
        v->len  = sizeof(pow) - 1;
        break;
    case UNMASK_BV_KIND_REBIND:
        v->data = (u_char *)rebind;
        v->len  = sizeof(rebind) - 1;
        break;
    case UNMASK_BV_KIND_PASSTHROUGH:
        v->data = (u_char *)passth;
        v->len  = sizeof(passth) - 1;
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
    v->data = (ngx_unmask_bv_kind(r) == want)
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
 * Change watch: the first lookup in a request calls stat() (mtime, size and
 * inode compared) and reloads on a change; the answer is kept in the request
 * ctx for every later evaluation in that request.
 * Sorted ASC by "ip|ja4"; lookup is bsearch O(log N).
 * ============================================================================ */

#include <sys/stat.h>

typedef struct { char *key; char *action; } ngx_unmask_ban_row_t;

static int unmask_ban_row_cmp(const void *a, const void *b) {
    return strcmp(((const ngx_unmask_ban_row_t *)a)->key,
                  ((const ngx_unmask_ban_row_t *)b)->key);
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
    ngx_unmask_ban_cidr_t *cidrs =
        (ngx_unmask_ban_cidr_t *)malloc((maxk + 1) * sizeof(*cidrs));
    if (!cidrs) { free(actions); free(keys); free(buf); return -1; }
    size_t ncidr = 0;
    cap = maxk;
    (void)cap;

    /* split by '\n' in-place */
    size_t nk = 0;
    int sorted = 1;
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
            char *p2 = NULL;
            if (p1 != NULL) {
                p2 = (char *)memchr(p1 + 1, '|', (size_t)(ln_end - (p1 + 1)));
                if (p2 != NULL) {
                    *p2 = '\0';
                    char *p3 = (char *)memchr(p2 + 1, '|', (size_t)(ln_end - (p2 + 1)));
                    if (p3 != NULL && p3 + 1 < ln_end) {
                        act = p3 + 1;
                    }
                }
            }
            /* An ip-only line whose address carries a prefix length
             * ("2001:db8:1:2::/64|", "203.0.113.0/24|") is a prefix ban:
             * parsed once here, matched by mask after the exact keys.  A
             * line that does not parse is skipped rather than kept as a
             * key no address could ever equal. */
            if (p1 != NULL && memchr(ln_start, '/', (size_t)(p1 - ln_start)) != NULL
                && (p2 == NULL ? (p1 + 1 == ln_end) : (p2 == p1 + 1)))
            {
                ngx_str_t  txt;
                ngx_int_t  rc;
                txt.data = (u_char *)ln_start;
                txt.len  = (size_t)(p1 - ln_start);
                rc = ngx_ptocidr(&txt, &cidrs[ncidr].cidr);
                if (rc == NGX_OK || rc == NGX_DONE) {
                    cidrs[ncidr].action = (char *)act;
                    ncidr++;
                }
            } else {
                keys[nk] = ln_start;
                actions[nk] = (char *)act;
                if (nk > 0 && sorted && strcmp(keys[nk - 1], keys[nk]) > 0) {
                    sorted = 0;
                }
                nk++;
            }
        }
        if (nl == NULL) break;
        p = nl + 1;
    }
    /* sort ASC by key (= ip|ja4), each action travelling with its key.  The
     * daemon writes the file sorted, but a hand-written or an older file is
     * not, and the insertion sort this replaces walked a few ten thousand
     * unsorted lines for seconds, inside a request, on every worker; its
     * out-of-memory fallback sorted keys[] alone and left actions[] behind. */
    if (nk > 1 && !sorted) {
        ngx_unmask_ban_row_t *rows =
            (ngx_unmask_ban_row_t *)malloc(nk * sizeof(*rows));
        if (rows == NULL) {
            free(cidrs); free(keys); free(actions); free(buf);
            return -1;
        }
        for (size_t i = 0; i < nk; i++) {
            rows[i].key = keys[i];
            rows[i].action = actions[i];
        }
        qsort(rows, nk, sizeof(*rows), unmask_ban_row_cmp);
        for (size_t i = 0; i < nk; i++) {
            keys[i] = rows[i].key;
            actions[i] = rows[i].action;
        }
        free(rows);
    }

    /* swap into global */
    char *old_buf = ngx_unmask_banlist.buf;
    char **old_keys = ngx_unmask_banlist.keys;
    char **old_actions = ngx_unmask_banlist.actions;
    ngx_unmask_ban_cidr_t *old_cidrs = ngx_unmask_banlist.cidrs;
    ngx_unmask_banlist.buf = buf;
    ngx_unmask_banlist.keys = keys;
    ngx_unmask_banlist.actions = actions;
    ngx_unmask_banlist.nkeys = nk;
    ngx_unmask_banlist.cidrs = cidrs;
    ngx_unmask_banlist.ncidrs = ncidr;
    free(old_buf);
    free(old_keys);
    free(old_actions);
    free(old_cidrs);
    return 0;
}

/* Prefix bans: the client's address against every /len row.  Linear, but
 * the rows are the daemon's escalations and an operator's CIDRs, a handful
 * at most, and this runs once per request after the exact lookups missed. */
static int ngx_unmask_banlist_cidr_lookup(struct sockaddr *sa,
                                          const char **action_out)
{
    size_t i;

    if (sa == NULL) return 0;
    for (i = 0; i < ngx_unmask_banlist.ncidrs; i++) {
        ngx_unmask_ban_cidr_t *e = &ngx_unmask_banlist.cidrs[i];
        if (e->cidr.family != (ngx_uint_t) sa->sa_family) continue;
#if (NGX_HAVE_INET6)
        if (sa->sa_family == AF_INET6) {
            u_char *a = ((struct sockaddr_in6 *) sa)->sin6_addr.s6_addr;
            ngx_uint_t n;
            for (n = 0; n < 16; n++) {
                if ((a[n] & e->cidr.u.in6.mask.s6_addr[n])
                    != e->cidr.u.in6.addr.s6_addr[n])
                {
                    break;
                }
            }
            if (n == 16) {
                if (action_out) *action_out = e->action;
                return 1;
            }
            continue;
        }
#endif
        if (sa->sa_family == AF_INET) {
            in_addr_t a = ((struct sockaddr_in *) sa)->sin_addr.s_addr;
            if ((a & e->cidr.u.in.mask) == e->cidr.u.in.addr) {
                if (action_out) *action_out = e->action;
                return 1;
            }
        }
    }
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


/* Lazy reload when the file changed (mtime, size or inode): one stat() per
 * request, from the ban lookup below. */
static void ngx_unmask_maybe_reload_banlist(const char *path, ngx_log_t *log) {
    struct stat st;
    if (stat(path, &st) != 0) {
        int err = errno;
        /* file gone -> empty list.  Said when it is not merely absent: a
         * permission or label change leaves every ban unenforced, and that
         * is invisible from a module that stays silent. */
        if (err == ENOENT) {
            /* Absent is normal only before the daemon's first write; an
             * operator reads this at the "error" level the distributions
             * ship, so it says what is (not) enforced. */
            if (ngx_unmask_log_due(UNMASK_LOG_BAN_MISSING)) {
                ngx_log_error(NGX_LOG_NOTICE, log, 0,
                              "unmask: ban file \"%s\" does not exist; "
                              "no ban is enforced until the daemon writes it",
                              path);
            }
        } else if (ngx_unmask_log_due(UNMASK_LOG_BAN_STAT)) {
            ngx_log_error(NGX_LOG_ERR, log, err,
                          "unmask: ban file \"%s\" cannot be read by this "
                          "worker; no ban is enforced (check the directory "
                          "and file permissions: unmask doctor)", path);
        }
        if (ngx_unmask_banlist.nkeys != 0 || ngx_unmask_banlist.ncidrs != 0) {
            free(ngx_unmask_banlist.buf);
            free(ngx_unmask_banlist.keys);
            free(ngx_unmask_banlist.actions);
            free(ngx_unmask_banlist.cidrs);
            ngx_unmask_banlist.buf = NULL;
            ngx_unmask_banlist.keys = NULL;
            ngx_unmask_banlist.actions = NULL;
            ngx_unmask_banlist.cidrs = NULL;
            ngx_unmask_banlist.nkeys = 0;
            ngx_unmask_banlist.ncidrs = 0;
            ngx_unmask_banlist.mtime = 0;
            ngx_unmask_banlist.size = 0;
            ngx_unmask_banlist.ino = 0;
        }
        return;
    }
    if (st.st_mtime == ngx_unmask_banlist.mtime
        && st.st_size == ngx_unmask_banlist.size
        && st.st_ino == ngx_unmask_banlist.ino) {
        return;
    }
    if (ngx_unmask_load_banlist(path) == 0) {
        ngx_unmask_banlist.mtime = st.st_mtime;
        ngx_unmask_banlist.size = st.st_size;
        ngx_unmask_banlist.ino = st.st_ino;
    } else if (ngx_unmask_log_due(UNMASK_LOG_BAN_LOAD)) {
        ngx_log_error(NGX_LOG_ERR, log, errno,
                      "unmask: ban file \"%s\" could not be loaded; "
                      "the previous list stays in force", path);
    }
}

/* One ban-file lookup per request (see ngx_http_unmask_req_ctx_t): the list
 * is (re)loaded if the file changed, then the client's "<ip>|<ja4>" key is
 * tried, then the JA4-only "|<ja4>" shape (scope ja4_only), then the IP-only
 * "<ip>|" shape (scope ip_only: every JA4 from this source, a compromised
 * host or a scraper farm across changing TLS stacks).  Later calls in the
 * same request answer from the ctx. */
static void
ngx_unmask_ban_lookup_req(ngx_http_request_t *r, int *hit, ngx_str_t *action)
{
    ngx_http_unmask_req_ctx_t *ctx = ngx_unmask_req_ctx(r);
    ngx_http_ja4_main_conf_t *mcf;
    char path[1024];
    char key[256];
    const u_char *ip;
    size_t iplen;
    u_char *ja4_data = (u_char *)"";
    size_t  ja4_len  = 0;
    const char *act = "";
    int found = 0;

    *hit = 0;
    action->len = 0;
    action->data = (u_char *)"";

    if (ctx != NULL && ctx->ban_done) {
        *hit = ctx->ban_hit;
        *action = ctx->ban_action;
        return;
    }

    mcf = ngx_http_get_module_main_conf(r, ngx_http_unmask_module);
    if (mcf == NULL || mcf->ban_file_path.len == 0
        || mcf->ban_file_path.len >= sizeof(path))
    {
        goto done;
    }
    /* Make a NUL-terminated path (= ngx_str_t is not NUL-terminated). */
    ngx_memcpy(path, mcf->ban_file_path.data, mcf->ban_file_path.len);
    path[mcf->ban_file_path.len] = '\0';

    ngx_unmask_maybe_reload_banlist(path, r->connection->log);
    if (ngx_unmask_banlist.nkeys == 0 && ngx_unmask_banlist.ncidrs == 0) {
        goto done;
    }

    ip = r->connection->addr_text.data;
    iplen = r->connection->addr_text.len;
    if (iplen == 0 || iplen > 80) {
        goto done;
    }
    /* fetch ja4 string (= same pattern as $unmask_bv_kind). */
    if (r->connection->ssl) {
        SSL *ssl_obj = r->connection->ssl->connection;
        if (ssl_obj && ngx_http_ja4_ssl_ex_data_idx >= 0) {
            ngx_http_ja4_ctx_t *jctx = SSL_get_ex_data(
                ssl_obj, ngx_http_ja4_ssl_ex_data_idx);
            ngx_unmask_ja4_apply_transport(r, jctx);  /* 't' -> 'q' for HTTP/3 */
            if (jctx && jctx->ja4.len > 0) {
                ja4_data = jctx->ja4.data;
                ja4_len  = jctx->ja4.len;
            }
        }
    }
    if (iplen + 1 + ja4_len + 1 > sizeof(key)) {
        goto done;
    }
    ngx_memcpy(key, ip, iplen);
    key[iplen] = '|';
    if (ja4_len) ngx_memcpy(key + iplen + 1, ja4_data, ja4_len);
    key[iplen + 1 + ja4_len] = '\0';
    found = ngx_unmask_banlist_lookup(key, &act);
    if (!found && ja4_len > 0) {
        key[0] = '|';
        ngx_memcpy(key + 1, ja4_data, ja4_len);
        key[1 + ja4_len] = '\0';
        found = ngx_unmask_banlist_lookup(key, &act);
    }
    if (!found) {
        ngx_memcpy(key, ip, iplen);
        key[iplen] = '|';
        key[iplen + 1] = '\0';
        found = ngx_unmask_banlist_lookup(key, &act);
    }
    if (!found && ngx_unmask_banlist.ncidrs > 0) {
        found = ngx_unmask_banlist_cidr_lookup(r->connection->sockaddr, &act);
    }
    if (found) {
        *hit = 1;
        if (act != NULL && *act != '\0') {
            /* Copied out: the list's buffer is freed by the next reload, and
             * this request may still be reading its answer after one. */
            size_t alen = strlen(act);
            u_char *p = ngx_pnalloc(r->pool, alen);
            if (p != NULL) {
                ngx_memcpy(p, (const u_char *)act, alen);
                action->data = p;
                action->len = alen;
            }
        }
    }

done:
    if (ctx != NULL) {
        ctx->ban_done = 1;
        ctx->ban_hit = (*hit != 0);
        ctx->ban_action = *action;
    }
}

static ngx_int_t ngx_http_unmask_banned_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    static const char zero[] = "0";
    static const char one[]  = "1";
    int hit = 0;
    ngx_str_t action;

    (void)data;
    v->len = 1;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    ngx_unmask_ban_lookup_req(r, &hit, &action);
    v->data = (u_char *)(hit ? one : zero);
    return NGX_OK;
}

/* $unmask_ban_action: returns the per-row action token on hit
 * (= "deny" / "pow_only" / "pow_then_captcha" / "captcha_only") so the
 * server-block render can switch the response (= return 403 vs rewrite
 * to /unmask/challenge/).  Empty string when not banned. */
static ngx_int_t ngx_http_unmask_ban_action_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    int hit = 0;
    ngx_str_t action;

    (void)data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;
    ngx_unmask_ban_lookup_req(r, &hit, &action);
    v->data = action.data;
    v->len = action.len;
    return NGX_OK;
}

/* unmask_has_signed_agent: walk the inbound headers for "Signature-Input".
 * Returns "1" when present (non-empty), "0" otherwise.  Header name match
 * is case-insensitive per HTTP, so we use ngx_strncasecmp.  No allocation
 * on the hot path -- the two output strings are static.
 *
 * Subrequests always report "0".  Subrequests share headers_in with the
 * main request, and nginx re-runs server-scope rewrite directives for
 * them -- so without this guard the auth_request subrequest that the
 * signed-route itself issues (uri /_unmask/_signed_verify) matches the
 * server-scope signed-route gate again and gets rewritten away from the
 * verify proxy, and the daemon is never consulted.  The variable means
 * "the CLIENT's request carries a signature", which is only ever a
 * property of the main request. */
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

    /* Subrequests always report "0" -- see the comment above.  The test goes
     * through the POST_READ marker rather than `r == r->main`, which is one of
     * the fields a patched ngx_http_request_t shifts (ABI note above): reading it
     * there yields NULL, this guard fires for EVERY request, and the variable is
     * stuck at "0" so the signed-route gate never engages. */
    if (!ngx_unmask_is_main_request(r)) {
        return NGX_OK;
    }

    /* headers_in.headers sits at offset 0 of headers_in, so walking the header
     * list stays correct even where the rest of the struct is shifted. */
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

/* unmask_client_net: the rate-limit key.  Reads the (realip-rewritten)
 * connection address -- exactly like $binary_remote_addr -- and folds it to a
 * network granularity so one client can't multiply its rate budget by rotating
 * source addresses:
 *   IPv4          -> the 4 address bytes (= /32, same as $binary_remote_addr)
 *   IPv4-mapped v6-> the embedded IPv4 (4 bytes), so it keys identically to v4
 *   IPv6          -> the /64 (first 8 bytes); a v6 client owns a whole /64 and
 *                    its privacy-extension addresses rotate within it
 * Binary value (like $binary_remote_addr); mirrors the _bv cookie's IPv6 /64
 * binding so the two layers agree on "a /64 is one client". */
static ngx_int_t
ngx_http_unmask_client_net_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data)
{
    struct sockaddr *sa = r->connection->sockaddr;
    u_char *p;

    (void) data;
    v->valid = 1;
    v->no_cacheable = 1;
    v->not_found = 0;

    if (sa != NULL && sa->sa_family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) sa;
        u_char *a = sin6->sin6_addr.s6_addr;
        ngx_uint_t i, mapped = 1;
        for (i = 0; i < 10; i++) {
            if (a[i] != 0) { mapped = 0; break; }
        }
        if (mapped && a[10] == 0xff && a[11] == 0xff) {
            /* IPv4-mapped -> key on the embedded IPv4. */
            p = ngx_pnalloc(r->pool, 4);
            if (p == NULL) return NGX_ERROR;
            ngx_memcpy(p, a + 12, 4);
            v->data = p; v->len = 4;
        } else {
            /* /64 = the first 8 bytes. */
            p = ngx_pnalloc(r->pool, 8);
            if (p == NULL) return NGX_ERROR;
            ngx_memcpy(p, a, 8);
            v->data = p; v->len = 8;
        }
        return NGX_OK;
    }

    if (sa != NULL && sa->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) sa;
        p = ngx_pnalloc(r->pool, 4);
        if (p == NULL) return NGX_ERROR;
        ngx_memcpy(p, &sin->sin_addr.s_addr, 4);
        v->data = p; v->len = 4;
        return NGX_OK;
    }

    /* Unknown family (= unix socket, etc.): empty key (degenerate but safe -- a
     * non-IP connection never reaches the public rate-limited paths). */
    v->data = (u_char *) "";
    v->len = 0;
    return NGX_OK;
}
