# /etc/unmask/forward-auth/server.inc — forward-auth mode server-scope snippet.
#
# Usage: include from directly inside an existing server block via
# `include /etc/unmask/forward-auth/server.inc;`.
# That makes https://<your-host>/unmask/admin/ (= admin UI) and
# /unmask/challenge/ etc. reachable on that vhost.  To actually **protect**
# user paths (= fire the challenge), include protect.inc separately at
# server scope or inside the locations you want protected (= same 2-include
# pattern as native mode's /etc/unmask/native/{server,protect}.inc).
#
# Locations provided:
#   /unmask/admin/      → admin UI / dashboard
#   /unmask/challenge/  → challenge HTML (= PoW + CAPTCHA)
#   /unmask/api/        → verify endpoints
#   /unmask/static/     → assets
#   /unmask/_rl/        → rate-limit-triggered challenge
#   /unmask/healthz     → 200 health
#   /unmask/metrics     → Prometheus metrics (= localhost only)
#   /_unmask/check      → internal subrequest (= for forward-auth mode)
#   @unmask_rate_challenge / @unmask_blocked / @unmask_fail_open / @unmask_daemon_down
#
# Each /unmask/* location carries `auth_request off;` to avoid a self-loop if
# the server scope enables auth_request /_unmask/check; (= unmask itself does
# not self-check).  Exception: /unmask/admin/ is **not** opted out — the
# admin login page is itself a sensitive target, so when protect.inc is on
# the server and the protected-paths preset "unmask itself" is enabled,
# operators clear a CAPTCHA before reaching the login form.  Other /unmask/*
# (= challenge / api / static / _rl / test / healthz / metrics) and
# /_unmask/check keep auth_request off; to break the verify loop.
# When protect.inc is restricted to specific locations, the off is a harmless no-op.
#
# X-Client-JA4 is forwarded as $unmask_fa_ja4 — the LB-gated client JA4 defined
# by /var/lib/unmask/nginx/forward-auth-lbtrust.conf (rendered by `unmask
# render-nginx`; the unmask-web-nginx package symlinks it into conf.d/ so it
# loads in http {}).  That file ALWAYS defines $unmask_fa_ja4 (= "" when no
# trusted LB is configured), so this snippet parses with or without an LB.  The
# other verdict headers (X-JA4-Verdict / X-JA4-Action / X-Honeypot-Hit /
# X-Protected-Mode / X-Banned / X-Unmask-Site / X-Unmask-Conn-Peer) are blanked
# here and computed by the daemon; in hybrid setups that also load native
# http.inc you may instead wire the JA4 ones to the plugin maps ($effective_ja4
# / $ja4_verdict / ...).  X-Unmask-Conn-Peer is the Apache forward-auth LB-gate
# input; nginx gates the JA4 at the edge instead, so it is stripped here so a
# client can never inject it.

# /unmask/admin/  — admin UI / dashboard.  The allow list is rendered from
#                   config.yml's admin_allow_from; here we default to
#                   `allow all` (= login auth protects access).
# Self-protect ENABLED: unlike other /unmask/* paths, this carries its own
# auth_request (= same as protect.inc, baked in here) so that the protected-
# paths preset "unmask itself" works regardless of whether protect.inc is
# included at server scope.  Other /unmask/* below stay auth_request off; so
# the verify loop never reaches itself (= challenge / api / static / _check
# are exempt).
location ^~ /unmask/admin/ {
    auth_request /_unmask/check;
    error_page 401 = /unmask/challenge/;
    proxy_pass        http://unmask_daemon;
    proxy_set_header  Host          $host;
    proxy_set_header  X-Real-IP     $remote_addr;
    # Verdict-header strip: a visitor could otherwise send X-JA4-Verdict /
    # X-Unmask-Site etc. itself and have the daemon record a forged verdict /
    # honeypot hit / site identity (audit integrity).  These are blanked and
    # computed by the daemon.  X-Client-JA4 is the exception: it carries the
    # LB-gated $unmask_fa_ja4 (the daemon's JA4 input; "" off-LB), see the file
    # header.
    proxy_set_header  X-Client-JA4     $unmask_fa_ja4;
    proxy_set_header  X-Unmask-Conn-Peer "";
    proxy_set_header  X-JA4-Verdict    "";
    proxy_set_header  X-JA4-Action     "";
    proxy_set_header  X-Honeypot-Hit   "";
    proxy_set_header  X-Header-Mismatch "";
    proxy_set_header  X-Protected-Mode "";
    proxy_set_header  X-Banned         "";
    proxy_set_header  X-Unmask-Site    "";
    proxy_set_header  X-Original-Host  $host;
    proxy_set_header  X-Original-URI   $request_uri;
    proxy_set_header  X-Original-IP    $remote_addr;
    proxy_set_header  X-Original-UA    $http_user_agent;
    # Disable buffering so SSE (= /admin/api/events/stream) flows through.
    proxy_http_version 1.1;
    proxy_set_header   Connection "";
    proxy_buffering    off;
    proxy_cache        off;
    proxy_read_timeout 1h;
}

# /unmask/challenge/ — challenge HTML (= PoW / CAPTCHA).  Passes various hint headers.
# When the admin is down (= 502/503/504), fall back to @unmask_daemon_down.
# The default definition below redirects to / (fail-open: the request then
# flows through to the backend); define @unmask_daemon_down BEFORE this
# include (see the note at its definition below) to override — e.g. return
# 503 + Retry-After to fail closed so an upstream LB drains this node.
location ^~ /unmask/challenge/ {
    auth_request off;
    proxy_pass        http://unmask_daemon;
    proxy_set_header  Host             $host;
    proxy_set_header  X-Real-IP        $remote_addr;
    # Verdict-header strip (see /unmask/admin/ above): X-Client-JA4 carries the
    # LB-gated $unmask_fa_ja4; the rest are blanked (daemon-computed).
    proxy_set_header  X-Client-JA4     $unmask_fa_ja4;
    proxy_set_header  X-Unmask-Conn-Peer "";
    proxy_set_header  X-JA4-Verdict    "";
    proxy_set_header  X-JA4-Action     "";
    proxy_set_header  X-Honeypot-Hit   "";
    proxy_set_header  X-Header-Mismatch "";
    proxy_set_header  X-Protected-Mode "";
    proxy_set_header  X-Banned         "";
    proxy_set_header  X-Unmask-Site    "";
    proxy_set_header  X-Original-Host  $host;
    proxy_set_header  X-Original-URI   $request_uri;
    proxy_set_header  X-Original-IP    $remote_addr;
    proxy_set_header  X-Original-UA    $http_user_agent;
    proxy_intercept_errors on;
    error_page 502 503 504 = @unmask_daemon_down;
}
location = /unmask/challenge.html {
    auth_request off;
    return 301 /unmask/challenge/$is_args$args;
}

# /unmask/api/check — the forward-auth DECISION endpoint (records bans / counts
# rate by client IP).  Reached ONLY via the internal subrequest (/_unmask/check
# below), never directly.  This rendered config already forces X-Original-IP =
# $remote_addr in the /unmask/api/ block (so a direct client can only affect
# itself), but block the endpoint outright as defense-in-depth -- it is never a
# public endpoint.  Exact (`=`) match wins over the `^~ /unmask/api/` prefix.
location = /unmask/api/check { return 404; }

# /unmask/api/  — verify endpoints (= POSTed by the challenge JS).
location ^~ /unmask/api/ {
    auth_request off;
    proxy_pass        http://unmask_daemon;
    proxy_set_header  Host          $host;
    proxy_set_header  X-Real-IP     $remote_addr;
    # Verdict-header strip (see /unmask/admin/ above): X-Client-JA4 carries the
    # LB-gated $unmask_fa_ja4; the rest are blanked (daemon-computed).
    proxy_set_header  X-Client-JA4     $unmask_fa_ja4;
    proxy_set_header  X-Unmask-Conn-Peer "";
    proxy_set_header  X-JA4-Verdict    "";
    proxy_set_header  X-JA4-Action     "";
    proxy_set_header  X-Honeypot-Hit   "";
    proxy_set_header  X-Header-Mismatch "";
    proxy_set_header  X-Protected-Mode "";
    proxy_set_header  X-Banned         "";
    proxy_set_header  X-Unmask-Site    "";
    proxy_set_header  X-Original-Host  $host;
    proxy_set_header  X-Original-URI   $request_uri;
    proxy_set_header  X-Original-IP    $remote_addr;
    proxy_set_header  X-Original-UA    $http_user_agent;
}

# /unmask/static/  — assets (= challenge.js / flag PNG etc.).
location ^~ /unmask/static/ {
    auth_request off;
    proxy_pass        http://unmask_daemon;
    proxy_set_header  Host  $host;
}

# /unmask/_rl/  — challenge for rate-limit overage.  Rewritten from @unmask_rate_challenge.
location ^~ /unmask/_rl/ {
    auth_request off;
    proxy_pass        http://unmask_daemon;
    proxy_set_header  Host             $host;
    proxy_set_header  X-Real-IP        $remote_addr;
    # Verdict-header strip (see /unmask/admin/ above): X-Client-JA4 carries the
    # LB-gated $unmask_fa_ja4; the rest are blanked (daemon-computed).
    proxy_set_header  X-Client-JA4     $unmask_fa_ja4;
    proxy_set_header  X-Unmask-Conn-Peer "";
    proxy_set_header  X-JA4-Verdict    "";
    proxy_set_header  X-JA4-Action     "";
    proxy_set_header  X-Honeypot-Hit   "";
    proxy_set_header  X-Header-Mismatch "";
    proxy_set_header  X-Protected-Mode "";
    proxy_set_header  X-Banned         "";
    proxy_set_header  X-Unmask-Site    "";
    proxy_set_header  X-Original-Host  $host;
    proxy_set_header  X-Original-URI   $request_uri;
    proxy_set_header  X-Original-IP    $remote_addr;
    proxy_set_header  X-Original-UA    $http_user_agent;
    proxy_intercept_errors off;
}
location @unmask_rate_challenge {
    rewrite ^ /unmask/_rl$request_uri last;
}

# /unmask/metrics  — Prometheus metrics.  localhost only.
location = /unmask/metrics {
    auth_request off;
    allow 127.0.0.1;
    allow ::1;
    deny  all;
    proxy_pass        http://unmask_daemon;
    proxy_set_header  Host  $host;
}

# /unmask/healthz  — 200 health probe.
location = /unmask/healthz {
    auth_request off;
    proxy_pass        http://unmask_daemon;
    proxy_set_header  Host  $host;
}

# /unmask/test/  — public debug page (= cookie reset / forced PoW / forced CAPTCHA).
# The "public test page" toggle under admin settings → challenge tab flips
# this between 404 / 200 (= judged by the admin-side PublicTestGate).
# Matches the following 4 paths by prefix:
#   /unmask/test/                 index page
#   /unmask/test/reset-cookie
#   /unmask/test/force-pow
#   /unmask/test/force-captcha
# The admin-side /unmask/admin/test/ is handled separately by the
# /unmask/admin/ prefix location.
location ^~ /unmask/test/ {
    auth_request off;
    proxy_pass        http://unmask_daemon;
    proxy_set_header  Host             $host;
    proxy_set_header  X-Real-IP        $remote_addr;
    # Verdict-header strip (see /unmask/admin/ above): X-Client-JA4 carries the
    # LB-gated $unmask_fa_ja4; the rest are blanked (daemon-computed).
    proxy_set_header  X-Client-JA4     $unmask_fa_ja4;
    proxy_set_header  X-Unmask-Conn-Peer "";
    proxy_set_header  X-JA4-Verdict    "";
    proxy_set_header  X-JA4-Action     "";
    proxy_set_header  X-Honeypot-Hit   "";
    proxy_set_header  X-Header-Mismatch "";
    proxy_set_header  X-Protected-Mode "";
    proxy_set_header  X-Banned         "";
    proxy_set_header  X-Unmask-Site    "";
    proxy_set_header  X-Original-Host  $host;
    proxy_set_header  X-Original-URI   $request_uri;
    proxy_set_header  X-Original-IP    $remote_addr;
    proxy_set_header  X-Original-UA    $http_user_agent;
}

# /_unmask/check  — internal subrequest endpoint for forward-auth mode.
# External direct access is forbidden.  Harmless to keep even when running native mode.
location = /_unmask/check {
    internal;
    auth_request off;
    proxy_pass http://unmask_daemon/unmask/api/check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Host             $host;
    proxy_set_header X-Original-URI   $request_uri;
    proxy_set_header X-Original-IP    $remote_addr;
    proxy_set_header X-Original-UA    $http_user_agent;
    proxy_set_header X-Original-Host  $host;
    proxy_set_header Cookie           $http_cookie;
    # Verdict-header strip: the subrequest inherits the client's headers, so
    # blank the spoofable verdict set (see /unmask/admin/ above).  X-Client-JA4
    # carries the LB-gated $unmask_fa_ja4 = the daemon's JA4 input.
    proxy_set_header X-Client-JA4     $unmask_fa_ja4;
    proxy_set_header X-Unmask-Conn-Peer "";
    proxy_set_header X-JA4-Verdict    "";
    proxy_set_header X-JA4-Action     "";
    proxy_set_header X-Honeypot-Hit   "";
    proxy_set_header X-Header-Mismatch "";
    proxy_set_header X-Protected-Mode "";
    proxy_set_header X-Banned         "";
    proxy_set_header X-Unmask-Site    "";
    proxy_connect_timeout 1s;
    proxy_read_timeout    2s;
    proxy_send_timeout    1s;
    # fail-open when the admin is down.  For strict operation, delete the error_page line.
    proxy_intercept_errors on;
    error_page 502 503 504 = @unmask_fail_open;
}

# Internal target for auth_request 401 redirects (= used by protect.inc).
# Honeypot / rate-limit branches surface chMode via the admin's X-Unmask-Chmode
# response header; protect.inc captures it with
# `auth_request_set $unmask_chmode $upstream_http_x_unmask_chmode;` and native
# mode defines $unmask_chmode via http.inc's `map "" $unmask_chmode`.
# This snippet, however, must ALSO parse when server.inc is included WITHOUT
# protect.inc and WITHOUT the native http.inc — the documented setup-wizard
# step exposes /unmask/admin/ before protection is turned on.  In that
# standalone case $unmask_chmode is never registered, and nginx validates every
# referenced variable at config-init (even inside never-entered locations), so
# interpolating it here would abort `nginx -t` with
# `unknown "unmask_chmode" variable`.  We therefore redirect to the plain
# challenge URL.  The ?chm= hint (= rate-limit / honeypot pre-selecting CAPTCHA
# over PoW) is only an optimization: when it is absent the admin's serve handler
# falls back to the default per-axis chain.
location @unmask_to_challenge {
    rewrite ^ /unmask/challenge/ last;
}

# named locations.
# Block (ban / geo-deny / honeypot-deny / rate-deny): serve the daemon's branded
# "blocked" page from /unmask/_ban -- the same page native + apache mode serve, so
# DenyTheme / DenyCopyPreset / branding apply -- instead of a bare 403.  Wired
# from protect.inc's `error_page 403`.  If the admin is down the block still HOLDS
# (proxy_intercept_errors -> @unmask_blocked_down returns a bare 403, fail-closed).
location @unmask_blocked {
    rewrite ^ /unmask/_ban$request_uri break;
    proxy_pass        http://unmask_daemon;
    proxy_set_header  Host          $host;
    proxy_set_header  X-Real-IP     $remote_addr;
    # Strip admin-internal headers a blocked visitor must not smuggle (the block
    # decision is already made; this only keeps the recorded event honest).
    proxy_set_header  X-Banned         "";
    proxy_set_header  X-JA4-Verdict    "";
    proxy_set_header  X-JA4-Action     "";
    proxy_set_header  X-Honeypot-Hit   "";
    proxy_set_header  X-Header-Mismatch "";
    proxy_set_header  X-Protected-Mode "";
    proxy_set_header  X-Unmask-Site    "";
    proxy_intercept_errors on;
    error_page 502 503 504 = @unmask_blocked_down;
}
# Admin unreachable while serving the blocked page: keep the block (fail-closed).
location @unmask_blocked_down {
    add_header Content-Type "text/plain; charset=utf-8";
    return 403 "Access denied by unmask\n";
}
location @unmask_fail_open {
    return 204;
}

# Daemon-down fallback for the /unmask/* serving paths.  Protected user paths
# already FAIL OPEN by default (auth_request -> @unmask_fail_open -> backend);
# this only catches a visitor who is mid-challenge (on /unmask/challenge/) at
# the instant the daemon dies.  DEFAULT: fail open too — 302 the visitor to "/",
# which re-enters the site and passes through to the backend via the
# auth_request fail-open.  This mirrors native mode (= @unmask_daemon_down
# replays the original request), so forward-auth is fully fail-open by default.
# (We redirect to "/" rather than the original URL on purpose: deriving the
# target from a request arg would open a redirect-injection hole, and native's
# internal replay can't be reproduced from a static include.)
#
# To fail CLOSED instead (= 503 so an upstream LB drains this node via its
# health check, OR pass the original request to your own backend), define the
# same-named location BEFORE the `include` of this file — nginx keeps the FIRST
# definition of a named location, so one placed after the include is silently
# ignored.  Examples (above the include line):
#   # (a) fail closed so the LB drains this node:
#   location @unmask_daemon_down { add_header Retry-After "10" always; return 503; }
#   # (b) pass the original request straight to your backend:
#   location @unmask_daemon_down { proxy_pass http://backend; proxy_set_header Host $host; }
#   include /etc/unmask/forward-auth/server.inc;
location @unmask_daemon_down {
    return 302 /;
}
