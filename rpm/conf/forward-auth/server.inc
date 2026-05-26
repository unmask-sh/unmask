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
#   @unmask_rate_challenge / @unmask_blocked / @unmask_fail_open / @unmask_admin_down
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
# The variables referenced in native mode (= when ngx_http_unmask_module is
# used) — $effective_ja4 / $ja4_verdict / $ja4_action / $serve_bot_challenge
# / $protected_mode / $unmask_banned — are satisfied by including
# /etc/unmask/native/http.inc in http {}.  In forward-auth mode, nginx treats
# unresolved variables as empty and falls through (= nginx v1.6+ treats
# undefined variables as empty strings, so it does not error out).

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
    proxy_pass        http://unmask_admin;
    proxy_set_header  Host          $host;
    proxy_set_header  X-Real-IP     $remote_addr;
    proxy_set_header  X-Client-JA4  $effective_ja4;
    proxy_set_header  X-JA4-Verdict $ja4_verdict;
    proxy_set_header  X-JA4-Action  $ja4_action;
    # Disable buffering so SSE (= /admin/api/events/stream) flows through.
    proxy_http_version 1.1;
    proxy_set_header   Connection "";
    proxy_buffering    off;
    proxy_cache        off;
    proxy_read_timeout 1h;
}

# /unmask/challenge/ — challenge HTML (= PoW / CAPTCHA).  Passes various hint headers.
# When the admin is down (= 502/503/504), fall back to @unmask_admin_down.
# Default behavior is 503 + Retry-After, but overriding @unmask_admin_down in
# a server block lets you fail-open (= pass through to the backend).
location ^~ /unmask/challenge/ {
    auth_request off;
    proxy_pass        http://unmask_admin;
    proxy_set_header  Host             $host;
    proxy_set_header  X-Real-IP        $remote_addr;
    proxy_set_header  X-Client-JA4     $effective_ja4;
    proxy_set_header  X-JA4-Verdict    $ja4_verdict;
    proxy_set_header  X-JA4-Action     $ja4_action;
    proxy_set_header  X-Honeypot-Hit   $serve_bot_challenge;
    proxy_set_header  X-Protected-Mode $protected_mode;
    proxy_set_header  X-Banned         $unmask_banned;
    proxy_intercept_errors on;
    error_page 502 503 504 = @unmask_admin_down;
}
location = /unmask/challenge.html {
    auth_request off;
    return 301 /unmask/challenge/$is_args$args;
}

# /unmask/api/  — verify endpoints (= POSTed by the challenge JS).
location ^~ /unmask/api/ {
    auth_request off;
    proxy_pass        http://unmask_admin;
    proxy_set_header  Host          $host;
    proxy_set_header  X-Real-IP     $remote_addr;
    proxy_set_header  X-Client-JA4  $effective_ja4;
    proxy_set_header  X-JA4-Verdict $ja4_verdict;
    proxy_set_header  X-JA4-Action  $ja4_action;
}

# /unmask/static/  — assets (= challenge.js / flag PNG etc.).
location ^~ /unmask/static/ {
    auth_request off;
    proxy_pass        http://unmask_admin;
    proxy_set_header  Host  $host;
}

# /unmask/_rl/  — challenge for rate-limit overage.  Rewritten from @unmask_rate_challenge.
location ^~ /unmask/_rl/ {
    auth_request off;
    proxy_pass        http://unmask_admin;
    proxy_set_header  Host             $host;
    proxy_set_header  X-Real-IP        $remote_addr;
    proxy_set_header  X-Client-JA4     $effective_ja4;
    proxy_set_header  X-JA4-Verdict    $ja4_verdict;
    proxy_set_header  X-JA4-Action     $ja4_action;
    proxy_set_header  X-Honeypot-Hit   $serve_bot_challenge;
    proxy_set_header  X-Protected-Mode $protected_mode;
    proxy_set_header  X-Banned         $unmask_banned;
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
    proxy_pass        http://unmask_admin;
    proxy_set_header  Host  $host;
}

# /unmask/healthz  — 200 health probe.
location = /unmask/healthz {
    auth_request off;
    proxy_pass        http://unmask_admin;
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
    proxy_pass        http://unmask_admin;
    proxy_set_header  Host             $host;
    proxy_set_header  X-Real-IP        $remote_addr;
    proxy_set_header  X-Client-JA4     $effective_ja4;
    proxy_set_header  X-JA4-Verdict    $ja4_verdict;
    proxy_set_header  X-JA4-Action     $ja4_action;
}

# /_unmask/check  — internal subrequest endpoint for forward-auth mode.
# External direct access is forbidden.  Harmless to keep even when running native mode.
location = /_unmask/check {
    internal;
    auth_request off;
    proxy_pass http://unmask_admin/unmask/api/check;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header Host             $host;
    proxy_set_header X-Original-URI   $request_uri;
    proxy_set_header X-Original-IP    $remote_addr;
    proxy_set_header X-Original-UA    $http_user_agent;
    proxy_set_header X-Original-Host  $host;
    proxy_set_header Cookie           $http_cookie;
    proxy_connect_timeout 1s;
    proxy_read_timeout    2s;
    proxy_send_timeout    1s;
    # fail-open when the admin is down.  For strict operation, delete the error_page line.
    proxy_intercept_errors on;
    error_page 502 503 504 = @unmask_fail_open;
}

# Internal target for auth_request 401 redirects (= used by protect.inc).
# Honeypot / future per-axis branches surface chMode via X-Unmask-Chmode →
# auth_request_set $unmask_chmode → here we forward as ?chm=<mode> so the
# challenge HTML JS skips PoW / goes straight to CAPTCHA / etc.  An empty
# $unmask_chmode adds ?chm= (= empty) which the serve handler ignores, so
# the default per-axis chain takes over.
location @unmask_to_challenge {
    rewrite ^ /unmask/challenge/?chm=$unmask_chmode? last;
}

# named locations.
location @unmask_blocked {
    add_header Content-Type "text/plain; charset=utf-8";
    return 403 "Access denied by unmask\n";
}
location @unmask_fail_open {
    return 204;
}

# fail-open hook when the admin daemon is down.  Default is 503 + Retry-After
# (= the LB notices via health check).  Overriding the same-named location in
# the user's server block switches to full fail-open that passes through to
# the backend.  Example:
#   location @unmask_admin_down {
#       proxy_pass http://backend;
#       proxy_set_header Host $host;
#   }
location @unmask_admin_down {
    add_header Retry-After "10" always;
    return 503 "unmask admin temporarily unavailable\n";
}
