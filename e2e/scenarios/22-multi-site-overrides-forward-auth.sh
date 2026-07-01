#!/bin/bash
# 22: multi-site overrides through Apache forward-auth mode.
#
# Mirror of scenario 21 (= native nginx multi-site) but driven through the
# Apache mod_lua forward-auth integration.  The fixture lives in
# e2e/docker/admin/admin.yml (= shared with 21):
#
#   bypass_paths.paths:
#     - "^/e2e-shop-bypass/"  site=shop.example.com
#   honeypot.urls:
#     - "^/shop-trap/"        site=shop.example.com
#   protected_paths.paths:
#     - "^/admin-shop/"  mode=captcha  site=shop.example.com   (from scenario 19)
#
# In forward-auth mode the per-site decision is made entirely by admin's
# /_unmask/check handler (= the lua passes the original Host header in
# X-Original-Host and branches on the X-Unmask-Action response).  Native
# mode rebuilds the same decision out of nginx maps at $host scope;
# scenarios 19 + 21 cover that path.  This scenario closes the loop by
# proving admin's Resolve* helpers + the lua handler agree end-to-end.
#
# The Apache backend has a single VirtualHost on :8081 with no ServerName,
# so it accepts any Host header.  Paths that don't exist in DocumentRoot
# (= /e2e-shop-bypass/foo, /shop-trap/foo, /unrelated/foo, /admin-shop/foo)
# 404 when admin grants "pass".  Admin's "challenge" verdict becomes a 302
# to /unmask/challenge/.  The 302 vs 404 split is the verdict signal.
#
# Each case sends a fresh X-Forwarded-For (RFC 5737 TEST-NET-3) so the
# scenarios don't bleed honeypot / ban state into one another.
#
# Assertions (8):
#   (a) shop /e2e-shop-bypass/ + curl UA       -> 404 (bypass fires)
#   (b) shop /e2e-shop-bypass/ + browser UA    -> 404 (bypass for browser)
#   (c) blog /e2e-shop-bypass/ + curl UA       -> 302 (no bypass)
#   (d) shop /shop-trap/foo                    -> 302 (honeypot fires)
#   (e) blog /shop-trap/foo                    -> 404 (no honeypot)
#   (f) shop /unrelated/                       -> 404 (no over-match)
#   (g) shop /admin-shop/foo                   -> 302 (protected fires)
#   (h) blog /admin-shop/foo                   -> 404 (no protected)

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# probe(host, path, ua, xff) -> echoes status; writes body to $tmpdir/body.
probe() {
    local host="$1" path="$2" ua="$3" xff="$4"
    curl -s -A "$ua" \
        -H "Host: $host" \
        -H "X-Forwarded-For: $xff" \
        -o "$tmpdir/body" -w '%{http_code}' \
        "${APACHE_URL}${path}"
}

# expect(label, expected_code, actual_code) -> log_pass / log_fail.
expect() {
    local desc="$1" want="$2" got="$3"
    if [ "$want" = "$got" ]; then
        log_pass "$desc (status=$got)"
        return 0
    fi
    log_fail "$desc: expected status=$want got=$got"
    head -c 200 "$tmpdir/body" >&2; printf '\n' >&2
    return 1
}

fails=0

# (a) shop /e2e-shop-bypass/ + curl UA -> bypass.  Admin returns pass (200);
# the lua hands the request back to Apache (DECLINED), which 404s the
# nonexistent file under DocumentRoot.
code=$(probe shop.example.com /e2e-shop-bypass/foo "$UA_CURL" 198.51.100.41)
expect "(a) shop /e2e-shop-bypass/ + curl UA -> bypassed" 404 "$code" || fails=$((fails+1))

# (b) shop /e2e-shop-bypass/ + browser UA -> same bypass; control case so
# the bypass is verified to short-circuit independent of UA.
code=$(probe shop.example.com /e2e-shop-bypass/foo "$UA_BROWSER" 198.51.100.42)
expect "(b) shop /e2e-shop-bypass/ + browser UA -> bypassed" 404 "$code" || fails=$((fails+1))

# (c) blog /e2e-shop-bypass/ + curl UA -> bypass is shop-only, so the
# UA-blacklist axis fires the challenge -> admin returns 401 -> lua emits
# the 302 redirect to /unmask/challenge/.
code=$(probe blog.example.com /e2e-shop-bypass/foo "$UA_CURL" 198.51.100.43)
expect "(c) blog /e2e-shop-bypass/ + curl UA -> challenge" 302 "$code" || fails=$((fails+1))

# (d) shop /shop-trap/foo -> honeypot fires.  $serve_bot_challenge=1 forces
# the chain regardless of UA / cookie state -> admin returns 401 -> 302.
code=$(probe shop.example.com /shop-trap/foo "$UA_BROWSER" 198.51.100.44)
expect "(d) shop /shop-trap/ + browser UA -> honeypot fires" 302 "$code" || fails=$((fails+1))

# (e) blog /shop-trap/foo -> honeypot row is shop-only.  Browser UA passes
# the UA-blacklist axis -> admin returns pass (200) -> Apache 404.
code=$(probe blog.example.com /shop-trap/foo "$UA_BROWSER" 198.51.100.45)
expect "(e) blog /shop-trap/ + browser UA -> no honeypot" 404 "$code" || fails=$((fails+1))

# (f) shop /unrelated/ + browser UA -> nothing matches; control for the
# per-host maps not over-applying to every path under shop.example.com.
code=$(probe shop.example.com /unrelated/foo "$UA_BROWSER" 198.51.100.46)
expect "(f) shop /unrelated/ -> no over-match" 404 "$code" || fails=$((fails+1))

# (g) shop /admin-shop/foo -> per-site protected fires (mode=captcha).
# Verifies the same admin-side per-site decision used by native scenario 19
# also produces a challenge through the Apache forward-auth path.
code=$(probe shop.example.com /admin-shop/foo "$UA_BROWSER" 198.51.100.47)
expect "(g) shop /admin-shop/ -> protected fires" 302 "$code" || fails=$((fails+1))

# (h) blog /admin-shop/foo -> same path, no per-site protected row, no
# global rule -> admin returns pass -> Apache 404.
code=$(probe blog.example.com /admin-shop/foo "$UA_BROWSER" 198.51.100.48)
expect "(h) blog /admin-shop/ -> no protected" 404 "$code" || fails=$((fails+1))

exit "$fails"
