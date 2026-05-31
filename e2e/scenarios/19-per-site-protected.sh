#!/bin/bash
# 19: per-site protected paths — the same /admin-shop/ path triggers different
# behaviour on shop.example.com vs blog.example.com.  Scenario 16 verifies
# the site value is *recorded* in unmask_event; 19 verifies the *nginx
# render* (= the http.conf.tmpl host dispatcher) actually branches on it.
#
# Fixture (e2e/docker/admin/admin.yml):
#   nginx.protected_paths.paths:
#     - path: "^/admin-shop/"
#       mode: "captcha"
#       site: "shop.example.com"
#
# Expectations:
#   (a) Host=shop.example.com  /admin-shop/foo  -> challenge fires (fc=1 / 403)
#   (b) Host=blog.example.com  /admin-shop/foo  -> pass through    (fc=0)
#   (c) Host=shop.example.com  /unrelated/      -> pass through    (fc=0)

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

# Extract the port from BASE_URL (https://localhost:8443 -> 8443) so the
# scenario also works when BASE_URL is overridden.
PORT=$(echo "$BASE_URL" | sed -nE 's|^https?://[^:/]+:([0-9]+).*|\1|p')
PORT=${PORT:-8443}
RESOLVE_IP=127.0.0.1

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# IP isolation: dedicated XFF keeps prior-scenario honeypot bans (= ban on
# the shared docker IP) from masking the per-host protected_mode test.
CLIENT_IP=198.51.100.190

# probe(host, path) -> echoes status code, writes body to $tmpdir/body.
probe() {
    local host="$1" path="$2"
    curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" \
        --resolve "${host}:${PORT}:${RESOLVE_IP}" \
        -o "$tmpdir/body" -w '%{http_code}' \
        "https://${host}:${PORT}${path}"
}

fails=0

# (a) shop /admin-shop/ -> protected_mode=captcha -> challenge.  nginx may
# either redirect to /unmask/challenge/ (= status 302) or, for unsupported
# request shapes, fall through to @echo with fc=1.  Accept any signal that
# isn't a clean fc=0 + 200 pair.
code_a=$(probe shop.example.com /admin-shop/foo)
body_a=$(cat "$tmpdir/body")
if echo "$body_a" | grep -qE 'fc=1'; then
    log_pass "(a) shop.example.com /admin-shop/ → fc=1 (protected fires)"
elif [ "$code_a" = "302" ] || [ "$code_a" = "403" ]; then
    log_pass "(a) shop.example.com /admin-shop/ → challenge status $code_a"
else
    log_fail "(a) shop.example.com /admin-shop/: expected challenge, got status=$code_a"
    head -c 200 "$tmpdir/body" >&2
    fails=$((fails+1))
fi

# (b) blog /admin-shop/ -> the per-host map yields "" so $protected_mode
# falls back to global ("" because no global rule matches), and the request
# walks straight to @echo with fc=0.
code_b=$(probe blog.example.com /admin-shop/foo)
body_b=$(cat "$tmpdir/body")
if [ "$code_b" = "200" ] && echo "$body_b" | grep -qE 'fc=0'; then
    log_pass "(b) blog.example.com /admin-shop/ → fc=0 (per-host map returns empty)"
else
    log_fail "(b) blog.example.com /admin-shop/: expected fc=0, got status=$code_b"
    head -c 200 "$tmpdir/body" >&2
    fails=$((fails+1))
fi

# (c) shop /unrelated/ -> the per-host map doesn't match the path, so
# protected_mode stays empty and the request passes through.  Ensures the
# per-host map doesn't accidentally over-match.
code_c=$(probe shop.example.com /unrelated/foo)
body_c=$(cat "$tmpdir/body")
if [ "$code_c" = "200" ] && echo "$body_c" | grep -qE 'fc=0'; then
    log_pass "(c) shop.example.com /unrelated/ → fc=0 (path outside rule)"
else
    log_fail "(c) shop.example.com /unrelated/: expected fc=0, got status=$code_c"
    head -c 200 "$tmpdir/body" >&2
    fails=$((fails+1))
fi

exit "$fails"
