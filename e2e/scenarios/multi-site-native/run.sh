#!/bin/bash
# multi-site-native (phase 2.2): one unmask-admin + native unmask module
# fronts 3 vhosts.  Verifies that per-site ProtectedPaths overrides land
# correctly via the rendered $protected_mode_host_<host> / disable maps in
# /etc/unmask/native/http.inc.
#
# Assertions:
#   1. shop.local/admin/    -> challenge fires (default protected_paths /admin/)
#   2. shop.local/checkout/ -> challenge fires (per-site Append /checkout/)
#   3. blog.local/admin/    -> NO challenge (per-site Remove ["/admin/"] honored)
#   4. blog.local/anything/ -> NO challenge (no protected match)
#   5. default.example/admin/    -> challenge fires (default inherited)
#   6. default.example/checkout/ -> NO challenge (shop's Append doesn't leak)
#
# Each curl uses --resolve so the vhost names don't need /etc/hosts entries on
# the host.  The compose stack publishes nginx on :8445 (not :8444 -- avoids
# colliding with the auth_request multi-site-basic scenario).

set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
# shellcheck source=../../lib/assert.sh
. "$ROOT/lib/assert.sh"

PORT="${PORT:-8445}"
COMPOSE="$DIR/docker-compose.yml"

# Bring the stack up if it isn't already; trap to tear down on exit.
manage_stack=0
if [ -z "$(docker compose -f "$COMPOSE" ps -q admin 2>/dev/null)" ]; then
    manage_stack=1
    log "bringing the multi-site-native stack up..."
    docker compose -f "$COMPOSE" up -d --build --wait >/dev/null
    trap 'docker compose -f "$COMPOSE" down -v >/dev/null 2>&1 || true' EXIT
fi

# Real browser UA so assertions 3/4/6 don't get challenged by the Global axis.
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'

fetch() {
    local host="$1" path="$2"; shift 2
    curl -sk \
        --resolve "${host}:${PORT}:127.0.0.1" \
        -A "$UA" \
        -w '\n__HTTP_STATUS__:%{http_code}' \
        "$@" \
        "https://${host}:${PORT}${path}"
}
status_of() { echo "$1" | awk -F: '/^__HTTP_STATUS__:/ {print $2}'; }
body_of()   { echo "$1" | awk 'BEGIN{f=1} /^__HTTP_STATUS__:/{f=0;next} f'; }
is_challenge_html() { echo "$1" | grep -q 'window\.UNMASK'; }

fails=0

# ---------------------------------------------------------------------------
# 1. shop.local/admin/ -> challenge fires (default /admin/ inherited)
# ---------------------------------------------------------------------------
out=$(fetch shop.local /admin/)
body=$(body_of "$out")
if is_challenge_html "$body"; then
    log_pass "1 shop /admin/ -> challenge fired (default protected_paths)"
else
    log_fail "1 shop /admin/: no challenge HTML in response\n--- body head ---\n$(echo "$body" | head -8)"
    fails=$((fails+1))
fi

# ---------------------------------------------------------------------------
# 2. shop.local/checkout/ -> challenge fires (per-site Append /checkout/)
# ---------------------------------------------------------------------------
out=$(fetch shop.local /checkout/)
body=$(body_of "$out")
if is_challenge_html "$body"; then
    log_pass "2 shop /checkout/ -> challenge fired (per-site Append)"
else
    log_fail "2 shop /checkout/: no challenge HTML in response\n--- body head ---\n$(echo "$body" | head -8)"
    fails=$((fails+1))
fi

# ---------------------------------------------------------------------------
# 3. blog.local/admin/ -> NO challenge (per-site Remove honored via disable map)
# ---------------------------------------------------------------------------
out=$(fetch blog.local /admin/)
body=$(body_of "$out")
if is_challenge_html "$body"; then
    log_fail "3 blog /admin/: challenge fired despite Remove override\n--- body head ---\n$(echo "$body" | head -8)"
    fails=$((fails+1))
elif echo "$body" | grep -q '\[blog.local OK /admin/\]'; then
    log_pass "3 blog /admin/ -> no challenge (Remove override honored via disable map)"
else
    log_fail "3 blog /admin/: unexpected body\n$body"
    fails=$((fails+1))
fi

# ---------------------------------------------------------------------------
# 4. blog.local/anything/ -> NO challenge (no protected match anywhere)
# ---------------------------------------------------------------------------
out=$(fetch blog.local /anything/)
body=$(body_of "$out")
if is_challenge_html "$body"; then
    log_fail "4 blog /anything/: unexpected challenge\n--- body head ---\n$(echo "$body" | head -8)"
    fails=$((fails+1))
elif echo "$body" | grep -q '\[blog.local OK /anything/\]'; then
    log_pass "4 blog /anything/ -> 200 pass-through"
else
    log_fail "4 blog /anything/: unexpected body\n$body"
    fails=$((fails+1))
fi

# ---------------------------------------------------------------------------
# 5. default.example/admin/ -> challenge fires (default rules inherited)
# ---------------------------------------------------------------------------
out=$(fetch default.example /admin/)
body=$(body_of "$out")
if is_challenge_html "$body"; then
    log_pass "5 default /admin/ -> challenge fired (default inherited)"
else
    log_fail "5 default /admin/: no challenge HTML in response\n--- body head ---\n$(echo "$body" | head -8)"
    fails=$((fails+1))
fi

# ---------------------------------------------------------------------------
# 6. default.example/checkout/ -> NO challenge (shop's Append doesn't leak)
# ---------------------------------------------------------------------------
out=$(fetch default.example /checkout/)
body=$(body_of "$out")
if is_challenge_html "$body"; then
    log_fail "6 default /checkout/: challenge fired despite per-host Append being shop-only\n--- body head ---\n$(echo "$body" | head -8)"
    fails=$((fails+1))
elif echo "$body" | grep -q '\[default.example OK /checkout/\]'; then
    log_pass "6 default /checkout/ -> 200 pass-through (shop's Append is host-scoped)"
else
    log_fail "6 default /checkout/: unexpected body\n$body"
    fails=$((fails+1))
fi

echo
if [ "$fails" -eq 0 ]; then
    log_pass "multi-site-native: all 6 assertions PASS"
else
    log_fail "multi-site-native: $fails assertion(s) FAILED"
fi

exit "$fails"
