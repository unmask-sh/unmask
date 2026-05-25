#!/bin/bash
# multi-site-basic (phase 1.5): one unmask instance fronts 2 vhosts and a
# default catch-all.  Verifies that per-site Branding / ProtectedPaths
# overrides land correctly on the challenge page + auth_request decisions.
#
# Assertions:
#   1. shop.local/unmask/challenge/  -> brand.site_name == "Shop Co" + logo_url
#   2. blog.local/unmask/challenge/  -> brand.site_name == "Blog Co" + copy_preset minimal
#   3. shop.local/admin/             -> challenge fires (HTML body has window.UNMASK)
#   4. shop.local/checkout/          -> challenge fires (append override)
#   5. blog.local/admin/             -> NO challenge (remove override; body == "[blog.local OK /admin/]")
#   6. shop.local/static/foo.txt     -> passes (no protected match)
#   7. default.example/unmask/challenge/ -> brand.site_name == "Default Co" (top-level fallthrough)
#
# Each curl uses --resolve so the vhost names don't need /etc/hosts entries on
# the host.  The compose stack publishes nginx on :8444 so it can run in
# parallel with the main e2e suite on :8443.

set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$DIR/../.." && pwd)"
# shellcheck source=../../lib/assert.sh
. "$ROOT/lib/assert.sh"

PORT="${PORT:-8444}"
COMPOSE="$DIR/docker-compose.yml"

# Bring the stack up if it isn't already; trap to tear down on exit.
manage_stack=0
if [ -z "$(docker compose -f "$COMPOSE" ps -q admin 2>/dev/null)" ]; then
    manage_stack=1
    log "bringing the multi-site-basic stack up..."
    docker compose -f "$COMPOSE" up -d --build --wait >/dev/null
    trap 'docker compose -f "$COMPOSE" down -v >/dev/null 2>&1 || true' EXIT
fi

# Real browser UA so assertions 5/6 don't get challenged by the Global axis.
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36'

# curl wrapper.  $1 = host, $2 = path, then extra args.  Echoes "STATUS\nBODY".
fetch() {
    local host="$1" path="$2"; shift 2
    curl -sk \
        --resolve "${host}:${PORT}:127.0.0.1" \
        -A "$UA" \
        -w '\n__HTTP_STATUS__:%{http_code}' \
        "$@" \
        "https://${host}:${PORT}${path}"
}

# Split fetch output: status (last line after the marker) + body (everything before).
status_of() { echo "$1" | awk -F: '/^__HTTP_STATUS__:/ {print $2}'; }
body_of()   { echo "$1" | awk 'BEGIN{f=1} /^__HTTP_STATUS__:/{f=0;next} f'; }

# Extract the embedded /*__BRANDING__*/{...} JSON from challenge.html and
# read site_name / copy_preset / logo_url fields out of it.  The braces are
# the regex anchor; the body is anything until the first `}` after the marker.
brand_json() {
    echo "$1" | grep -oE '/\*__BRANDING__\*/\{[^}]+\}' | sed 's|/\*__BRANDING__\*/||' | head -1
}
brand_field() {
    # $1 = JSON, $2 = field name
    echo "$1" | grep -oE "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" | head -1 | sed -E "s/\"$2\"[[:space:]]*:[[:space:]]*\"([^\"]*)\"/\1/"
}

# Detect that a response carries the challenge HTML (= has the UNMASK init script).
is_challenge_html() {
    echo "$1" | grep -q 'window\.UNMASK'
}

fails=0

# ---------------------------------------------------------------------------
# 1. shop.local challenge page -> Shop Co + shop-logo
# ---------------------------------------------------------------------------
out=$(fetch shop.local /unmask/challenge/)
body=$(body_of "$out")
brand=$(brand_json "$body")
if [ -z "$brand" ]; then
    log_fail "1 shop branding: no /*__BRANDING__*/ JSON in challenge HTML\n--- body head ---\n$(echo "$body" | head -20)"
    fails=$((fails+1))
else
    name=$(brand_field "$brand" site_name)
    logo=$(brand_field "$brand" logo_url)
    assert_eq "Shop Co" "$name" "1 shop branding: site_name" || fails=$((fails+1))
    if echo "$logo" | grep -q '/branding/logo'; then
        log_pass "1 shop branding: logo_url present ($logo)"
    else
        log_fail "1 shop branding: logo_url missing/unexpected (got '$logo')"
        fails=$((fails+1))
    fi
fi

# ---------------------------------------------------------------------------
# 2. blog.local challenge page -> Blog Co + copy_preset minimal
# ---------------------------------------------------------------------------
out=$(fetch blog.local /unmask/challenge/)
body=$(body_of "$out")
brand=$(brand_json "$body")
if [ -z "$brand" ]; then
    log_fail "2 blog branding: no /*__BRANDING__*/ JSON in challenge HTML"
    fails=$((fails+1))
else
    name=$(brand_field "$brand" site_name)
    preset=$(brand_field "$brand" copy_preset)
    assert_eq "Blog Co" "$name"     "2 blog branding: site_name" || fails=$((fails+1))
    assert_eq "minimal" "$preset"   "2 blog branding: copy_preset" || fails=$((fails+1))
fi

# ---------------------------------------------------------------------------
# 3. shop.local/admin/ -> challenge fires (default /admin/ retained)
# ---------------------------------------------------------------------------
out=$(fetch shop.local /admin/)
body=$(body_of "$out")
if is_challenge_html "$body"; then
    log_pass "3 shop /admin/ -> challenge fired (default protected_paths)"
else
    log_fail "3 shop /admin/: no challenge HTML in response\n--- body head ---\n$(echo "$body" | head -8)"
    fails=$((fails+1))
fi

# ---------------------------------------------------------------------------
# 4. shop.local/checkout/ -> challenge fires (override.append /checkout/)
# ---------------------------------------------------------------------------
out=$(fetch shop.local /checkout/)
body=$(body_of "$out")
if is_challenge_html "$body"; then
    log_pass "4 shop /checkout/ -> challenge fired (override append)"
else
    log_fail "4 shop /checkout/: no challenge HTML in response\n--- body head ---\n$(echo "$body" | head -8)"
    fails=$((fails+1))
fi

# ---------------------------------------------------------------------------
# 5. blog.local/admin/ -> NO challenge (override.remove ["/admin/"])
# ---------------------------------------------------------------------------
out=$(fetch blog.local /admin/)
body=$(body_of "$out")
if is_challenge_html "$body"; then
    log_fail "5 blog /admin/: challenge fired despite remove override\n--- body head ---\n$(echo "$body" | head -8)"
    fails=$((fails+1))
elif echo "$body" | grep -q '\[blog.local OK /admin/\]'; then
    log_pass "5 blog /admin/ -> no challenge (remove override honored)"
else
    log_fail "5 blog /admin/: unexpected body\n$body"
    fails=$((fails+1))
fi

# ---------------------------------------------------------------------------
# 6. shop.local/static/foo.txt -> passes (no protected match for /static/)
# ---------------------------------------------------------------------------
out=$(fetch shop.local /static/foo.txt)
status=$(status_of "$out")
body=$(body_of "$out")
if is_challenge_html "$body"; then
    log_fail "6 shop /static/foo.txt: challenge fired unexpectedly\n--- body head ---\n$(echo "$body" | head -8)"
    fails=$((fails+1))
elif [ "$status" = "200" ] && echo "$body" | grep -q '\[shop.local OK /static/foo.txt\]'; then
    log_pass "6 shop /static/foo.txt -> 200 pass-through"
else
    log_fail "6 shop /static/foo.txt: unexpected (status=$status)\nbody=$body"
    fails=$((fails+1))
fi

# ---------------------------------------------------------------------------
# 7. default.example/unmask/challenge/ -> top-level Branding fall-through
# ---------------------------------------------------------------------------
out=$(fetch default.example /unmask/challenge/)
body=$(body_of "$out")
brand=$(brand_json "$body")
if [ -z "$brand" ]; then
    log_fail "7 default branding: no /*__BRANDING__*/ JSON in challenge HTML"
    fails=$((fails+1))
else
    name=$(brand_field "$brand" site_name)
    assert_eq "Default Co" "$name" "7 default branding: site_name fallback" || fails=$((fails+1))
fi

echo
if [ "$fails" -eq 0 ]; then
    log_pass "multi-site-basic: all 7 assertions PASS"
else
    log_fail "multi-site-basic: $fails assertion(s) FAILED"
fi

exit "$fails"
