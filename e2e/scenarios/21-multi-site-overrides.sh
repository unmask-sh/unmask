#!/bin/bash
# 21: multi-site overrides — bypass_paths + honeypot URLs branch on $host.
#
# Scenario 16 verified the site value is recorded; 19 verified protected_paths
# branches per-site.  This scenario closes the remaining axes:
#
#   * bypass_paths.paths[].site  — bypass fires only on the named host
#   * honeypot.urls[].site       — honeypot trap fires only on the named host
#
# The render-time host dispatcher in admin/internal/nginxconf/templates/http.conf.tmpl
# stitches per-site path maps onto $host; this test drives /api/check via the
# native nginx path with distinct Host headers (resolved through curl --resolve)
# and confirms the chained $is_bypass_path / $serve_bot_challenge variables
# only react on the configured site.
#
# Fixture (e2e/docker/admin/admin.yml):
#   bypass_paths.paths:
#     - path: "^/e2e-shop-bypass/", site: "shop.example.com"
#   honeypot.urls:
#     - path: "^/shop-trap/",       site: "shop.example.com"
#
# Assertions (7):
#   (a) shop /e2e-shop-bypass/ + curl UA       -> bypassed (fc=0)
#   (b) shop /e2e-shop-bypass/ + browser UA    -> bypassed (fc=0)
#   (c) blog /e2e-shop-bypass/ + curl UA       -> challenge fires (fc=1)
#   (d) shop /shop-trap/foo                    -> honeypot fires (fc=1)
#   (e) blog /shop-trap/foo                    -> no honeypot   (fc=0)
#   (f) shop /unrelated/                       -> normal pass   (fc=0)
#   (g) /etc/unmask/native/http.inc contains the per-host map for shop

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

PORT=$(echo "$BASE_URL" | sed -nE 's|^https?://[^:/]+:([0-9]+).*|\1|p')
PORT=${PORT:-8443}
RESOLVE_IP=127.0.0.1

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# probe(host, path, ua, [xff]) -> echoes status; writes body to $tmpdir/body.
probe() {
    local host="$1" path="$2" ua="$3" xff="${4:-}"
    local args=(
        -sk -A "$ua"
        --resolve "${host}:${PORT}:${RESOLVE_IP}"
        -o "$tmpdir/body" -w '%{http_code}'
    )
    if [ -n "$xff" ]; then
        args+=(-H "X-Forwarded-For: $xff")
    fi
    args+=("https://${host}:${PORT}${path}")
    curl "${args[@]}"
}

fails=0

# (a) shop /e2e-shop-bypass/ + curl UA -> bypassed.  Even though curl is in
# the UA blacklist, the per-site bypass map yields is_bypass_path=1, which
# short-circuits the challenge chain.
code_a=$(probe shop.example.com /e2e-shop-bypass/foo "$UA_CURL" 198.51.100.21)
body_a=$(cat "$tmpdir/body")
if [ "$code_a" = "200" ] && echo "$body_a" | grep -qE 'fc=0'; then
    log_pass "(a) shop /e2e-shop-bypass/ + curl UA -> bypassed (fc=0)"
else
    log_fail "(a) shop /e2e-shop-bypass/ + curl UA: expected fc=0/200, got status=$code_a"
    head -c 200 "$tmpdir/body" >&2; printf '\n' >&2
    fails=$((fails+1))
fi

# (b) shop /e2e-shop-bypass/ + browser UA -> bypassed (no challenge would
# have fired here anyway; assert the bypass is a no-op for friendly clients).
code_b=$(probe shop.example.com /e2e-shop-bypass/foo "$UA_BROWSER" 198.51.100.22)
body_b=$(cat "$tmpdir/body")
if [ "$code_b" = "200" ] && echo "$body_b" | grep -qE 'fc=0'; then
    log_pass "(b) shop /e2e-shop-bypass/ + browser UA -> pass (fc=0)"
else
    log_fail "(b) shop /e2e-shop-bypass/ + browser UA: expected fc=0/200, got status=$code_b"
    head -c 200 "$tmpdir/body" >&2; printf '\n' >&2
    fails=$((fails+1))
fi

# (c) blog /e2e-shop-bypass/ + curl UA -> challenge fires.  The bypass row
# is scoped to shop.example.com; on blog.example.com the per-host map yields
# empty -> $is_bypass_path falls back to the global map (no global rule
# matches), so the curl UA still gets challenged.
code_c=$(probe blog.example.com /e2e-shop-bypass/foo "$UA_CURL" 198.51.100.23)
body_c=$(cat "$tmpdir/body")
if echo "$body_c" | grep -qE 'fc=1'; then
    log_pass "(c) blog /e2e-shop-bypass/ + curl UA -> fc=1 (no per-site bypass)"
elif [ "$code_c" = "302" ] || [ "$code_c" = "403" ]; then
    log_pass "(c) blog /e2e-shop-bypass/ + curl UA -> challenge status $code_c"
else
    log_fail "(c) blog /e2e-shop-bypass/ + curl UA: expected challenge, got status=$code_c"
    head -c 200 "$tmpdir/body" >&2; printf '\n' >&2
    fails=$((fails+1))
fi

# (d) shop /shop-trap/foo -> honeypot fires.  $serve_bot_challenge=1 forces
# the chain irrespective of UA / cookie state.
code_d=$(probe shop.example.com /shop-trap/foo "$UA_BROWSER" 198.51.100.24)
body_d=$(cat "$tmpdir/body")
if echo "$body_d" | grep -qE 'hp=1|fc=1'; then
    log_pass "(d) shop /shop-trap/ -> honeypot fires"
elif [ "$code_d" = "302" ] || [ "$code_d" = "403" ]; then
    log_pass "(d) shop /shop-trap/ -> challenge status $code_d"
else
    log_fail "(d) shop /shop-trap/: expected honeypot, got status=$code_d"
    head -c 200 "$tmpdir/body" >&2; printf '\n' >&2
    fails=$((fails+1))
fi

# (e) blog /shop-trap/foo -> no honeypot.  Same path, different host -> the
# per-host honeypot map yields empty, global rule list has no /shop-trap/
# entry, $serve_bot_challenge=0.
code_e=$(probe blog.example.com /shop-trap/foo "$UA_BROWSER" 198.51.100.25)
body_e=$(cat "$tmpdir/body")
if [ "$code_e" = "200" ] && echo "$body_e" | grep -qE 'hp=0' && echo "$body_e" | grep -qE 'fc=0'; then
    log_pass "(e) blog /shop-trap/ -> no honeypot (hp=0 fc=0)"
else
    log_fail "(e) blog /shop-trap/: expected hp=0/fc=0/200, got status=$code_e"
    head -c 200 "$tmpdir/body" >&2; printf '\n' >&2
    fails=$((fails+1))
fi

# (f) shop /unrelated/ -> normal pass.  Asserts the per-host maps don't
# over-match (= a rule that fires on every path under shop.example.com).
code_f=$(probe shop.example.com /unrelated/foo "$UA_BROWSER" 198.51.100.26)
body_f=$(cat "$tmpdir/body")
if [ "$code_f" = "200" ] && echo "$body_f" | grep -qE 'fc=0'; then
    log_pass "(f) shop /unrelated/ -> fc=0 (no over-match)"
else
    log_fail "(f) shop /unrelated/: expected fc=0/200, got status=$code_f"
    head -c 200 "$tmpdir/body" >&2; printf '\n' >&2
    fails=$((fails+1))
fi

# (g) Rendered http.inc must contain the shop-specific maps.  Skip if the
# rendered file is not reachable from the harness (= the test ran against a
# remote BASE_URL or compose isn't running locally).
COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
if [ -f "$COMPOSE" ] && docker compose -f "$COMPOSE" ps admin >/dev/null 2>&1; then
    rendered=$(docker compose -f "$COMPOSE" exec -T admin cat /etc/unmask/native/http.inc 2>/dev/null || true)
    # Both the per-host bypass map (= unmask_bp_host_shop_example_com on
    # /e2e-shop-bypass/) and the per-host honeypot map (= unmask_hp_host_*
    # on /shop-trap/) must be present in the rendered http.inc.  Each map
    # spans multiple lines, so check for the named map and the path entry
    # separately rather than trying to grep across lines.
    if echo "$rendered" | grep -qE '\$unmask_bp_host_shop_example_com' \
       && echo "$rendered" | grep -qF '/e2e-shop-bypass/' \
       && echo "$rendered" | grep -qE '\$unmask_hp_host_shop_example_com' \
       && echo "$rendered" | grep -qF '/shop-trap/'; then
        log_pass "(g) rendered http.inc contains per-host maps for shop"
    else
        log_fail "(g) rendered http.inc missing per-host maps for shop"
        printf '%s\n' "$rendered" | grep -E 'shop|e2e-shop|shop-trap' | head -20 >&2
        fails=$((fails+1))
    fi
else
    log_skip "(g) compose not reachable; skipped render inspection"
fi

exit "$fails"
