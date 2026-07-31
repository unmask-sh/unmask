#!/bin/bash
# 51: range-verified crawler rescue — genuine crawler, auto fallback, and the
# explicit (decoupled) lists.
#
# Scenario 15 pins the spoof side (a Googlebot UA from a non-Google IP gets
# challenged).  This one pins the other contracts of uarange.go on the
# forward-auth endpoint, where the daemon re-reads everything on restart:
#
#   A. genuine crawler: a Googlebot UA from inside Google's published ranges
#      passes via the bypass-IP set (reason=bypass:ip).  Simulated by writing
#      an iprange override file (the hub-sync target) containing a test CIDR
#      and restarting the admin.
#   B. auto fallback: with no explicit lists saved, disabling the vendor's
#      range presets reverts that vendor to UA-only rescue (reason carries
#      search_ai again) — never "UA dropped AND ranges off" by default.
#   C. explicit UA-off: search_bots.upstream_disabled beats the auto
#      fallback — presets off AND the pattern disabled = no rescue at all
#      (both axes off is reachable only through explicit choices).
#   D. explicit UA opt-in vs the ON-by-default require_range_verification
#      policy: the policy outranks the row, the UA stays closed.
#   E. policy off + the same opt-in: search_bots.upstream_ua_enabled keeps the UA line
#      although every preset is live (the OR state — either axis passes).
#
# Needs the docker e2e stack (it writes files inside the admin container and
# restarts it); skips cleanly when the suite targets a remote BASE_URL.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
if ! command -v docker >/dev/null 2>&1 || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q admin 2>/dev/null)" ]; then
    log_skip "51-crawler-range-inversion needs the docker e2e stack (admin container) — skipped"
    exit 0
fi

ADMIN_URL=${ADMIN_URL:-http://127.0.0.1:19477}
OVERRIDE=/var/lib/unmask/iprange/googlebot.json
CONF=/etc/unmask/admin.yml
# RFC 5737-adjacent fixture IPs, distinct from other scenarios' ban state.
IP_IN_RANGE=7.7.7.7
IP_OUT_RANGE=7.7.8.7

admin_exec() {
    docker compose -f "$COMPOSE" exec -T --user root admin sh -c "$1"
}
healthz() {
    curl -s -o /dev/null -w '%{http_code}' --max-time 3 "${ADMIN_URL}/unmask/healthz"
}
wait_healthz_200() {
    local i
    for i in $(seq 1 30); do
        [ "$(healthz)" = 200 ] && return 0
        sleep 1
    done
    return 1
}
restart_admin() {
    docker compose -f "$COMPOSE" stop admin >/dev/null 2>&1
    docker compose -f "$COMPOSE" start admin >/dev/null 2>&1
    wait_healthz_200
}
# X-Unmask-Reason for a Googlebot UA from $1 (same header protocol as 05).
reason_for_ip() {
    local hdrfile
    hdrfile=$(mktemp)
    curl -sk -o /dev/null -D "$hdrfile" --max-time 5 -A "$UA_GOOGLEBOT" \
        -H "X-Original-URI: /any" -H "X-Original-IP: $1" \
        "${ADMIN_URL}/unmask/api/check"
    grep -i '^X-Unmask-Reason:' "$hdrfile" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//'
    rm -f "$hdrfile"
}

# Restore everything on the way out; keep assert.sh's exit guard semantics
# (same pattern as scenario 49).
MUTATED=0
cleanup() {
    local rc=$?
    if [ "$MUTATED" = "1" ]; then
        admin_exec "rm -f '$OVERRIDE'; [ -f '$CONF.bak51' ] && mv '$CONF.bak51' '$CONF'" >/dev/null 2>&1 || true
        restart_admin || { log_fail "cleanup: admin did not come back healthy"; rc=1; }
    fi
    if [ "$rc" -eq 0 ] && [ "${_E2E_FAILS:-0}" -gt 0 ]; then
        exit 1
    fi
    exit "$rc"
}
trap cleanup EXIT

# Baseline sanity: from outside every vendor range the Googlebot UA is a
# spoof — no search_ai, no bypass:ip (the detailed spoof pins live in 15/05).
r=$(reason_for_ip "$IP_IN_RANGE")
case "$r" in
    *search_ai*|*bypass:ip*)
        log_fail "baseline: spoofed Googlebot already rescued (reason=$r) — override leaked from a previous run?"
        exit 1
        ;;
    *) log_pass "baseline: spoofed Googlebot not rescued (reason=$r)" ;;
esac

# A. Genuine crawler: put a test CIDR into the google-common override file
#    (exactly what the hub sync writes) and restart.  7.7.7.7 now counts as a
#    published Google address, so the UA+range pair passes by IP.
MUTATED=1
admin_exec "cp '$CONF' '$CONF.bak51' && mkdir -p \"\$(dirname '$OVERRIDE')\" && printf '%s' '{\"creationTime\":\"2026-07-16T00:00:00.000000\",\"prefixes\":[{\"ipv4Prefix\":\"7.7.7.0/24\"}]}' > '$OVERRIDE'"
if ! restart_admin; then
    log_fail "admin did not come back after the override restart (healthz $(healthz))"
    exit 1
fi
assert_in "bypass:ip" "$(reason_for_ip "$IP_IN_RANGE")" \
    "Googlebot UA from inside the published range → rescued by IP (reason=bypass:ip)"
r=$(reason_for_ip "$IP_OUT_RANGE")
case "$r" in
    *search_ai*|*bypass:ip*)
        log_fail "Googlebot UA just outside the range must stay unrescued, got reason=$r"
        ;;
    *) log_pass "Googlebot UA outside the range stays unrescued (reason=$r)" ;;
esac

# B. Auto fallback: with the Google range presets disabled and no explicit
#    lists saved, the vendor reverts to UA-only rescue — the same UA from a
#    non-Google IP is rescued again (v0.1.7-compatible default).
admin_exec "sed -i 's/^  seen_version: v0.1.0\$/  seen_version: v0.1.0\n  bypass_ip_enabled_presets: [\"chrome-prefetch-proxy\"]/' '$CONF'"
if ! admin_exec "grep -q 'bypass_ip_enabled_presets' '$CONF'"; then
    log_fail "failed to inject bypass_ip_enabled_presets into $CONF (seen_version anchor moved?)"
    exit 1
fi
if ! restart_admin; then
    log_fail "admin did not come back after the preset-off restart (healthz $(healthz))"
    exit 1
fi
assert_in "search_ai" "$(reason_for_ip "$IP_OUT_RANGE")" \
    "range presets off → Googlebot falls back to UA-only rescue (reason carries search_ai)"

# C. Explicit UA-off beats the auto fallback: presets still off, and the
#    pattern in upstream_disabled — no rescue path remains (yaml flow plain
#    scalar keeps the backslash: [Googlebot\/]).
admin_exec "sed -i 's,^  seen_version: v0.1.0\$,  seen_version: v0.1.0\n  search_bots:\n    upstream_disabled: [Googlebot\\\\/],' '$CONF'"
if ! admin_exec "grep -q 'upstream_disabled' '$CONF'"; then
    log_fail "failed to inject search_bots.upstream_disabled into $CONF"
    exit 1
fi
if ! restart_admin; then
    log_fail "admin did not come back after the explicit-off restart (healthz $(healthz))"
    exit 1
fi
r=$(reason_for_ip "$IP_OUT_RANGE")
case "$r" in
    *search_ai*|*bypass:ip*)
        log_fail "explicit UA-off + presets off: expected no rescue, got reason=$r"
        ;;
    *) log_pass "explicit UA-off + presets off → no rescue (reason=$r)" ;;
esac

# D. Explicit UA opt-in vs the standing policy.  require_range_verification
#    defaults to ON, and it outranks the per-pattern opt-in: with the presets
#    live the UA string stays closed however the row is ticked, so the same
#    non-Google IP is still refused.  (The unit side is
#    TestRequireRangeVerificationOutranksAnExplicitUAOptIn; this pins the
#    same resolution through the config file and the forward-auth wire.)
admin_exec "cp '$CONF.bak51' '$CONF' && sed -i 's,^  seen_version: v0.1.0\$,  seen_version: v0.1.0\n  search_bots:\n    upstream_ua_enabled: [Googlebot\\\\/],' '$CONF'"
if ! admin_exec "grep -q 'upstream_ua_enabled' '$CONF'"; then
    log_fail "failed to inject search_bots.upstream_ua_enabled into $CONF"
    exit 1
fi
if ! restart_admin; then
    log_fail "admin did not come back after the opt-in restart (healthz $(healthz))"
    exit 1
fi
r=$(reason_for_ip "$IP_OUT_RANGE")
case "$r" in
    *search_ai*|*bypass:ip*)
        log_fail "policy at its ON default: the UA opt-in must be outranked, got reason=$r"
        ;;
    *) log_pass "policy at its ON default → UA opt-in outranked from outside the ranges (reason=$r)" ;;
esac

# E. The OR state needs the policy switched off: same opt-in with
#    require_range_verification: false, and the UA line is back — a non-Google
#    IP passes by UA although every preset is live.
admin_exec "sed -i 's,^  search_bots:\$,  search_bots:\n    require_range_verification: false,' '$CONF'"
if ! admin_exec "grep -q 'require_range_verification' '$CONF'"; then
    log_fail "failed to inject require_range_verification into $CONF"
    exit 1
fi
if ! restart_admin; then
    log_fail "admin did not come back after the policy-off restart (healthz $(healthz))"
    exit 1
fi
assert_in "search_ai" "$(reason_for_ip "$IP_OUT_RANGE")" \
    "policy off + explicit UA opt-in → rescued by UA from outside the ranges (OR state)"

exit 0
