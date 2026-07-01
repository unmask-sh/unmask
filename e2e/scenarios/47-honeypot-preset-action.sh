#!/bin/bash
# 47: honeypot per-rule action override (= the "captcha escape hatch").
#
# A honeypot trip normally serves the section-wide chain (Honeypot.DefaultAction,
# which inherits pow_then_captcha when unset).  The operator can override the
# action PER honeypot rule (preset group OR custom URL) -- the case the user
# asked for: dial a high-risk trap up to captcha_only so a PoW-passing bot still
# has to clear a CAPTCHA, while a mis-routed human can recover, WITHOUT changing
# the global default.  Until now the override was a stored-but-ignored field; this
# pins it through the live decision.
#
# admin.yml fixture: a custom honeypot URL "^/pp-captcha-trap/" with
# action: captcha_only.  Its resolved action MUST differ from a default-chain
# honeypot (/wp-login.php, no override -> inherits pow_then_captcha), which proves
# case 1's captcha_only came from the per-rule override and not a global knob.
#
# Hits the admin /unmask/api/check directly (like scenario 05) so the decision
# REASON header is observable: honeypotDecide returns reason "honeypot:<action>"
# (or, if the just-added ban wins the same request, "ban:honeypot:<action>") --
# either way the resolved action is in the string.  Distinct RFC 5737 IPs per
# case so honeypot ban state does not bleed between them.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

ADMIN_URL=${ADMIN_URL:-http://127.0.0.1:19477}

# check <uri> <ip> -> prints "code|action|reason"
check() {
    local hdrfile code action reason
    hdrfile="$(mktemp)"
    code=$(curl -sk -o /dev/null -D "$hdrfile" -w '%{http_code}' \
        -A "$UA_BROWSER" -H "X-Original-URI: $1" -H "X-Original-IP: $2" \
        "${ADMIN_URL}/unmask/api/check")
    action=$(grep -i '^X-Unmask-Action:' "$hdrfile" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
    reason=$(grep -i '^X-Unmask-Reason:' "$hdrfile" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
    rm -f "$hdrfile"
    echo "${code}|${action}|${reason}"
}

# Skip cleanly when the admin port is not reachable (= suite targets a remote
# BASE_URL with no admin port published).
if ! curl -sk -o /dev/null --max-time 4 "${ADMIN_URL}/unmask/healthz"; then
    log_skip "47-honeypot-preset-action needs the admin port (19477) — skipped"
    exit 0
fi

fails=0

# 1) the override rule -> captcha_only.  Browser UA so the honeypot axis is the
#    winning verdict (a known browser otherwise passes) and the reason carries
#    the resolved action.
r=$(check "/pp-captcha-trap/x" "192.0.2.47")
action="${r#*|}"; action="${action%%|*}"; reason="${r##*|}"
log "override trap : code=${r%%|*} action=$action reason=$reason"
assert_eq "challenge" "$action" "captcha_only honeypot trip -> challenge" || fails=$((fails+1))
case "$reason" in
    *captcha_only*) log_pass "override honeypot resolves to captcha_only (reason=$reason)" ;;
    *) log_fail "override honeypot did NOT resolve to captcha_only (reason=$reason)"; fails=$((fails+1)) ;;
esac

# 2) control: a default-chain honeypot (/wp-login.php, no override) must NOT be
#    captcha_only -- it inherits pow_then_captcha.  Distinct action from case 1 is
#    the proof the per-rule override is real, not a global default change.
r=$(check "/wp-login.php" "192.0.2.48")
action="${r#*|}"; action="${action%%|*}"; reason="${r##*|}"
log "default trap  : code=${r%%|*} action=$action reason=$reason"
assert_eq "challenge" "$action" "default honeypot trip -> challenge" || fails=$((fails+1))
case "$reason" in
    *captcha_only*) log_fail "default honeypot unexpectedly captcha_only (reason=$reason) — override leaked into the global chain"; fails=$((fails+1)) ;;
    *honeypot*)     log_pass "default honeypot keeps the inherited chain, distinct from the override (reason=$reason)" ;;
    *)              log_fail "default honeypot reason not recognized (reason=$reason)"; fails=$((fails+1)) ;;
esac

[ "$fails" -eq 0 ] && exit 0
exit 1
