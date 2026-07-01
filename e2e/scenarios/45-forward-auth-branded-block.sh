#!/bin/bash
# 45: forward-auth NGINX serves the BRANDED "blocked" page for a hard block, not
# nginx's bare 403.  AuthCheck returns 403 for a block (ban / geo-deny /
# honeypot-deny / rate-deny); before the fix the rendered protect.inc had only
# `error_page 401`, so a 403 fell through to nginx's stock 403 and the operator's
# DenyTheme / branding never showed (config -> no-op).  protect.inc now wires
# `error_page 403 = @unmask_blocked` -> the daemon's /unmask/_ban page, the same
# branded surface native + apache (scenario 14) serve.
#
# 192.0.2.82 -> CN via UNMASK_TEST_GEO_OVERRIDE; the CN geo rule = deny.  Drives
# the protected location on fa-nginx (stock nginx, no plugin).
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

fails=0

if ! curl -fsS -o /dev/null --max-time 5 "${FA_NGINX_URL}/unmask/healthz"; then
    log_fail "pre-flight: ${FA_NGINX_URL}/unmask/healthz unreachable -- is the fa-nginx container up?"
    exit 1
fi

# --- block: geo-denied visitor gets the branded blocked page (403), not bare 403 ---
body="$(mktemp)"
code=$(curl -s -o "$body" -w '%{http_code}' \
    -A "$UA_BROWSER" -H 'X-Forwarded-For: 192.0.2.82' "${FA_NGINX_URL}/some/path")
assert_eq "403" "$code" "forward-auth: geo-denied visitor -> 403" || fails=$((fails+1))
assert_in "unmask:ban-deny" "$(cat "$body")" \
    "forward-auth: branded ban-deny page served via @unmask_blocked (not nginx's bare 403)" || fails=$((fails+1))
assert_in "Access blocked" "$(cat "$body")" \
    "forward-auth: persistent 'blocked' wording (DenyTheme/branding surface)" || fails=$((fails+1))
rm -f "$body"

# --- control: a normal browser from a non-denied IP still passes to the backend ---
body=$(curl -s -A "$UA_BROWSER" -H 'X-Forwarded-For: 203.0.113.45' "${FA_NGINX_URL}/")
assert_in "[fa-nginx backend]" "$body" \
    "forward-auth: normal browser still passes to the backend (block is scoped)" || fails=$((fails+1))

if [ "$fails" -eq 0 ]; then
    log_pass "forward-auth nginx serves the branded blocked page for a hard block"
    exit 0
fi
log_fail "forward-auth branded-block failed in $fails check(s)"
exit 1
