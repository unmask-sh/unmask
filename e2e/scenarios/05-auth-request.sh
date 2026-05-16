#!/bin/bash
# 05: the auth_request mode /unmask/api/check endpoint returns 4 verdict types.
#
#   pass case  : ordinary browser UA + ordinary path → 200 / X-Unmask-Action: pass
#   challenge  : curl UA + ordinary path             → 401 / X-Unmask-Action: challenge
#   bypass IP  : IP in bypass list                   → 200 / X-Unmask-Reason: bypass:ip
#   bypass path: path in bypass list                 → 200 / X-Unmask-Reason: bypass:path
#
# Runs in parallel with nginx-module mode, so it hits demo's /unmask/api/check
# directly.  Assumes nginx is already configured to proxy_pass /unmask/* to unmask-admin.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

# Helper that grabs both the /unmask/api/check response header (X-Unmask-Action)
# and the status code.  curl -D dumps headers.
check() {
    local hdrfile="$(mktemp)"
    local code
    code=$(curl -sk -o /dev/null -D "$hdrfile" \
        -w '%{http_code}' "$@" "${BASE_URL}/unmask/api/check")
    local action reason
    action=$(grep -i '^X-Unmask-Action:' "$hdrfile" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
    reason=$(grep -i '^X-Unmask-Reason:' "$hdrfile" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
    rm -f "$hdrfile"
    echo "$code|$action|$reason"
}

# Always pass X-Original-IP (= e2e hits admin from the same host, so without
# Original-IP clientIP becomes 127.0.0.1 and the honeypot ban from scenario 02
# would carry over and FAIL).  Use a distinct IP per case to isolate ban state.
result=$(check -A "$UA_BROWSER" -H "X-Original-URI: /index.html" -H "X-Original-IP: 9.9.9.9")
code="${result%%|*}"
rest="${result#*|}"
action="${rest%%|*}"
fails=0
assert_eq "200" "$code" "pass case: browser UA → 200" || fails=$((fails+1))
assert_eq "pass" "$action" "pass case: action=pass" || fails=$((fails+1))

result=$(check -A "$UA_CURL" -H "X-Original-URI: /admin-page" -H "X-Original-IP: 8.8.8.8")
code="${result%%|*}"
rest="${result#*|}"
action="${rest%%|*}"
assert_eq "401" "$code" "challenge case: curl UA → 401" || fails=$((fails+1))
assert_eq "challenge" "$action" "challenge case: action=challenge" || fails=$((fails+1))

# bypass IP (= assumes demo config has 192.168.1.1 in bypass_ips).
# Skip if it's not configured.
result=$(check -A "$UA_CURL" -H "X-Original-IP: 192.168.1.1" -H "X-Original-URI: /any")
code="${result%%|*}"
rest="${result#*|}"
action="${rest%%|*}"
reason="${rest#*|}"
if [ "$reason" = "bypass:ip" ]; then
    assert_eq "200" "$code" "bypass IP: 192.168.1.1 → 200" || fails=$((fails+1))
    assert_eq "pass" "$action" "bypass IP: action=pass" || fails=$((fails+1))
else
    log_skip "bypass IP test: 192.168.1.1 is not in bypass_ips (reason=$reason)"
fi

# Googlebot (= search bot UAs pass via the two-stage rescue)
result=$(check -A "$UA_GOOGLEBOT" -H "X-Original-URI: /any" -H "X-Original-IP: 7.7.7.7")
code="${result%%|*}"
rest="${result#*|}"
action="${rest%%|*}"
reason="${rest#*|}"
assert_eq "200" "$code" "Googlebot UA → 200" || fails=$((fails+1))
assert_eq "pass" "$action" "Googlebot UA: action=pass" || fails=$((fails+1))
assert_in "search_ai" "$reason" "Googlebot UA: reason contains search_ai" || fails=$((fails+1))

exit "$fails"
