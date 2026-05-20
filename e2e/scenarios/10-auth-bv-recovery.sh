#!/bin/bash
# 10: auth_request mode recovers a previously-blocked client via the _bv cookie.
#
# Flow (= mirrors a real Apache front-end deployment):
#   1. curl UA hits /unmask/api/check → action=challenge (= 401)
#   2. Solve the math captcha → receive _bv cookie
#   3. Same UA + _bv cookie hits /unmask/api/check → action=pass (= 200)
#
# Distinct from 04 (which exercises the native plugin's $bv_valid map).
# This scenario covers the Go admin AuthCheck handler's _bv branch.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

CLIENT_IP="5.5.5.5"
fails=0
ck=$(mktemp)
trap 'rm -f "$ck"' EXIT

# Hit admin directly (= port 9477 published by docker-compose).  Going through
# nginx would rewrite X-Real-IP to the docker network IP, so the cookie
# issued via /api/verify would be HMAC'd against a different IP than the
# one we pass via X-Original-IP on /api/check.
ADMIN_URL=${ADMIN_URL:-http://127.0.0.1:19477}

# Helper: hit /unmask/api/check with an arbitrary Original-IP / cookie.
check() {
    local hdrfile; hdrfile=$(mktemp)
    local code
    code=$(curl -sk -o /dev/null -D "$hdrfile" -w '%{http_code}' "$@" \
        "${ADMIN_URL}/unmask/api/check")
    local action
    action=$(grep -i '^X-Unmask-Action:' "$hdrfile" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
    rm -f "$hdrfile"
    echo "$code|$action"
}

# 1. challenge baseline: curl UA without _bv → 401 challenge
res=$(check -A "$UA_CURL" -H "X-Original-URI: /restricted" -H "X-Original-IP: $CLIENT_IP")
code="${res%%|*}"; action="${res##*|}"
assert_eq 401 "$code" "step 1: curl UA without _bv → 401" || fails=$((fails+1))
assert_eq challenge "$action" "step 1: action=challenge" || fails=$((fails+1))

# 2. solve math captcha (= run from the same client IP so the cookie HMAC matches).
new=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" \
    "${ADMIN_URL}/unmask/api/captcha/new")
a=$(echo "$new" | grep -oE '"a":[0-9]+' | grep -oE '[0-9]+')
b=$(echo "$new" | grep -oE '"b":[0-9]+' | grep -oE '[0-9]+')
token=$(echo "$new" | grep -oE '"token":"[^"]+"' | sed -E 's/.*"token":"([^"]+)".*/\1/')
[ -n "$a" ] && [ -n "$b" ] && [ -n "$token" ] || { log_fail "captcha new failed: $new"; exit 1; }
ans=$((a + b))

verify=$(curl -sk -A "$UA_BROWSER" -c "$ck" -H "X-Forwarded-For: $CLIENT_IP" \
    -H 'Content-Type: application/json' \
    -d "{\"token\":\"$token\",\"answer\":\"$ans\"}" \
    "${ADMIN_URL}/unmask/api/verify")
assert_in '"ok":1' "$verify" "step 2: verify returns ok=1" || fails=$((fails+1))
bv=$(grep '_bv' "$ck" | awk '{print $7}')
[ -n "$bv" ] || { log_fail "Set-Cookie: _bv not received"; exit 1; }

# 3. retry the original /unmask/api/check with the _bv cookie attached.
res=$(check -A "$UA_CURL" -H "X-Original-URI: /restricted" -H "X-Original-IP: $CLIENT_IP" \
    -H "Cookie: _bv=$bv")
code="${res%%|*}"; action="${res##*|}"
assert_eq 200 "$code" "step 3: curl UA + _bv → 200" || fails=$((fails+1))
assert_eq pass "$action" "step 3: action=pass" || fails=$((fails+1))

exit "$fails"
