#!/bin/bash
# 04: math captcha -> issues _bv cookie -> pass through the honeypot with that cookie.
#
# Flow:
#   1. GET /unmask/api/captcha/new -> {a, b, token}
#   2. POST /unmask/api/verify {token, answer=a+b} -> 200 + Set-Cookie: _bv=...
#   3. GET /wp-login.php with browser UA + _bv cookie -> 200 (= challenge skipped)
#
# Note: nginx-module's $unmask_bv_valid check runs, so step 3 still hits the
# challenge (= 403) unless the _bv cookie is a value the HMAC can verify.  This
# is an e2e check that verify issues a cookie correctly *and* nginx-module
# accepts it.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

ck=$(mktemp)
trap 'rm -f "$ck"' EXIT

# IP isolation: keep this scenario on a dedicated XFF so the prior
# honeypot scenarios (02 / 03) don't carry their ban into the cookie
# pass-through check.  _bv is HMAC-bound to remote_ip, so every reuse
# must come from the same XFF.
CLIENT_IP=198.51.100.40

# 1. fetch captcha
new=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" \
    "${BASE_URL}/unmask/api/captcha/new")
a=$(echo "$new" | grep -oE '"a":[0-9]+' | grep -oE '[0-9]+')
b=$(echo "$new" | grep -oE '"b":[0-9]+' | grep -oE '[0-9]+')
token=$(echo "$new" | grep -oE '"token":"[^"]+"' | sed -E 's/.*"token":"([^"]+)".*/\1/')
ct=$(echo "$new" | grep -oE '"ct":"[^"]+"' | sed -E 's/.*"ct":"([^"]+)".*/\1/')
[ -n "$a" ] && [ -n "$b" ] && [ -n "$token" ] || { log_fail "captcha new failed: $new"; exit 1; }
ans=$((a + b))
log "captcha: $a + $b = $ans  token=${token:0:24}..."

# 2. verify (= submit answer + the proof-of-load ct from /captcha/new)
verify=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" -c "$ck" \
    -H 'Content-Type: application/json' \
    -d "{\"token\":\"$token\",\"answer\":\"$ans\",\"ct\":\"$ct\"}" \
    "${BASE_URL}/unmask/api/verify")
assert_in '"ok":1' "$verify" "verify returns ok=1" || exit 1

bv=$(grep '_bv' "$ck" | awk '{print $7}')
[ -n "$bv" ] || { log_fail "Set-Cookie: _bv not received. cookie jar:\n$(cat "$ck")"; exit 1; }
log "_bv cookie received: ${bv:0:32}..."

# 3. Hit the honeypot with _bv.  Challenge should be skipped, expect 200.
code=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" -b "$ck" \
    -o /dev/null -w '%{http_code}' \
    "${BASE_URL}/wp-login.php")
assert_eq 200 "$code" "GET /wp-login.php with _bv cookie returns 200 (= challenge skipped)"
