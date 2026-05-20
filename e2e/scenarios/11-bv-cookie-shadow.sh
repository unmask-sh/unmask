#!/bin/bash
# 11: duplicate `_bv` cookies — a stale invalid entry must not shadow a valid one.
#
# Regression for the "challenge loop" bug: browsers can carry multiple `_bv`
# cookies (= old at a different path + freshly-set at /).  The server-side
# cookie lookup historically returned only the FIRST match, so an invalid
# stale value would reject the user and loop them through challenge forever
# even after they solved PoW correctly.
#
# Both the nginx C plugin and the Go admin's auth_request path now iterate
# every `_bv` value; this scenario sends ordered duplicates and verifies the
# user is still let through.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

ck=$(mktemp)
trap 'rm -f "$ck"' EXIT

# 1. obtain a valid _bv via the math captcha endpoint (same as 04).
new=$(curl -sk -A "$UA_BROWSER" "${BASE_URL}/unmask/api/captcha/new")
a=$(echo "$new" | grep -oE '"a":[0-9]+' | grep -oE '[0-9]+')
b=$(echo "$new" | grep -oE '"b":[0-9]+' | grep -oE '[0-9]+')
token=$(echo "$new" | grep -oE '"token":"[^"]+"' | sed -E 's/.*"token":"([^"]+)".*/\1/')
[ -n "$a" ] && [ -n "$b" ] && [ -n "$token" ] || { log_fail "captcha new failed: $new"; exit 1; }
curl -sk -A "$UA_BROWSER" -c "$ck" \
    -H 'Content-Type: application/json' \
    -d "{\"token\":\"$token\",\"answer\":\"$((a+b))\"}" \
    "${BASE_URL}/unmask/api/verify" > /dev/null

bv=$(grep '_bv' "$ck" | awk '{print $7}')
[ -n "$bv" ] || { log_fail "_bv not issued"; exit 1; }
log "valid _bv: ${bv:0:32}..."

# 2. baseline: stale-only -> 403 (= invalid cookie alone rejects).
stale_only=$(curl -sk -A "$UA_BROWSER" -o /dev/null -w '%{http_code}' \
    -H "Cookie: _bv=99999999.pow2.zzzz.0" \
    "${BASE_URL}/wp-login.php")
assert_eq 403 "$stale_only" "stale _bv alone: 403"

# 3. valid-first + stale-second -> 200 (= even the old buggy code accepted this).
valid_first=$(curl -sk -A "$UA_BROWSER" -o /dev/null -w '%{http_code}' \
    -H "Cookie: _bv=${bv}; _bv=99999999.pow2.zzzz.0" \
    "${BASE_URL}/wp-login.php")
assert_eq 200 "$valid_first" "valid _bv first, stale second: 200"

# 4. stale-first + valid-second -> 200 (= THE regression target.  Was 403 before).
stale_first=$(curl -sk -A "$UA_BROWSER" -o /dev/null -w '%{http_code}' \
    -H "Cookie: _bv=99999999.pow2.zzzz.0; _bv=${bv}" \
    "${BASE_URL}/wp-login.php")
assert_eq 200 "$stale_first" "stale _bv first, valid second: 200 (= iteration accepts ANY valid)"
