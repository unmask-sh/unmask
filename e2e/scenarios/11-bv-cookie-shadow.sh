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
#
# IP isolation: the `stale only` baseline (= step 2) hits the honeypot path,
# which lands the source IP in the ban list (= per BansConfig).  If steps
# 1/3/4 used the same IP, that ban would mask the shadow-iteration check
# (= visitor with valid _bv is then forced through `pow_then_captcha`
# challenge regardless of cookie validity).  Send step 2 from a throw-away
# XFF, keep steps 1/3/4 on the client IP that owns the freshly-issued _bv.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

CLIENT_IP=198.51.100.110
STALE_IP=198.51.100.120

ck=$(mktemp)
trap 'rm -f "$ck"' EXIT

# 1. obtain a valid _bv via the math captcha endpoint (same as 04).  IP-bound
#    to CLIENT_IP via HMAC, so every subsequent reuse keeps the same XFF.
new=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" \
    "${BASE_URL}/unmask/api/captcha/new")
a=$(echo "$new" | grep -oE '"a":[0-9]+' | grep -oE '[0-9]+')
b=$(echo "$new" | grep -oE '"b":[0-9]+' | grep -oE '[0-9]+')
token=$(echo "$new" | grep -oE '"token":"[^"]+"' | sed -E 's/.*"token":"([^"]+)".*/\1/')
[ -n "$a" ] && [ -n "$b" ] && [ -n "$token" ] || { log_fail "captcha new failed: $new"; exit 1; }
curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" -c "$ck" \
    -H 'Content-Type: application/json' \
    -d "{\"token\":\"$token\",\"answer\":\"$((a+b))\"}" \
    "${BASE_URL}/unmask/api/verify" > /dev/null

bv=$(grep '_bv' "$ck" | awk '{print $7}')
[ -n "$bv" ] || { log_fail "_bv not issued"; exit 1; }
log "valid _bv: ${bv:0:32}..."

# 2. baseline: stale-only -> 403 (= invalid cookie alone rejects).  Use a
#    throw-away IP so the resulting honeypot ban does not poison steps 3/4.
stale_only=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $STALE_IP" \
    -o /dev/null -w '%{http_code}' \
    -H "Cookie: _bv=99999999.pow2.zzzz.0" \
    "${BASE_URL}/wp-login.php")
assert_eq 403 "$stale_only" "stale _bv alone: 403" || exit 1

# 3. valid-first + stale-second -> 200 (= even the old buggy code accepted this).
valid_first=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" \
    -o /dev/null -w '%{http_code}' \
    -H "Cookie: _bv=${bv}; _bv=99999999.pow2.zzzz.0" \
    "${BASE_URL}/wp-login.php")
assert_eq 200 "$valid_first" "valid _bv first, stale second: 200" || exit 1

# 4. stale-first + valid-second -> 200 (= THE regression target.  Was 403 before).
stale_first=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" \
    -o /dev/null -w '%{http_code}' \
    -H "Cookie: _bv=99999999.pow2.zzzz.0; _bv=${bv}" \
    "${BASE_URL}/wp-login.php")
assert_eq 200 "$stale_first" "stale _bv first, valid second: 200 (= iteration accepts ANY valid)"
