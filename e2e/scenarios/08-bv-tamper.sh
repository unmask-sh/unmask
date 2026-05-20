#!/bin/bash
# 08: a tampered _bv cookie must be rejected by the plugin's HMAC check.
#
# Flow:
#   1. Solve the math captcha (= same as 04) → receive valid _bv cookie
#   2. Flip one character in the signature segment → rebuild Cookie header
#   3. Hit /wp-login.php with the tampered cookie → 403 (= HMAC mismatch)
#
# Cookie format: day.signature.0.c  (= 4 dot-separated fields).
# The plugin's $bv_valid map returns "" for a bad signature, so the honeypot
# challenge fires.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

ck=$(mktemp)
trap 'rm -f "$ck"' EXIT

# 1. solve math captcha
new=$(curl -sk -A "$UA_BROWSER" "${BASE_URL}/unmask/api/captcha/new")
a=$(echo "$new" | grep -oE '"a":[0-9]+' | grep -oE '[0-9]+')
b=$(echo "$new" | grep -oE '"b":[0-9]+' | grep -oE '[0-9]+')
token=$(echo "$new" | grep -oE '"token":"[^"]+"' | sed -E 's/.*"token":"([^"]+)".*/\1/')
[ -n "$a" ] && [ -n "$b" ] && [ -n "$token" ] || { log_fail "captcha new failed: $new"; exit 1; }
ans=$((a + b))

verify=$(curl -sk -A "$UA_BROWSER" -c "$ck" \
    -H 'Content-Type: application/json' \
    -d "{\"token\":\"$token\",\"answer\":\"$ans\"}" \
    "${BASE_URL}/unmask/api/verify")
assert_in '"ok":1' "$verify" "verify returns ok=1" || exit 1

bv=$(grep '_bv' "$ck" | awk '{print $7}')
[ -n "$bv" ] || { log_fail "Set-Cookie: _bv not received"; exit 1; }

# 2. tamper the signature segment (= 2nd dot-separated field)
day=$(echo "$bv" | awk -F. '{print $1}')
sig=$(echo "$bv" | awk -F. '{print $2}')
tail23=$(echo "$bv" | awk -F. '{print $3"."$4}')
# Flip the first character of the signature (0↔1 or a↔b)
first=${sig:0:1}
rest=${sig:1}
case "$first" in
    0) flipped="1" ;;
    1) flipped="0" ;;
    a) flipped="b" ;;
    b) flipped="a" ;;
    *) flipped="0" ;;
esac
bad="${day}.${flipped}${rest}.${tail23}"
log "valid _bv:    ${bv:0:40}..."
log "tampered _bv: ${bad:0:40}..."

# 3. hit honeypot with the tampered cookie
code=$(curl -sk -A "$UA_BROWSER" -H "Cookie: _bv=$bad" -o /dev/null \
    -w '%{http_code}' "${BASE_URL}/wp-login.php")
assert_eq 403 "$code" "GET /wp-login.php with tampered _bv returns 403"
