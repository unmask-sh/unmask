#!/bin/bash
# 32: a rate-limited client must be able to RECOVER -- solve the CAPTCHA, get a
# _bv, and pass again.
#
# Scenario 09 only proves the limit fires.  This proves the escape hatch works
# end to end: rate-limit -> CAPTCHA -> _bv -> exempt.  (The tool1-jp incident was
# real users wedged at a challenge they could not clear; recovery paths matter.)
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

CLIENT_IP=198.51.100.74
ck=$(mktemp); tmpdir=$(mktemp -d)
trap 'rm -f "$ck"; rm -rf "$tmpdir"' EXIT

# 1. trip the rate limit for this IP with a parallel burst (burst=10).
seq 1 50 | xargs -I{} -P 50 sh -c '
    curl -sk -A "'"$UA_BROWSER"'" -H "X-Forwarded-For: '"$CLIENT_IP"'" \
        -o /dev/null -w "%{http_code}\n" --max-time 5 "'"${BASE_URL}"'/?rl=$1" 2>/dev/null
' _ {} > "$tmpdir/codes"
denied=$(grep -cE '^(403|429)$' "$tmpdir/codes")
log "burst: 4xx(denied)=$denied / 50"
if [ "$denied" -lt 1 ]; then
    log_fail "rate limit never fired in the burst (denied=$denied) -- check the unmask_rate zone"
    exit 1
fi

# 2. solve the math CAPTCHA (the escape hatch) for this IP.
new=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" "${BASE_URL}/unmask/api/captcha/new")
a=$(echo "$new" | grep -oE '"a":[0-9]+' | grep -oE '[0-9]+')
b=$(echo "$new" | grep -oE '"b":[0-9]+' | grep -oE '[0-9]+')
token=$(echo "$new" | grep -oE '"token":"[^"]+"' | sed -E 's/.*"token":"([^"]+)".*/\1/')
ct=$(echo "$new" | grep -oE '"ct":"[^"]+"' | sed -E 's/.*"ct":"([^"]+)".*/\1/')
[ -n "$a" ] && [ -n "$token" ] || { log_fail "captcha/new failed during rate limit: $new"; exit 1; }
verify=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" -c "$ck" \
    -H 'Content-Type: application/json' \
    -d "{\"token\":\"$token\",\"answer\":\"$((a + b))\",\"ct\":\"$ct\"}" \
    "${BASE_URL}/unmask/api/verify")
assert_in '"ok":1' "$verify" "rate-limited client can still solve the CAPTCHA (verify ok)" || exit 1

# 3. with the _bv the same IP passes -- the rate limit is exempted.
code=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" -b "$ck" \
    -o /dev/null -w '%{http_code}' "${BASE_URL}/")
assert_eq 200 "$code" "rate-limited IP recovers with a CAPTCHA _bv -> 200 (escape hatch works)"
