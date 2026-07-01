#!/bin/bash
# 38: a "deny" rate-limit zone is a HARD CAP -- distinct from a challenge zone.
#
# A valid _bv (the visitor already passed a CAPTCHA) exempts the client from
# CHALLENGE-mode zones: re-challenging a proven human is pointless, and scenario
# 32 proves that recovery path.  A *deny* zone is the opposite -- it is a hard
# cap, so a human who passed CAPTCHA must NOT be able to flood past it.  This
# pins the native-mode behavior end to end:
#   A1 (counting):  a _bv holder over a DENY zone IS counted   -> 4xx
#   A2 (serve)   :  the over-cap response is a hard DENY page   -> not a re-challenge
#   control      :  a _bv holder over a CAPTCHA zone stays exempt -> 200
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

CLIENT_IP=198.51.100.91
ck=$(mktemp); tmpdir=$(mktemp -d)
# Clean up temp files AND preserve assert.sh's exit guard -- a bare
# `trap ... EXIT` here would shadow _e2e_exit_guard, so a scenario with FAILs
# (but no explicit `exit 1`) would still report exit 0 (= false green).
cleanup() { rc=$?; rm -f "$ck"; rm -rf "$tmpdir"; [ "$rc" -eq 0 ] && [ "${_E2E_FAILS:-0}" -gt 0 ] && exit 1; exit "$rc"; }
trap cleanup EXIT

# 1. solve the math CAPTCHA to obtain a _bv (= a proven human).
new=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" "${BASE_URL}/unmask/api/captcha/new")
a=$(echo "$new" | grep -oE '"a":[0-9]+' | grep -oE '[0-9]+')
b=$(echo "$new" | grep -oE '"b":[0-9]+' | grep -oE '[0-9]+')
token=$(echo "$new" | grep -oE '"token":"[^"]+"' | sed -E 's/.*"token":"([^"]+)".*/\1/')
ct=$(echo "$new" | grep -oE '"ct":"[^"]+"' | sed -E 's/.*"ct":"([^"]+)".*/\1/')
[ -n "$a" ] && [ -n "$token" ] || { log_fail "captcha/new failed: $new"; exit 1; }
verify=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" -c "$ck" \
    -H 'Content-Type: application/json' \
    -d "{\"token\":\"$token\",\"answer\":\"$((a + b))\",\"ct\":\"$ct\"}" \
    "${BASE_URL}/unmask/api/verify")
assert_in '"ok":1' "$verify" "obtained a _bv by solving the CAPTCHA" || exit 1

# sanity: the _bv passes on a normal path (the exemption works at all).
code=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" -b "$ck" \
    -o /dev/null -w '%{http_code}' "${BASE_URL}/")
assert_eq 200 "$code" "the _bv passes on a normal path" || exit 1

# 2. A1 (counting): the _bv holder flooding a DENY zone IS counted -> rate-limited.
seq 1 50 | xargs -I{} -P 50 sh -c '
    curl -sk -A "'"$UA_BROWSER"'" -H "X-Forwarded-For: '"$CLIENT_IP"'" -b "'"$ck"'" \
        -o /dev/null -w "%{http_code}\n" --max-time 5 "'"${BASE_URL}"'/deny-test/?x=$1" 2>/dev/null
' _ {} > "$tmpdir/deny_codes"
deny_denied=$(grep -cE '^(403|429)$' "$tmpdir/deny_codes")
log "deny zone, _bv holder: 4xx=$deny_denied / 50"
if [ "$deny_denied" -lt 1 ]; then
    log_fail "a _bv holder flooding a DENY zone was never rate-limited (4xx=$deny_denied) -- the hard cap exempts _bv, so a proven human can flood /admin/ forever"
else
    log_pass "deny zone counts the _bv holder ($deny_denied/50 limited) -- the hard cap holds"
fi

# 3. A2 (serve): the over-cap response is a hard DENY, not a re-challenge.  The
#    bucket is exhausted from step 2, so a probe stays over the cap.
deny_body=""
for i in 1 2 3; do
    deny_body=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" -b "$ck" \
        "${BASE_URL}/deny-test/?probe=$i")
    printf '%s' "$deny_body" | grep -q 'unmask:rate-deny' && break
done
if printf '%s' "$deny_body" | grep -q 'unmask:rate-deny'; then
    log_pass "the deny zone serves a hard DENY page (not a recoverable challenge)"
else
    log_fail "deny zone over the cap served a challenge/other, not a deny page (A2 not wired) -- head: $(printf '%s' "$deny_body" | head -c 160)"
fi

# 4. control: a CAPTCHA zone KEEPS the _bv exemption -> the holder stays at 200.
seq 1 50 | xargs -I{} -P 50 sh -c '
    curl -sk -A "'"$UA_BROWSER"'" -H "X-Forwarded-For: '"$CLIENT_IP"'" -b "'"$ck"'" \
        -o /dev/null -w "%{http_code}\n" --max-time 5 "'"${BASE_URL}"'/chal-test/?x=$1" 2>/dev/null
' _ {} > "$tmpdir/chal_codes"
chal_denied=$(grep -cE '^(403|429)$' "$tmpdir/chal_codes")
log "chal zone, _bv holder: 4xx=$chal_denied / 50"
assert_eq 0 "$chal_denied" "a _bv holder on a CAPTCHA zone stays exempt (never re-challenged)"
