#!/bin/bash
# 53: a UA row pinned to "deny" is denied even when the client holds a VALID
# pass cookie -- and the same cookie still passes an ordinary visitor.
#
# The bug this pins down: every axis except the ban was consulted only when
# $bv_any_valid was 0, so "deny" meant "deny unless this client cleared a
# challenge at some point in the last week".  Anything able to clear one met
# the rule exactly once and never again.  Observed on a production install: a
# crawler the operator had already removed from the rescue list solved the
# proof-of-work across a large pool of addresses and served itself a day's
# worth of traffic through a row set to deny.  Raising the difficulty cannot
# reach it -- the
# cookie lasts a week, so the cost is one solve per address per week whatever
# the difficulty is.
#
# So the ONE thing that matters here is that both requests carry the same
# cookie.  A scenario that denied a cookie-less client would pass against the
# broken build too.
#
# Fixture (admin.yml): challenge_targets.extra "contains:UnmaskDenyProbe"
# with extra_action deny.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

ck=$(mktemp)
trap 'rm -f "$ck"' EXIT

# _bv is HMAC-bound to the client IP, so every request below uses this one.
CLIENT_IP=198.51.100.53
UA_DENY="Mozilla/5.0 (compatible; UnmaskDenyProbe/1.0)"

# --- mint a genuine pass cookie (math captcha, as scenario 04 does) ----------
new=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" \
    "${BASE_URL}/unmask/api/captcha/new")
a=$(echo "$new" | grep -oE '"a":[0-9]+' | grep -oE '[0-9]+')
b=$(echo "$new" | grep -oE '"b":[0-9]+' | grep -oE '[0-9]+')
token=$(echo "$new" | grep -oE '"token":"[^"]+"' | sed -E 's/.*"token":"([^"]+)".*/\1/')
ct=$(echo "$new" | grep -oE '"ct":"[^"]+"' | sed -E 's/.*"ct":"([^"]+)".*/\1/')
[ -n "$a" ] && [ -n "$b" ] && [ -n "$token" ] || { log_fail "captcha new failed: $new"; exit 1; }
verify=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" -c "$ck" \
    -H 'Content-Type: application/json' \
    -d "{\"token\":\"$token\",\"answer\":\"$((a + b))\",\"ct\":\"$ct\"}" \
    "${BASE_URL}/unmask/api/verify")
assert_in '"ok":1' "$verify" "captcha verify issues a pass cookie" || exit 1
grep -q '_bv' "$ck" || { log_fail "no _bv in the cookie jar"; exit 1; }

# --- control: the cookie works ----------------------------------------------
# Establishes that the cookie really is valid, so the 403 below cannot be
# explained by a cookie the gate was rejecting anyway.
code=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" -b "$ck" \
    -o /dev/null -w '%{http_code}' "${BASE_URL}/")
assert_eq 200 "$code" "valid cookie + ordinary UA -> 200 (the cookie is good)" || exit 1

# --- the point: same cookie, denied UA --------------------------------------
body=$(mktemp); trap 'rm -f "$ck" "$body"' EXIT
code=$(curl -sk -A "$UA_DENY" -H "X-Forwarded-For: $CLIENT_IP" -b "$ck" \
    -o "$body" -w '%{http_code}' "${BASE_URL}/")
assert_eq 403 "$code" "valid cookie + denied UA -> 403 (deny outranks the cookie)" || exit 1

# ...and it is the deny page, not a challenge.  A challenge would mean the
# request fell through to the ordinary chain, where a PoW-capable client just
# clears it again -- the exact hole this closes.
if grep -qi 'pow\|captcha\|challenge.js' "$body"; then
    log_fail "denied UA was served a challenge, not a block: $(head -c 200 "$body")"
    exit 1
fi
log_pass "denied UA got a block page, not a challenge"

# --- an exemption the operator set on purpose still wins --------------------
# The bypass IP is checked ahead of the deny, so a denied UA arriving from a
# bypassed address passes.  Without this the fix would silently override
# monitoring and health checks.
code=$(curl -sk -A "$UA_DENY" -H "X-Forwarded-For: 203.0.113.77" \
    -o /dev/null -w '%{http_code}' "${BASE_URL}/unmask/healthz")
assert_eq 200 "$code" "denied UA on a bypass path -> 200 (explicit exemptions still win)"
