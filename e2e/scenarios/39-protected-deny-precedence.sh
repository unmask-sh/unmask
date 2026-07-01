#!/bin/bash
# 39 (B): a deny zone wins over the protected captcha on a PROTECTED path.
#
# /pdeny/ is BOTH a protected path (captcha preset) AND a deny rate-zone.
#   within the cap : a _bv-less visitor still gets the captcha (protection intact)
#   over the cap   : the deny zone wins -- a hard deny, NOT a recoverable captcha
#
# This is the "B" fix.  The protected captcha is a REWRITE-phase rewrite that
# fires before limit_req (preaccess), so a deny zone on a protected path used to
# be silently pre-empted by the captcha.  Compose mode runs limit_req in dry-run
# and the plugin's ACCESS-phase handler composes the two: over the cap it routes
# to the deny, within the cap it routes to the captcha.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

CLIENT_IP=198.51.100.93
tmpdir=$(mktemp -d)
cleanup() { rc=$?; rm -rf "$tmpdir"; [ "$rc" -eq 0 ] && [ "${_E2E_FAILS:-0}" -gt 0 ] && exit 1; exit "$rc"; }
trap cleanup EXIT

# 1. WITHIN the cap: the protected deny-path still serves the captcha to a
#    _bv-less visitor -- deny does NOT pre-empt the protection here.
code1=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" \
    -o "$tmpdir/within" -w '%{http_code}' "${BASE_URL}/pdeny/x")
log "within-cap /pdeny/: HTTP $code1"
if [ "$code1" = 403 ] && grep -qiE 'challenge|captcha|pow|proof' "$tmpdir/within" \
   && ! grep -q 'unmask:rate-deny' "$tmpdir/within"; then
    log_pass "within cap: protected deny-path serves the captcha (protection intact)"
else
    log_fail "within cap: expected captcha (403 challenge), got code=$code1 deny=$(grep -c 'unmask:rate-deny' "$tmpdir/within") head=$(head -c 120 "$tmpdir/within")"
fi

# 2. OVER the cap: the deny zone wins -> hard deny (unmask:rate-deny), NOT captcha.
seq 1 50 | xargs -I{} -P 50 sh -c '
    curl -sk -A "'"$UA_BROWSER"'" -H "X-Forwarded-For: '"$CLIENT_IP"'" \
        -o /dev/null --max-time 5 "'"${BASE_URL}"'/pdeny/x?f=$1" 2>/dev/null
' _ {} >/dev/null 2>&1
deny_body=""
for i in 1 2 3; do
    deny_body=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" "${BASE_URL}/pdeny/x?probe=$i")
    printf '%s' "$deny_body" | grep -q 'unmask:rate-deny' && break
done
if printf '%s' "$deny_body" | grep -q 'unmask:rate-deny'; then
    log_pass "over cap: the deny zone wins over the captcha (hard deny on a protected path)"
else
    log_fail "over cap: expected deny (unmask:rate-deny), markers=$(printf '%s' "$deny_body" | grep -oiE 'challenge|captcha|pow|deny' | tr 'A-Z' 'a-z' | sort -u | tr '\n' ' ') head=$(printf '%s' "$deny_body" | head -c 120)"
fi
