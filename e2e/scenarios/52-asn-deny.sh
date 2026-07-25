#!/bin/bash
# 52: ASN deny axis triggers 403 in isolation, and does NOT catch an ASN
# without a rule.  The by-network sibling of scenario 13 (geo deny).
#
# Fixture (admin.yml + UNMASK_TEST_GEO_OVERRIDE):
#   192.0.2.90 -> country US (default skip), ASN 16509 (rule: deny)
#   192.0.2.91 -> country US (default skip), ASN 64512 (no rule)
# So 192.0.2.90 must 403 on the ASN axis alone, while 192.0.2.91 passes
# (proving the axis is ASN-specific, not blanket).

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

ADMIN_URL=${ADMIN_URL:-http://127.0.0.1:19477}
JA4_OK="t13ok000000000_xxx_yyy" # not in any rule -> verdict=ok

check() { # <ip>
    local hdrfile code action reason
    hdrfile=$(mktemp)
    code=$(curl -sk -o /dev/null -D "$hdrfile" -w '%{http_code}' \
        -A "$UA_BROWSER" \
        -H "X-Original-URI: /public" \
        -H "X-Original-IP: $1" \
        -H "X-Client-JA4: $JA4_OK" \
        "${ADMIN_URL}/unmask/api/check")
    action=$(grep -i '^X-Unmask-Action:' "$hdrfile" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
    reason=$(grep -i '^X-Unmask-Reason:' "$hdrfile" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
    rm -f "$hdrfile"
    echo "$code|$action|$reason"
}

# AS16509 -> deny.
res=$(check "192.0.2.90")
code=${res%%|*}; rest=${res#*|}; action=${rest%%|*}; reason=${rest#*|}
assert_eq 403 "$code" "AS16509 visitor -> 403" || exit 1
[[ "$action" == "block" ]] || { log_fail "expected action=block, got $action"; exit 1; }
[[ "$reason" == *"asn:AS16509:deny"* ]] \
    || { log_fail "expected reason contains asn:AS16509:deny, got $reason"; exit 1; }
# geo (US) is default skip, so only the ASN axis voted -> no suppression noise.
[[ "$reason" == *"suppressed"* ]] \
    && { log_fail "did not expect suppressed list (only asn voted), got $reason"; exit 1; }
log_pass "asn deny isolates: code=$code action=$action reason=$reason"

# AS64512 has no rule -> passes (axis is ASN-specific).
res=$(check "192.0.2.91")
code=${res%%|*}; rest=${res#*|}; action=${rest%%|*}
assert_eq 200 "$code" "unruled ASN (AS64512) passes" || exit 1
[[ "$action" == "pass" ]] || { log_fail "expected action=pass for unruled ASN, got $action"; exit 1; }
log_pass "unruled ASN passes: code=$code action=$action"
