#!/bin/bash
# 13: geo deny mode triggers 403 with no other axis required.
#
# Scenario 12 already exercises the max-severity composition (= multiple
# axes voting together).  This one isolates the geo-deny path: a country
# with action=deny + benign JA4 + no other signal must still hit the deny
# branch because deny is sevDeny (= top of severity scale).
#
# Admin fixture: scenarios/12 already declares CN -> deny.  We reuse that
# rule here against the CN-mapped fixture IP.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

ADMIN_URL=${ADMIN_URL:-http://127.0.0.1:19477}

JA4_OK="t13ok000000000_xxx_yyy"   # not in any rule → verdict=ok

# Hit /api/check with CN-mapped IP + benign JA4.  No other axis should fire.
hdrfile=$(mktemp)
code=$(curl -sk -o /dev/null -D "$hdrfile" -w '%{http_code}' \
    -A "$UA_BROWSER" \
    -H "X-Original-URI: /public" \
    -H "X-Original-IP: 192.0.2.82" \
    -H "X-Client-JA4: $JA4_OK" \
    "${ADMIN_URL}/unmask/api/check")
action=$(grep -i '^X-Unmask-Action:' "$hdrfile" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
reason=$(grep -i '^X-Unmask-Reason:' "$hdrfile" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
rm -f "$hdrfile"

assert_eq 403 "$code"          "CN visitor + benign JA4 → 403"
[[ "$action" == "block" ]]     || { log_fail "expected action=block, got $action"; exit 1; }
[[ "$reason" == *"geo:CN:deny"* ]] \
    || { log_fail "expected reason contains geo:CN:deny, got $reason"; exit 1; }

# No suppression noise expected (= geo is the only axis that voted)
[[ "$reason" == *"suppressed"* ]] \
    && { log_fail "did not expect suppressed list (only geo voted), got $reason"; exit 1; }

log_pass "geo deny isolates correctly: code=$code action=$action reason=$reason"
