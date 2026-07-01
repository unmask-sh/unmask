#!/bin/bash
# 30: an expired _bv must be re-challenged cleanly (403 + a fresh challenge) and
# then recover with a new solve -- never silently looped.
#
# verifyPowSHA256 checks the issued-at validity window BEFORE the PoW, so a _bv
# with a long-past issued is rejected as expired (no valid nonce needed).  The
# point: expiry leads to a clean re-challenge that a fresh solve clears, not a
# dead-end -- the failure mode behind the tool1-jp loop was "valid-looking _bv,
# still re-challenged forever".
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

CLIENT_IP=198.51.100.73
PROT=/wp-login.php

# 1. an expired _bv (issued in 2001) is rejected -> challenged (403).
expired="1000000000.pow2.1.0"
c0=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" -H "Cookie: _bv=$expired" \
    -o /dev/null -w '%{http_code}' "${BASE_URL}${PROT}")
assert_eq 403 "$c0" "expired _bv (year-2001 issued) is re-challenged (403)" || exit 1

# 2. a fresh seed-bound solve passes -> expiry recovers, not a dead-end.
ch=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" "${BASE_URL}/unmask/challenge/")
seed=$(printf '%s' "$ch" | grep -oE '__POW_SEED__\*/"[0-9a-f]+' | grep -oE '[0-9a-f]{40}' | head -1)
issued=$(printf '%s' "$ch" | grep -oE '__ISSUED_AT__\*/[0-9]+' | grep -oE '[0-9]{6,}' | head -1)
diff=$(printf '%s' "$ch" | grep -oE '__POW_DIFFICULTY__\*/[0-9]+' | grep -oE '[0-9]+$' | head -1)
if [ -z "$seed" ] || [ -z "$issued" ]; then
    log_fail "challenge page missing pow_seed/issued_at"
    exit 1
fi
bv=$(python3 "$DIR/lib/powsolve.py" "$seed" "$issued" "${diff:-18}")
[ -n "$bv" ] || { log_fail "PoW solve produced no _bv"; exit 1; }
c1=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" -H "Cookie: _bv=$bv" \
    -o /dev/null -w '%{http_code}' "${BASE_URL}${PROT}")
assert_eq 200 "$c1" "a fresh solve after expiry passes (200) -- expiry recovers, not a dead-end"
