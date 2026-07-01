#!/bin/bash
# 26: solving the challenge once must STOP it -- the visitor must not be
# re-challenged on the next request.
#
# The tool1-jp loop was exactly this failing: a solved _bv the plugin rejected,
# so every request re-challenged forever.  Assert the whole boundary: no _bv ->
# 403, a solved seed-bound PoW _bv -> 200, and the SAME _bv still -> 200 on the
# next request (a rejected _bv would 403 here and loop).
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

CLIENT_IP=198.51.100.71
PROT=/wp-login.php

# 1. baseline: challenged without a _bv.
c0=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" -o /dev/null -w '%{http_code}' "${BASE_URL}${PROT}")
assert_eq 403 "$c0" "no _bv: ${PROT} is challenged (403)" || exit 1

# 2. solve the seed-bound PoW (challenge.js's exact algorithm; see lib/powsolve.py).
ch=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" "${BASE_URL}/unmask/challenge/")
seed=$(printf '%s' "$ch" | grep -oE '__POW_SEED__\*/"[0-9a-f]+' | grep -oE '[0-9a-f]{40}' | head -1)
issued=$(printf '%s' "$ch" | grep -oE '__ISSUED_AT__\*/[0-9]+' | grep -oE '[0-9]{6,}' | head -1)
diff=$(printf '%s' "$ch" | grep -oE '__POW_DIFFICULTY__\*/[0-9]+' | grep -oE '[0-9]+$' | head -1)
if [ -z "$seed" ] || [ -z "$issued" ]; then
    log_fail "challenge page missing pow_seed/issued_at: seed='$seed' issued='$issued'"
    exit 1
fi
bv=$(python3 "$DIR/lib/powsolve.py" "$seed" "$issued" "${diff:-18}")
[ -n "$bv" ] || { log_fail "PoW solve produced no _bv"; exit 1; }
log "solved _bv=$bv"

# 3. solved _bv -> pass.
c1=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" -H "Cookie: _bv=$bv" -o /dev/null -w '%{http_code}' "${BASE_URL}${PROT}")
assert_eq 200 "$c1" "solved _bv: ${PROT} passes (200)" || exit 1

# 4. the SAME _bv on the next request must still pass -- not re-challenged.
c2=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" -H "Cookie: _bv=$bv" -o /dev/null -w '%{http_code}' "${BASE_URL}${PROT}")
assert_eq 200 "$c2" "same _bv on the next request still passes (200) -- no re-challenge loop"
