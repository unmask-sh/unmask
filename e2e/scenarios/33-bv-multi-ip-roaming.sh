#!/bin/bash
# 33: multi-IP _bv roaming.  A client that solves the PoW on IP-A then moves to
# IP-B accumulates BOTH per-IP signatures in one "~"-joined _bv, so switching
# back to IP-A (= 5G <-> wifi) no longer re-challenges.  At the same time a
# SINGLE-entry _bv must still never grant a NEW IP, so the per-IP anti-reuse that
# stops a botnet reusing one solve across residential IPs is preserved.
#
# Exercises the cross-language any-match: the native C plugin
# (ngx_unmask_bv_verify_value) splits the "~" list and recomputes each entry's
# seed for the CURRENT IP, mirroring cookies.Verify in the Go package.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

IP_A=203.0.113.10
IP_B=198.51.100.20

# solve_bv <client-ip> -> echoes a freshly solved PoW _bv entry bound to that IP.
solve_bv() {
    local ip="$1" ch seed issued diff
    ch=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $ip" "${BASE_URL}/unmask/challenge/")
    seed=$(printf '%s' "$ch" | grep -oE '__POW_SEED__\*/"[0-9a-f]+' | grep -oE '[0-9a-f]{40}' | head -1)
    issued=$(printf '%s' "$ch" | grep -oE '__ISSUED_AT__\*/[0-9]+' | grep -oE '[0-9]{6,}' | head -1)
    diff=$(printf '%s' "$ch" | grep -oE '__POW_DIFFICULTY__\*/[0-9]+' | grep -oE '[0-9]+$' | head -1)
    [ -n "$seed" ] && [ -n "$issued" ] || { echo ""; return; }
    python3 "$DIR/lib/powsolve.py" "$seed" "$issued" "${diff:-18}"
}

# code <client-ip> <bv-cookie-value> -> HTTP status of a challenged path.
code() {
    curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $1" -H "Cookie: _bv=$2" \
        -o /dev/null -w '%{http_code}' "${BASE_URL}/wp-login.php"
}

# 1. Solve on IP-A; the single-entry _bv passes from IP-A.
bvA=$(solve_bv "$IP_A")
[ -n "$bvA" ] || { log_fail "PoW solve on IP-A produced no _bv"; exit 1; }
log "IP-A _bv=$bvA"
assert_eq 200 "$(code "$IP_A" "$bvA")" "IP-A single-entry _bv passes from IP-A (200)"

# 2. The SAME single-entry _bv must be rejected from IP-B (per-IP binding holds;
#    one solve does not grant another IP).
assert_eq 403 "$(code "$IP_B" "$bvA")" "IP-A single-entry _bv is rejected from IP-B (403, no cross-IP grant)"

# 3. Solve on IP-B and accumulate: the client now carries "bvB~bvA" (= what
#    challenge.js / setBVCookie produce by appending newest-first).
bvB=$(solve_bv "$IP_B")
[ -n "$bvB" ] || { log_fail "PoW solve on IP-B produced no _bv"; exit 1; }
list="$bvB~$bvA"
log "combined _bv=$list"

# 4. The combined list passes from BOTH IPs (any-match) -> roaming back to IP-A
#    no longer re-challenges, and IP-B works too.
assert_eq 200 "$(code "$IP_A" "$list")" "combined list passes from IP-A (200, roaming back keeps the old IP valid)"
assert_eq 200 "$(code "$IP_B" "$list")" "combined list passes from IP-B (200, the new IP works too)"
