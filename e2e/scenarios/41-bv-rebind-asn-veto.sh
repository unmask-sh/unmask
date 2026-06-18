#!/bin/bash
# 41: roaming rebind ASN veto (rebind mode = "asn", the default).  A solved
# client that roams to a new IP on the SAME carrier (ASN) is silently re-bound,
# but the SAME _bvj replayed from a DIFFERENT carrier (ASN) is refused and falls
# through to a real challenge.  This is the gate that stops a _bv/_bvj pair
# solved on one network from being handed to a bot on another, while still
# absorbing a genuine 5G <-> wifi handoff within one carrier.
#
# The e2e geo override seeds ASNs via the 3-field <ip>:<country>:<asn> form,
# which flips ASNLoaded() on so the veto actually runs (scenario 36 keeps every
# IP on one ASN, so its rebinds still fire; here we cross the ASN boundary on
# purpose):
#   203.0.113.41  -> ASN 64500 (solve / home network)
#   198.51.100.41 -> ASN 64500 (same carrier  -> rebinds)
#   198.51.100.42 -> ASN 64501 (other carrier -> vetoed)
#
# The refused rebind is also recorded as a bv_rebind_veto event (operator-facing
# "cross-carrier replay blocked" signal); the HTTP outcome below is the contract
# under test, the event surfacing is covered by the admin layer.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

# UA_CURL is a challenge_target UA, so "/" challenges with forceReason=none (the
# only path on which a silent rebind is allowed to fire).
UA_SOLVER="$UA_CURL"
PATH_NORMAL="/"

IP_SOLVE=203.0.113.41      # ASN 64500 (home)
IP_SAME_ASN=198.51.100.41  # ASN 64500 (same carrier)
IP_DIFF_ASN=198.51.100.42  # ASN 64501 (different carrier)

# solve_bv <client-ip> -> echoes a freshly solved PoW _bv entry bound to that IP.
solve_bv() {
    local ip="$1" ch seed issued diff
    ch=$(curl -sk -A "$UA_SOLVER" -H "X-Forwarded-For: $ip" "${BASE_URL}/unmask/challenge/")
    seed=$(printf '%s' "$ch" | grep -oE '__POW_SEED__\*/"[0-9a-f]+' | grep -oE '[0-9a-f]{40}' | head -1)
    issued=$(printf '%s' "$ch" | grep -oE '__ISSUED_AT__\*/[0-9]+' | grep -oE '[0-9]{6,}' | head -1)
    diff=$(printf '%s' "$ch" | grep -oE '__POW_DIFFICULTY__\*/[0-9]+' | grep -oE '[0-9]+$' | head -1)
    [ -n "$seed" ] && [ -n "$issued" ] || { echo ""; return; }
    python3 "$DIR/lib/powsolve.py" "$seed" "$issued" "${diff:-18}"
}

# 1. Solve on the home network (ASN 64500) and fetch the _bvj credential.
bvA=$(solve_bv "$IP_SOLVE")
[ -n "$bvA" ] || { log_fail "PoW solve on IP_SOLVE produced no _bv"; exit 1; }
hdrs=$(curl -sk -D - -o /dev/null -X POST -A "$UA_SOLVER" -H "X-Forwarded-For: $IP_SOLVE" \
    -H "Cookie: _bv=$bvA" "${BASE_URL}/unmask/api/bvj")
bvj=$(printf '%s' "$hdrs" | sed -n 's/^[Ss]et-[Cc]ookie: _bvj=\([^;]*\).*/\1/p' | head -1)
[ -n "$bvj" ] || { log_fail "/api/bvj returned no _bvj cookie"; exit 1; }
log "solve_asn=64500 _bvj=$bvj"

# rebind_resp <ip> -> headers of a forceReason=none challenged GET carrying the
# stale _bv + the _bvj (= a roaming client presenting from a new network).
rebind_resp() {
    curl -sk -D - -o /dev/null -A "$UA_SOLVER" -H "X-Forwarded-For: $1" \
        -H "Cookie: _bv=$bvA; _bvj=$bvj" "${BASE_URL}${PATH_NORMAL}"
}

# 2. Roam to a NEW IP on the SAME carrier (ASN 64500): the veto passes (shared
#    AS), so the client is silently re-bound -- 200 + X-Unmask-Mode: rebind.
resp=$(rebind_resp "$IP_SAME_ASN")
assert_eq 200 "$(printf '%s' "$resp" | head -1 | grep -oE '[0-9]{3}' | head -1)" \
    "same-ASN roam answers the rebind bounce (200)"
printf '%s' "$resp" | grep -qi '^x-unmask-mode: rebind' \
    && log_pass "same-ASN roam is silently re-bound (asn veto passes within one carrier)" \
    || log_fail "same-ASN roam should rebind but the X-Unmask-Mode: rebind marker is missing"

# 3. Replay the SAME _bvj from a DIFFERENT carrier (ASN 64501): the veto refuses
#    the rebind (cross-AS), so the real challenge is served (403) with no rebind
#    marker -- the cross-carrier _bv replay is blocked.
resp=$(rebind_resp "$IP_DIFF_ASN")
assert_eq 403 "$(printf '%s' "$resp" | head -1 | grep -oE '[0-9]{3}' | head -1)" \
    "cross-ASN replay is challenged, not rebound (403)"
printf '%s' "$resp" | grep -qi '^x-unmask-mode: rebind' \
    && log_fail "cross-ASN replay must NOT carry the rebind marker (asn veto failed to block it)" \
    || log_pass "cross-ASN replay refused the rebind (asn veto enforced)"
