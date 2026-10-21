#!/bin/bash
# 68: a pass cookie bound to a relay's egress range.
#
# A relay such as iCloud Private Relay moves a visitor's egress address within
# its published range from one request to the next.  A _bv bound to the address
# re-challenged on every move, so a visitor behind such a relay never got
# through.  http.inc now gives $unmask_bind_key the published range for a
# client inside one (iprange/relay-egress.json), server.inc forwards it to the
# daemon as X-Unmask-Bind-Key, and both the daemon's issuer and the plugin's
# verifier bind the cookie -- and the PoW seed -- to that range.
#
# The e2e image carries a fixture list with 192.0.2.192/26 as a relay range.
#   1. solve the math CAPTCHA from one address in the range
#   2. the cookie passes from another address in the range, and not from outside
#   3. the same for a PoW pass (the seed is bound to the range too)
#   4. the rendered http.inc carries the range
#   5. a relay bound as a whole (bind "relay", ranges with no country: the
#      shape of a cloud proxy such as Zscaler) -- the fixture's e2e-cloud lists
#      two ranges, and a pass solved inside one is good inside the other
#   6. the roaming credential (_bvj) challenge.js asks for after a solve is
#      issued for a pass bound to the relay: the daemon checks the pass with
#      the relay's key, as the plugin does (0.1.53-rc6 checked it with the
#      address and refused every such pass, 403 no_valid_bv)
#   7. with it, a visitor the relay moves out of the listed range, within the
#      same network, is re-bound there without a challenge
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

IP_A=192.0.2.200     # inside the fixture relay range 192.0.2.192/26
IP_B=192.0.2.201     # another address in the same range
IP_OUT=192.0.2.100   # outside it

ck=$(mktemp)
# Clean up AND keep assert.sh's exit guard: a bare `trap ... EXIT` here would
# replace _e2e_exit_guard, and a FAIL with no explicit `exit 1` would report
# the scenario as passed.
cleanup() { rc=$?; rm -f "$ck"; [ "$rc" -eq 0 ] && [ "${_E2E_FAILS:-0}" -gt 0 ] && exit 1; exit "$rc"; }
trap cleanup EXIT

# code <client-ip> <bv-cookie-value> -> HTTP status of a challenged path.
code() {
    curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $1" -H "Cookie: _bv=$2" \
        -o /dev/null -w '%{http_code}' "${BASE_URL}/wp-login.php"
}

# 1. Solve the math CAPTCHA from IP-A (scenario 04's flow).
new=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $IP_A" "${BASE_URL}/unmask/api/captcha/new")
a=$(printf '%s' "$new" | grep -oE '"a":[0-9]+' | grep -oE '[0-9]+')
b=$(printf '%s' "$new" | grep -oE '"b":[0-9]+' | grep -oE '[0-9]+')
token=$(printf '%s' "$new" | grep -oE '"token":"[^"]+"' | sed -E 's/.*"token":"([^"]+)".*/\1/')
ct=$(printf '%s' "$new" | grep -oE '"ct":"[^"]+"' | sed -E 's/.*"ct":"([^"]+)".*/\1/')
[ -n "$a" ] && [ -n "$b" ] && [ -n "$token" ] || { log_fail "captcha new failed: $new"; exit 1; }
verify=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $IP_A" -c "$ck" \
    -H 'Content-Type: application/json' \
    -d "{\"token\":\"$token\",\"answer\":\"$((a + b))\",\"ct\":\"$ct\",\"iv\":3,\"dt\":2500}" \
    "${BASE_URL}/unmask/api/verify")
assert_in '"ok":1' "$verify" "the CAPTCHA is solved from an address in the relay range" || exit 1
bv=$(awk '$6 == "_bv" {print $7}' "$ck")
[ -n "$bv" ] || { log_fail "no _bv cookie was issued"; exit 1; }
log "_bv=${bv:0:40}..."

# 2. The cookie passes from the solving address, from another address in the
#    range (the relay moved), and not from outside the range.
assert_eq 200 "$(code "$IP_A" "$bv")" "the cookie passes from the address that solved (200)"
assert_eq 200 "$(code "$IP_B" "$bv")" "the cookie passes from another address in the relay's range (200: bound to the range, not the address)"
assert_eq 403 "$(code "$IP_OUT" "$bv")" "the cookie is refused outside the range (403)"

# 3. A PoW pass is bound to the range the same way: the seed the challenge page
#    hands out from IP-A verifies from IP-B.
pow_range=""
ch=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $IP_A" "${BASE_URL}/unmask/challenge/")
seed=$(printf '%s' "$ch" | grep -oE '__POW_SEED__\*/"[0-9a-f]+' | grep -oE '[0-9a-f]{40}' | head -1)
issued=$(printf '%s' "$ch" | grep -oE '__ISSUED_AT__\*/[0-9]+' | grep -oE '[0-9]{6,}' | head -1)
diff=$(printf '%s' "$ch" | grep -oE '__POW_DIFFICULTY__\*/[0-9]+' | grep -oE '[0-9]+$' | head -1)
if [ -n "$seed" ] && [ -n "$issued" ]; then
    pow=$(python3 "$DIR/lib/powsolve.py" "$seed" "$issued" "${diff:-18}")
    if [ -n "$pow" ]; then
        assert_eq 200 "$(code "$IP_A" "$pow")" "a PoW solved from IP-A passes from IP-A (200)"
        assert_eq 200 "$(code "$IP_B" "$pow")" "the PoW pass is good from another address in the range (200)"
        assert_eq 403 "$(code "$IP_OUT" "$pow")" "the PoW pass is refused outside the range (403)"
        pow_range=$pow
    else
        log_fail "PoW solve produced no _bv"
    fi
else
    log_fail "the challenge page carried no PoW seed"
fi

# 4. The rendered http.inc carries the range as the key.
COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
line=$(docker compose -f "$COMPOSE" exec -T nginx \
    sh -c "grep -h '192.0.2.192/26 \"192.0.2.192/26\"' /etc/unmask/http.inc 2>/dev/null | head -1" 2>/dev/null | tr -d '\r')
if [ -z "$line" ]; then
    log_skip "bind-key geo check: could not read http.inc in the nginx container"
else
    log_pass "http.inc binds 192.0.2.192/26 to itself: $line"
fi

# 5. A relay bound as a whole: the fixture's e2e-cloud (192.0.2.128/27 and
#    192.0.2.160/27, no country).  A PoW solved from the first range passes
#    from the second -- the key is the relay, not the range -- and not from
#    outside; http.inc values both ranges with the relay's id.
IP_C1=192.0.2.130
IP_C2=192.0.2.170
pow_cloud=""
ch=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $IP_C1" "${BASE_URL}/unmask/challenge/")
seed=$(printf '%s' "$ch" | grep -oE '__POW_SEED__\*/"[0-9a-f]+' | grep -oE '[0-9a-f]{40}' | head -1)
issued=$(printf '%s' "$ch" | grep -oE '__ISSUED_AT__\*/[0-9]+' | grep -oE '[0-9]{6,}' | head -1)
diff=$(printf '%s' "$ch" | grep -oE '__POW_DIFFICULTY__\*/[0-9]+' | grep -oE '[0-9]+$' | head -1)
if [ -n "$seed" ] && [ -n "$issued" ]; then
    pow=$(python3 "$DIR/lib/powsolve.py" "$seed" "$issued" "${diff:-18}")
    if [ -n "$pow" ]; then
        assert_eq 200 "$(code "$IP_C1" "$pow")" "a PoW solved inside the cloud proxy's first range passes there (200)"
        assert_eq 200 "$(code "$IP_C2" "$pow")" "the pass is good from the proxy's other range (200: bound to the relay as a whole)"
        assert_eq 403 "$(code "$IP_OUT" "$pow")" "the pass is refused outside the proxy (403)"
        pow_cloud=$pow
    else
        log_fail "PoW solve inside the cloud proxy produced no _bv"
    fi
else
    log_fail "the challenge page carried no PoW seed for the cloud proxy's address"
fi
line=$(docker compose -f "$COMPOSE" exec -T nginx \
    sh -c "grep -h '192.0.2.160/27 \"e2e-cloud\"' /etc/unmask/http.inc 2>/dev/null | head -1" 2>/dev/null | tr -d '\r')
if [ -z "$line" ]; then
    log_skip "bind-key geo check: could not read the relay-level line in http.inc"
else
    log_pass "http.inc binds the cloud proxy's range to the relay: $line"
fi

# bvj_for <client-ip> <pass> -> the _bvj /unmask/api/bvj sets for the pass, as
# challenge.js asks for it right after a solve; empty when refused.  The curl
# UA, which "/" challenges with no forced reason (scenario 36), so the rebind
# below is reached with the same fingerprint.
bvj_for() {
    curl -sk -D - -o /dev/null -X POST -A "$UA_CURL" -H "X-Forwarded-For: $1" \
        -H "Cookie: _bv=$2" "${BASE_URL}/unmask/api/bvj" \
        | sed -n 's/^[Ss]et-[Cc]ookie: _bvj=\([^;]*\).*/\1/p' | head -1
}

# 6. The _bvj for the cloud proxy's pass, posted from the proxy's other range
#    -- a proxy sends the request after a page from another of its addresses.
if [ -n "$pow_cloud" ]; then
    [ -n "$(bvj_for "$IP_C2" "$pow_cloud")" ] \
        && log_pass "/api/bvj issues the roaming credential for a pass bound to the relay as a whole" \
        || log_fail "/api/bvj refused a pass bound to the cloud proxy"
else
    log_fail "no pass from the cloud proxy to ask a _bvj for"
fi

# 7. The same for a pass bound to a range, and what the _bvj is for: the relay
#    moves the visitor out of the listed range, to an address of the same
#    network (the e2e geo override gives IP-B and IP_MOVED one ASN, so the
#    roaming ASN gate passes, as it does for a relay that moves its visitors
#    within one provider).  The stale pass fails the plugin there, and the
#    _bvj re-binds it: the bounce, no challenge.
IP_MOVED=198.51.100.69   # outside every fixture range, same ASN as IP-B
if [ -n "$pow_range" ]; then
    bvj=$(bvj_for "$IP_B" "$pow_range")
    if [ -n "$bvj" ]; then
        log_pass "/api/bvj issues the roaming credential for a pass bound to the relay's range"
        resp=$(curl -sk -D - -o /dev/null -A "$UA_CURL" -H "X-Forwarded-For: $IP_MOVED" \
            -H "Cookie: _bv=$pow_range; _bvj=$bvj" "${BASE_URL}/")
        printf '%s' "$resp" | grep -qi '^x-unmask-mode: rebind' \
            && log_pass "moved out of the range, the pass is re-bound without a challenge (X-Unmask-Mode: rebind)" \
            || log_fail "moved out of the range, the pass was not re-bound: $(printf '%s' "$resp" | head -1 | tr -d '\r')"
    else
        log_fail "/api/bvj refused a pass bound to the relay's range"
    fi
else
    log_fail "no pass from the relay's range to ask a _bvj for"
fi
