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
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

IP_A=192.0.2.200     # inside the fixture relay range 192.0.2.192/26
IP_B=192.0.2.201     # another address in the same range
IP_OUT=192.0.2.100   # outside it

ck=$(mktemp)
trap 'rm -f "$ck"' EXIT

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
