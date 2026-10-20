#!/bin/bash
# 69: a request carrying a body is re-bound in place.
#
# A proxy that sends one visitor's requests from several addresses (a cloud
# proxy's data centre, a two-exit NAT) handed the page from one address and
# the form posted from it from another.  The posted request's _bv was bound
# to the first address, and the challenge route could not serve a page to a
# POST: the visitor got a JSON error and the input was gone.  Now the roaming
# gates (the _bvj credential: same fingerprint, UA and carrier, within the
# cap) run for the posted request itself.
#   1. passed: a 307 back to the original URL with a fresh _bv entry (kind
#      rebind), so the browser repeats the post with the re-bound cookie
#   2. the repeated post passes the native plugin
#   3. refused (another UA): a browser's form post is sent back to the page it
#      was posted from (303 to the same-origin Referer), not to a JSON body
#   4. refused, from a fetch: the JSON refusal, as before
#   5. a forced challenge (a trap) is not re-bound even with a good _bvj
# Same shape as scenario 36 (a curl UA on a plain path is the one way to make
# a forceReason=none challenge in this config); the geo override puts every
# address here on one carrier, so the ASN veto passes.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

UA_SOLVER="$UA_CURL"
UA_OTHER="curl/7.50-mismatch"
IP_A=203.0.113.110
IP_B=203.0.113.111
IP_C=203.0.113.112
IP_D=203.0.113.113

solve_bv() {
    local ip="$1" ch seed issued diff
    ch=$(curl -sk -A "$UA_SOLVER" -H "X-Forwarded-For: $ip" "${BASE_URL}/unmask/challenge/")
    seed=$(printf '%s' "$ch" | grep -oE '__POW_SEED__\*/"[0-9a-f]+' | grep -oE '[0-9a-f]{40}' | head -1)
    issued=$(printf '%s' "$ch" | grep -oE '__ISSUED_AT__\*/[0-9]+' | grep -oE '[0-9]{6,}' | head -1)
    diff=$(printf '%s' "$ch" | grep -oE '__POW_DIFFICULTY__\*/[0-9]+' | grep -oE '[0-9]+$' | head -1)
    [ -n "$seed" ] && [ -n "$issued" ] || { echo ""; return; }
    python3 "$DIR/lib/powsolve.py" "$seed" "$issued" "${diff:-18}"
}
status_of() { printf '%s' "$1" | head -1 | grep -oE '[0-9]{3}' | head -1; }
header_of() { printf '%s' "$1" | sed -n "s/^$2: *//Ip" | tr -d '\r' | head -1; }

# Solve on IP-A and fetch the rebind credential, as challenge.js does.
bvA=$(solve_bv "$IP_A")
[ -n "$bvA" ] || { log_fail "PoW solve on IP-A produced no _bv"; exit 1; }
hdrs=$(curl -sk -D - -o /dev/null -X POST -A "$UA_SOLVER" -H "X-Forwarded-For: $IP_A" \
    -H "Cookie: _bv=$bvA" "${BASE_URL}/unmask/api/bvj")
bvj=$(printf '%s' "$hdrs" | sed -n 's/^[Ss]et-[Cc]ookie: _bvj=\([^;]*\).*/\1/p' | head -1)
[ -n "$bvj" ] || { log_fail "/api/bvj returned no _bvj cookie"; exit 1; }

# 1. The form posted from IP-B with IP-A's _bv: re-bound in place, 307 back to
#    the URL it was posted to, with a kind=rebind entry first in the cookie.
resp=$(curl -sk -D - -o /dev/null -X POST --data 'name=a&qty=1' -A "$UA_SOLVER" \
    -H "X-Forwarded-For: $IP_B" -H "Cookie: _bv=$bvA; _bvj=$bvj" \
    -H "Sec-Fetch-Dest: document" -H "Sec-Fetch-Mode: navigate" \
    -H "Referer: ${BASE_URL}/form/order?step=2" "${BASE_URL}/form/check?x=1")
assert_eq 307 "$(status_of "$resp")" "a form posted from a new address is re-bound and sent again (307)"
assert_eq "/form/check?x=1" "$(header_of "$resp" location)" "the 307 points back at the URL the form was posted to"
printf '%s' "$resp" | grep -qi '^x-unmask-mode: rebind' \
    && log_pass "the 307 is marked as a rebind" \
    || log_fail "X-Unmask-Mode: rebind header missing on the 307"
bvB=$(printf '%s' "$resp" | sed -n 's/^[Ss]et-[Cc]ookie: _bv=\([^;]*\).*/\1/p' | head -1)
[ -n "$bvB" ] || { log_fail "the 307 set no fresh _bv"; exit 1; }
entryB="${bvB%%~*}"
case "$entryB" in
    *.rebind) log_pass "the fresh entry is kind=rebind ($entryB)";;
    *) log_fail "expected a kind=rebind entry, got: $entryB";;
esac

# 2. The repeated post, with the re-bound cookie, passes the native plugin
#    and reaches the origin (the e2e echo answers any method with 200).
assert_eq 200 "$(curl -sk -o /dev/null -w '%{http_code}' -X POST --data 'name=a&qty=1' -A "$UA_SOLVER" \
    -H "X-Forwarded-For: $IP_B" -H "Cookie: _bv=$bvB" "${BASE_URL}/form/check?x=1")" \
    "the repeated post passes the plugin from IP-B (200)"

# 3. The gates refuse (another UA, so another fingerprint): a browser's form
#    post goes back to the page it was posted from, as a GET.
resp=$(curl -sk -D - -o /dev/null -X POST --data 'name=a&qty=1' -A "$UA_OTHER" \
    -H "X-Forwarded-For: $IP_C" -H "Cookie: _bv=$bvA; _bvj=$bvj" \
    -H "Sec-Fetch-Dest: document" -H "Sec-Fetch-Mode: navigate" \
    -H "Referer: ${BASE_URL}/form/order?step=2" "${BASE_URL}/form/check")
assert_eq 303 "$(status_of "$resp")" "a refused form post is sent back to its page (303)"
assert_eq "/form/order?step=2" "$(header_of "$resp" location)" "the 303 points at the page the form was posted from"
printf '%s' "$resp" | grep -qi '^set-cookie: _bv=' \
    && log_fail "a refused post must not be given a _bv" \
    || log_pass "the refused post got no cookie"

# 4. The same refusal from a fetch: the JSON body, as before.
body=$(mktemp)
code=$(curl -sk -o "$body" -w '%{http_code}' -X POST --data '{"q":1}' -A "$UA_OTHER" \
    -H "X-Forwarded-For: $IP_D" -H "Cookie: _bv=$bvA; _bvj=$bvj" \
    -H "Content-Type: application/json" -H "Accept: application/json" \
    -H "Sec-Fetch-Dest: empty" -H "Sec-Fetch-Mode: cors" "${BASE_URL}/data/items")
assert_eq 403 "$code" "a refused fetch is answered 403"
assert_in '"challenge_required"' "$(cat "$body")" "the refused fetch gets the JSON refusal"
rm -f "$body"

# 5. A trap keeps its challenge: the honeypot path, posted with a good _bvj
#    from IP-B, is not re-bound (403, no rebind marker).
resp=$(curl -sk -D - -o /dev/null -X POST --data 'log=a' -A "$UA_SOLVER" \
    -H "X-Forwarded-For: $IP_B" -H "Cookie: _bv=$bvA; _bvj=$bvj" "${BASE_URL}/wp-login.php")
assert_eq 403 "$(status_of "$resp")" "a trap's challenge stands for a posted request (403)"
printf '%s' "$resp" | grep -qi '^x-unmask-mode: rebind' \
    && log_fail "a forced challenge must not be re-bound" \
    || log_pass "the trap's post was not re-bound"
