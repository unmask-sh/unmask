#!/bin/bash
# 36: silent roaming rebind (_bvj).  A client that solved the PoW on IP-A and
# fetched its _bvj credential gets its _bv silently re-bound when it reappears
# from a new IP (= a 5G cell handoff) instead of being re-challenged: the
# challenge route answers with a bounce page (X-Unmask-Mode: rebind) + a fresh
# per-IP _bv entry, no PoW.
#
# Why a curl UA on a normal path: rebind only fires on forceReason="none" (the
# plain default-challenge path), NOT on a forced challenge (honeypot / ja4_bot /
# protected / rate-limit) -- a deliberate challenge must never be rebound away.
# In this e2e config global known/unknown_ua_action=pass, so a browser UA on "/"
# passes outright; a challenge_target UA (curl) on "/" is the only way to make a
# plain forceReason="none" challenge happen.  /wp-login.php would be a honeypot
# (forceReason="honeypot") and would correctly NOT rebind.
#
# Gates exercised end-to-end:
#   - the rebound entry is kind="rebind" and must verify in the NATIVE C plugin
#     (= free-form kind segment, cross-language HMAC)
#   - a different UA must NOT rebind (fingerprint gate) -- still a curl variant
#     so the challenge fires, but a different fingerprint than the solver's
#   - the per-lineage hourly cap refuses the 5th rebind (default 4/h)
#   - /api/bvj refuses to seed a fresh lineage off a kind="rebind" entry
#     (= the budget-refill recursion stays closed)
#
# The override now puts every IP here on ASN 64500 (one carrier), so the ASN
# veto is ACTIVE but always passes (solve + roam share the AS); scenario 41
# covers the cross-ASN refusal.  RebindAllow unit tests cover the cap math.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

# UA_CURL is a challenge_target (blacklisted) UA, so "/" challenges with
# forceReason=none.  UA_OTHER is also a curl variant (still challenged) but a
# different fingerprint than the solver, to exercise the rebind UA gate.
UA_SOLVER="$UA_CURL"
UA_OTHER="curl/7.50-mismatch"
PATH_NORMAL="/"

IP_A=203.0.113.30
IP_B=198.51.100.31
IP_C=198.51.100.32
IP_D=198.51.100.33
IP_E=198.51.100.34
IP_F=198.51.100.35

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

# 1. Solve on IP-A, then fetch the rebind credential the way challenge.js does
#    (POST /unmask/api/bvj with the fresh _bv attached).
bvA=$(solve_bv "$IP_A")
[ -n "$bvA" ] || { log_fail "PoW solve on IP-A produced no _bv"; exit 1; }

hdrs=$(curl -sk -D - -o /dev/null -X POST -A "$UA_SOLVER" -H "X-Forwarded-For: $IP_A" \
    -H "Cookie: _bv=$bvA" "${BASE_URL}/unmask/api/bvj")
bvj=$(printf '%s' "$hdrs" | sed -n 's/^[Ss]et-[Cc]ookie: _bvj=\([^;]*\).*/\1/p' | head -1)
[ -n "$bvj" ] || { log_fail "/api/bvj returned no _bvj cookie"; exit 1; }
log "IP-A _bvj=$bvj"

# 1b. Without a valid _bv the endpoint must refuse.
assert_eq 403 "$(curl -sk -o /dev/null -w '%{http_code}' -X POST -A "$UA_SOLVER" \
    -H "X-Forwarded-For: $IP_A" "${BASE_URL}/unmask/api/bvj")" \
    "/api/bvj without a valid _bv is refused (403)"

# rebind_resp <ip> <ua> -> dumps headers of a forceReason=none challenged GET
# carrying the stale _bv + the _bvj (= what a roaming client presents from a new
# network).
rebind_resp() {
    curl -sk -D - -o /dev/null -A "$2" -H "X-Forwarded-For: $1" \
        -H "Cookie: _bv=$bvA; _bvj=$bvj" "${BASE_URL}${PATH_NORMAL}"
}

# 2. From IP-B the stale _bv fails plugin verification, but the _bvj rebinds:
#    bounce page (200 + X-Unmask-Mode: rebind) + a fresh _bv entry, no PoW.
resp=$(rebind_resp "$IP_B" "$UA_SOLVER")
assert_eq 200 "$(printf '%s' "$resp" | head -1 | grep -oE '[0-9]{3}' | head -1)" \
    "roaming to IP-B answers the rebind bounce (200)"
printf '%s' "$resp" | grep -qi '^x-unmask-mode: rebind' \
    && log_pass "rebind bounce carries X-Unmask-Mode: rebind" \
    || log_fail "X-Unmask-Mode: rebind header missing"
bvB=$(printf '%s' "$resp" | sed -n 's/^[Ss]et-[Cc]ookie: _bv=\([^;]*\).*/\1/p' | head -1)
[ -n "$bvB" ] || { log_fail "rebind set no fresh _bv"; exit 1; }
entryB="${bvB%%~*}"
case "$entryB" in
    *.rebind) log_pass "fresh entry is kind=rebind ($entryB)";;
    *) log_fail "expected a kind=rebind entry, got: $entryB";;
esac

# 3. The rebound entry must pass the NATIVE plugin from IP-B (= the C side
#    accepts the free-form kind segment; this is the cross-language proof).
#    A passing _bv short-circuits before the challenge target check, so the
#    backend answers 200 even for the curl UA.
assert_eq 200 "$(curl -sk -A "$UA_SOLVER" -H "X-Forwarded-For: $IP_B" \
    -H "Cookie: _bv=$bvB" -o /dev/null -w '%{http_code}' "${BASE_URL}${PATH_NORMAL}")" \
    "rebound kind=rebind entry passes the native plugin from IP-B (200)"

# 4. A different UA must NOT rebind (fingerprint gate).  UA_OTHER is still a curl
#    variant so the challenge fires, but its fingerprint != the solver's, so
#    rebind is refused and the real challenge is served (403, no rebind marker).
resp=$(rebind_resp "$IP_C" "$UA_OTHER")
assert_eq 403 "$(printf '%s' "$resp" | head -1 | grep -oE '[0-9]{3}' | head -1)" \
    "a different UA is challenged, not rebound (403)"
printf '%s' "$resp" | grep -qi '^x-unmask-mode: rebind' \
    && log_fail "UA-mismatch request must not carry the rebind marker" \
    || log_pass "UA mismatch refused the rebind"

# 5. /api/bvj must refuse to mint a fresh lineage off the REBOUND entry
#    (only a real solve buys a fresh rebind budget).
body=$(curl -sk -X POST -A "$UA_SOLVER" -H "X-Forwarded-For: $IP_B" \
    -H "Cookie: _bv=$entryB" "${BASE_URL}/unmask/api/bvj")
printf '%s' "$body" | grep -q 'rebound_entry' \
    && log_pass "/api/bvj refuses a fresh lineage off a rebound entry" \
    || log_fail "expected skip=rebound_entry, got: $body"

# 6. Hourly cap: IP-B consumed slot 1 (step 2); IPs C-E consume 2-4; the 5th
#    distinct rebind is refused (default max_rebinds_per_hour=4).  The UA gate
#    in step 4 refused before charging, so IP-C still has its slot here.
for ip in "$IP_C" "$IP_D" "$IP_E"; do
    resp=$(rebind_resp "$ip" "$UA_SOLVER")
    printf '%s' "$resp" | grep -qi '^x-unmask-mode: rebind' \
        && log_pass "rebind within the hourly window ($ip)" \
        || log_fail "expected a rebind for $ip within the window"
done
resp=$(rebind_resp "$IP_F" "$UA_SOLVER")
printf '%s' "$resp" | grep -qi '^x-unmask-mode: rebind' \
    && log_fail "5th rebind in the window must be refused (cap)" \
    || log_pass "5th rebind refused by the per-lineage hourly cap"
assert_eq 403 "$(printf '%s' "$resp" | head -1 | grep -oE '[0-9]{3}' | head -1)" \
    "capped client falls back to the real challenge (403)"

# 7. The plugin must call a re-bound pass what it is.
#
#    Both wires used to read the cookie's SHAPE: three segments meant CAPTCHA,
#    four meant PoW, and a re-bound entry has three -- so every request passing
#    on a roamed credential was filed as a CAPTCHA pass.  On a production
#    install that made a crawler passing entirely by re-binding look like a
#    steady trickle of CAPTCHA traffic while the proof-of-work counters it
#    never touched read zero.  The kind is signed into the cookie; this asserts
#    the plugin reads it.
#
#    Asserted on the access-log line rather than on the admin's counters: the
#    counters are flushed on a 60s tick, so reading them proves the plugin's
#    output only after a wait longer than this whole suite.  The log line IS
#    the plugin's output, and the aggregation from it is covered by unit tests.
COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
MARK_PATH="/rebind-kind-probe-$$"
curl -sk -A "$UA_SOLVER" -H "X-Forwarded-For: $IP_B" -H "Cookie: _bv=$bvB" \
    -o /dev/null "${BASE_URL}${MARK_PATH}"
logline=$(docker compose -f "$COMPOSE" exec -T nginx \
    sh -c "grep -h -- '$MARK_PATH' /var/log/nginx/unmask-decisions.log 2>/dev/null | tail -1" 2>/dev/null | tr -d '\r')
if [ -z "$logline" ]; then
    log_skip "rebind kind check: the probe request left no access-log line"
else
    case "$logline" in
        *bv_kind=rebind*) log_pass "the plugin reports bv_kind=rebind for a re-bound pass";;
        *bv_kind=captcha*) log_fail "a re-bound pass is being reported as bv_kind=captcha (the shape-based reading is back): $logline";;
        *) log_fail "expected bv_kind=rebind, got: $logline";;
    esac
fi
