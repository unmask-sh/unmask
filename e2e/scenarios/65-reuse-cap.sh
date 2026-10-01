#!/bin/bash
# 65: the pass-cookie reuse cap stops a client that keeps reusing one pass.
#
# Every rate limit counts only requests WITHOUT a valid pass cookie, so a
# scraper that runs a real browser, solves the proof-of-work once and then
# reuses the cookie is never counted again for as long as the cookie lives.
# settings.rate_limit.reuse counts only the requests WITH a valid pass, per
# client address.  This scenario plays that scraper on the real stack:
#
#   1. the cap is on by default (the stack renders it at the seeds); give it a
#      small budget (1,440 a day = one a minute, 20 at once), re-render,
#      reload nginx
#   2. solve the proof-of-work, then reuse the pass: the first 21 requests
#      pass, the rest get a CAPTCHA-only challenge recorded as reuse_limit
#      (an API client hears the same reason); solving the proof-of-work
#      again gives a new pass but not a new budget -- it is still over
#   3. the same address without the cookie is not counted by the cap (the
#      plain challenge, not reuse_limit); another address with its own pass
#      is not affected
#   4. with the action set to deny, the address over the cap gets the deny
#      page instead
#
# Needs the docker e2e stack (it rewrites config.yml in the unmask container,
# restarts it and reloads nginx) and python3 on the host; skips otherwise.
# The config is put back on exit.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
if ! command -v docker >/dev/null 2>&1 || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q unmask 2>/dev/null)" ]; then
    log_skip "65-reuse-cap needs the docker e2e stack (unmask container) — skipped"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    log_skip "65-reuse-cap needs python3 on the host — skipped"
    exit 0
fi
dc() { docker compose -f "$COMPOSE" "$@"; }
CFG=/etc/unmask/config.yml
OUT_DIR=/etc/unmask   # = nginx.output_dir in the fixture config
IP1=203.0.113.65
IP2=203.0.113.66
BUDGET_BURST=20

WORK=$(mktemp -d)
healthz() { curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "${BASE_URL}/unmask/healthz"; }
wait_healthz() {
    local i
    for i in $(seq 1 60); do
        [ "$(healthz)" = 200 ] && return 0
        sleep 1
    done
    return 1
}
put_config() { dc exec -T --user root unmask sh -c "cat > $CFG" < "$1"; }
# Restart the daemon (it re-renders the includes on start) and reload nginx:
# SIGHUP to the master, as scenario 58 explains (`nginx -s reload` would look
# for a compiled-in prefix this image does not have).
apply() {
    dc restart unmask >/dev/null 2>&1
    wait_healthz || return 1
    dc exec -T --user root nginx sh -c 'kill -HUP 1' >/dev/null 2>&1
    sleep 3
}
# Put the config back on the way out.  This replaces assert.sh's exit guard,
# so it keeps the exit status and fails the run when any assertion did.
restore() {
    local rc=$?
    if [ -s "$WORK/config.orig.yml" ]; then
        put_config "$WORK/config.orig.yml" >/dev/null 2>&1 || true
        apply >/dev/null 2>&1 || true
    fi
    rm -rf "$WORK"
    if [ "$rc" -eq 0 ] && [ "${_E2E_FAILS:-0}" -gt 0 ]; then
        rc=1
    fi
    exit "$rc"
}
trap restore EXIT

# The fixture config with a small reuse budget under rate_limit (action: $1).
make_config() {
    python3 - "$WORK/config.orig.yml" "$1" "$BUDGET_BURST" <<'EOF'
import sys
src, action, burst = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(src).read().split("\n")
i = lines.index("rate_limit:")
assert not any(l.startswith("  reuse:") for l in lines), "the fixture already has a reuse block"
lines[i + 1:i + 1] = ["  reuse:", "    per_day: 1440",
                      "    burst: " + burst, "    action: " + action]
print("\n".join(lines), end="")
EOF
}

# A pass for $1: fetch the challenge as that address and solve its PoW.
get_pass() {
    local ip="$1" ch seed issued diff
    ch=$(curl -sk --max-time 8 -A "$UA_BROWSER" -H "X-Forwarded-For: $ip" "${BASE_URL}/unmask/challenge/")
    seed=$(printf '%s' "$ch" | grep -oE '__POW_SEED__\*/"[0-9a-f]+' | grep -oE '[0-9a-f]{40}' | head -1)
    issued=$(printf '%s' "$ch" | grep -oE '__ISSUED_AT__\*/[0-9]+' | grep -oE '[0-9]{6,}' | head -1)
    diff=$(printf '%s' "$ch" | grep -oE '__POW_DIFFICULTY__\*/[0-9]+' | grep -oE '[0-9]+$' | head -1)
    [ -n "$seed" ] && [ -n "$issued" ] || return 1
    python3 "$DIR/lib/powsolve.py" "$seed" "$issued" "${diff:-18}"
}
# GET / as $1 with the pass $2 ("" = no cookie); extra curl args follow.
visit() {
    local ip="$1" bv="$2"; shift 2
    if [ -n "$bv" ]; then
        curl -sk --max-time 8 -A "$UA_BROWSER" -H "X-Forwarded-For: $ip" -H "Cookie: _bv=$bv" "$@" "${BASE_URL}/"
    else
        curl -sk --max-time 8 -A "$UA_BROWSER" -H "X-Forwarded-For: $ip" "$@" "${BASE_URL}/"
    fi
}

dc exec -T unmask cat "$CFG" > "$WORK/config.orig.yml"
if ! grep -q '^rate_limit:$' "$WORK/config.orig.yml"; then
    log_fail "pre-flight: the fixture config has no top-level rate_limit block to extend"
    exit 1
fi
# On by default: the untouched fixture already renders the cap, at the seeds.
assert_in "zone=unmask_reuse:10m rate=7r/m" "$(dc exec -T unmask cat "$OUT_DIR/http.inc" 2>/dev/null)" \
    "the cap is on by default (10,000 a day = seven a minute)"

# --- 1. the cap on (captcha_only) ------------------------------------------
make_config captcha_only > "$WORK/config.cap.yml" && put_config "$WORK/config.cap.yml"
if ! apply; then
    log_fail "the daemon did not come back after the config change"
    exit 1
fi
assert_in "zone=unmask_reuse:10m rate=1r/m" "$(dc exec -T unmask cat "$OUT_DIR/http.inc" 2>/dev/null)" \
    "http.inc declares the reuse zone (1,440 a day = one a minute)"
assert_in "limit_req zone=unmask_reuse burst=${BUDGET_BURST} nodelay;" "$(dc exec -T unmask cat "$OUT_DIR/protect.inc" 2>/dev/null)" \
    "protect.inc applies it"

# --- 2. reuse one pass past the budget -------------------------------------
BV1=$(get_pass "$IP1")
if [ -z "$BV1" ]; then
    log_fail "could not solve the proof-of-work for $IP1"
    exit 1
fi
: > "$WORK/codes"
first_over=""
for i in $(seq 1 40); do
    code=$(visit "$IP1" "$BV1" -o "$WORK/body.$i" -w '%{http_code}')
    echo "$code" >> "$WORK/codes"
    if [ "$code" = 429 ] && [ -z "$first_over" ]; then first_over=$i; fi
done
n200=$(grep -c '^200$' "$WORK/codes")
n429=$(grep -c '^429$' "$WORK/codes")
log_note "65 reuse cap: one pass reused 40 times -> ${n200} passed, ${n429} stopped with 429 (budget: ${BUDGET_BURST} at once, one a minute)"
if [ "$n200" -ge "$BUDGET_BURST" ] && [ "$n200" -le $((BUDGET_BURST + 2)) ]; then
    log_pass "the pass carries its holder through the budget ($n200 x 200) and no further"
else
    log_fail "expected about $((BUDGET_BURST + 1)) passes before the cap, got $n200 (codes: $(tr '\n' ' ' < "$WORK/codes"))"
fi
assert_eq $((40 - n200)) "$n429" "every request over the budget is stopped with 429 Too Many Requests"
if [ -n "$first_over" ]; then
    over_body=$(cat "$WORK/body.$first_over")
    assert_in '"reuse_limit"' "$over_body" "the challenge over the cap is recorded as reuse_limit"
    assert_in '"captcha_only"' "$over_body" "and it is CAPTCHA-only: a proof-of-work does not get past it"
fi
api=$(visit "$IP1" "$BV1" -H 'Sec-Fetch-Dest: empty' -H 'Sec-Fetch-Mode: cors')
assert_in '"reason":"reuse_limit"' "$api" "an API client over the cap hears reuse_limit"
# Solving the proof-of-work again gets a new pass, not a new budget: the cap
# counts the address, so the fresh cookie is over it from its first request.
# A challenge is keyed on the second it is issued in (the seed is), so one
# asked for within the same second as the first IS the first, and solves to
# the same cookie: on a fast runner the forty requests above fit in that
# second.  Wait for the next one before asking again.
while [ "$(date +%s)" -le "${BV1%%.*}" ]; do sleep 0.1; done
BV1B=$(get_pass "$IP1")
if [ -n "$BV1B" ] && [ "$BV1B" != "$BV1" ]; then
    fresh=$(visit "$IP1" "$BV1B" -H 'Sec-Fetch-Dest: empty' -H 'Sec-Fetch-Mode: cors')
    assert_in '"reason":"reuse_limit"' "$fresh" "a fresh proof-of-work pass from the same address is still over the cap (the budget is the address's, not the cookie's)"
else
    log_fail "could not get a second pass for $IP1"
fi

# --- 3. what the cap does not count ----------------------------------------
plain=$(visit "$IP1" "")
assert_not_in "reuse_limit" "$plain" "the same address without the cookie is not counted by the cap (the plain challenge)"
BV2=$(get_pass "$IP2")
: > "$WORK/codes2"
for i in 1 2 3 4 5; do visit "$IP2" "$BV2" -o /dev/null -w '%{http_code}\n' >> "$WORK/codes2"; done
assert_eq 5 "$(grep -c '^200$' "$WORK/codes2")" "another address with its own pass is not affected (5 x 200)"

# --- 4. the deny action -----------------------------------------------------
make_config deny > "$WORK/config.deny.yml" && put_config "$WORK/config.deny.yml"
if ! apply; then
    log_fail "the daemon did not come back after switching the action to deny"
    exit 1
fi
# The bucket refills one a minute, so a request or two may pass after the
# restart; the address is still far over.
deny=""
for i in 1 2 3 4 5; do
    r=$(visit "$IP1" "$BV1" -H 'Sec-Fetch-Dest: empty' -H 'Sec-Fetch-Mode: cors' -w '|%{http_code}')
    if [ "${r##*|}" = 429 ]; then deny="${r%|*}"; break; fi
done
assert_in '"error":"rate_limited"' "$deny" "with action deny, the address over the cap gets the deny response"
assert_in '"reason":"reuse_limit"' "$deny" "recorded as reuse_limit"

[ "${_E2E_FAILS:-0}" -eq 0 ]
