#!/bin/bash
# 71: the reuse cap's per-pass tier counts one pass at a time.
#
# Scenario 65 plays the scraper that reuses one pass against the address's
# budget.  This one is the cap's other tier: the plugin names the pass that
# verified ($unmask_bv_id -- the seed a proof-of-work answers, the signature
# of a CAPTCHA entry), and settings.rate_limit.reuse.pass_per_hour is a
# budget per pass, so the people behind one address each have their own.  On
# the real stack (nginx + the plugin):
#
#   1. the tier is on by default (the untouched fixture renders its zone at
#      the seed, 500 an hour); give it the smallest budget (60 an hour = one
#      a minute, 60 at once) and leave the address tier at its seeds (2,000
#      at once, so it never speaks here), re-render, reload nginx
#   2. one pass used 70 times: the first 60 or so pass, the rest get a
#      CAPTCHA-only challenge recorded as reuse_limit
#   3. the same seed answered with another nonce is the same pass: still over
#      (a nonce is no identity -- any number of them answer one seed)
#   4. a pass of another second (a new challenge, so a new seed) from the same
#      address has a budget of its own: it passes -- the address is not over
#   5. the CAPTCHA served over the budget makes a new pass: its holder passes,
#      and the proof-of-work pass alone stays over
#   6. with the action set to deny, the pass over its budget gets the deny
#      page
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
    log_skip "71-reuse-pass needs the docker e2e stack (unmask container) — skipped"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    log_skip "71-reuse-pass needs python3 on the host — skipped"
    exit 0
fi
dc() { docker compose -f "$COMPOSE" "$@"; }
CFG=/etc/unmask/config.yml
OUT_DIR=/etc/unmask   # = nginx.output_dir in the fixture config
IP1=203.0.113.71
PASS_BUDGET=60        # the smallest the cap takes: one a minute

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
# Restart the daemon (it re-renders the includes on start) and reload nginx
# with a SIGHUP to the master (scenario 58 explains why not `nginx -s reload`).
apply() {
    dc restart unmask >/dev/null 2>&1
    wait_healthz || return 1
    dc exec -T --user root nginx sh -c 'kill -HUP 1' >/dev/null 2>&1
    sleep 3
}
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

# The fixture config with the smallest per-pass budget under rate_limit
# (action: $1); the address tier keeps its seeds.
make_config() {
    python3 - "$WORK/config.orig.yml" "$1" "$PASS_BUDGET" <<'PY'
import sys
src, action, per_hour = sys.argv[1], sys.argv[2], sys.argv[3]
lines = open(src).read().split("\n")
i = lines.index("rate_limit:")
assert not any(l.startswith("  reuse:") for l in lines), "the fixture already has a reuse block"
lines[i + 1:i + 1] = ["  reuse:", "    pass_per_hour: " + per_hour, "    action: " + action]
print("\n".join(lines), end="")
PY
}

# Fetch the challenge as $1 and keep its seed, issue time and difficulty in
# $WORK/challenge.* -- one seed per second per address, so a second challenge
# asked for within the same second is the first again.
fetch_challenge() {
    local ip="$1" ch seed issued diff
    ch=$(curl -sk --max-time 8 -A "$UA_BROWSER" -H "X-Forwarded-For: $ip" "${BASE_URL}/unmask/challenge/")
    seed=$(printf '%s' "$ch" | grep -oE '__POW_SEED__\*/"[0-9a-f]+' | grep -oE '[0-9a-f]{40}' | head -1)
    issued=$(printf '%s' "$ch" | grep -oE '__ISSUED_AT__\*/[0-9]+' | grep -oE '[0-9]{6,}' | head -1)
    diff=$(printf '%s' "$ch" | grep -oE '__POW_DIFFICULTY__\*/[0-9]+' | grep -oE '[0-9]+$' | head -1)
    [ -n "$seed" ] && [ -n "$issued" ] || return 1
    printf '%s' "$seed" > "$WORK/challenge.seed"
    printf '%s' "$issued" > "$WORK/challenge.issued"
    printf '%s' "${diff:-18}" > "$WORK/challenge.diff"
}
# The nth answer to the challenge fetched last (1 = the first nonce that
# clears the difficulty, 2 = the next one), as the _bv cookie challenge.js
# would set.
solve() {
    python3 "$DIR/lib/powsolve.py" "$(cat "$WORK/challenge.seed")" "$(cat "$WORK/challenge.issued")" \
        "$(cat "$WORK/challenge.diff")" "$1"
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
# The API client's answer with the pass $2, once the bucket says 429 (it
# refills one a minute, so a request may slip through first).
over_api() {
    local i r
    for i in 1 2 3; do
        r=$(visit "$1" "$2" -H 'Sec-Fetch-Dest: empty' -H 'Sec-Fetch-Mode: cors' -w '|%{http_code}')
        if [ "${r##*|}" = 429 ]; then printf '%s' "${r%|*}"; return 0; fi
    done
    printf '%s' "${r%|*}"
    return 1
}

dc exec -T unmask cat "$CFG" > "$WORK/config.orig.yml"
if ! grep -q '^rate_limit:$' "$WORK/config.orig.yml"; then
    log_fail "pre-flight: the fixture config has no top-level rate_limit block to extend"
    exit 1
fi
# On by default: the untouched fixture renders the per-pass zone at the seed,
# 500 an hour = 8.3 a minute, keyed on the plugin's identity for the pass.
http_inc=$(dc exec -T unmask cat "$OUT_DIR/http.inc" 2>/dev/null)
assert_in "zone=unmask_reuse_pass:10m rate=9r/m" "$http_inc" \
    "the per-pass tier is on by default (500 an hour = nine a minute)"
assert_in 'map "$unmask_bv_id:$is_bypass_ip:$is_bypass_path" $rate_limit_key_pass {' "$http_inc" \
    "its key is the pass the plugin names"

# --- 1. the smallest budget (captcha_only) ----------------------------------
make_config captcha_only > "$WORK/config.cap.yml" && put_config "$WORK/config.cap.yml"
if ! apply; then
    log_fail "the daemon did not come back after the config change"
    exit 1
fi
assert_in "zone=unmask_reuse_pass:10m rate=1r/m" "$(dc exec -T unmask cat "$OUT_DIR/http.inc" 2>/dev/null)" \
    "http.inc declares the per-pass zone (60 an hour = one a minute)"
protect_inc=$(dc exec -T unmask cat "$OUT_DIR/protect.inc" 2>/dev/null)
assert_in "limit_req zone=unmask_reuse_pass burst=${PASS_BUDGET} nodelay;" "$protect_inc" \
    "protect.inc applies it with the hourly figure as the burst"
assert_in "limit_req zone=unmask_reuse burst=2000 nodelay;" "$protect_inc" \
    "the address tier stays at its seed (2,000 at once: silent here)"

# --- 2. one pass past its budget --------------------------------------------
fetch_challenge "$IP1" || { log_fail "could not fetch the challenge for $IP1"; exit 1; }
BV_A=$(solve 1)
[ -n "$BV_A" ] || { log_fail "could not solve the proof-of-work for $IP1"; exit 1; }
: > "$WORK/codes"
first_over=""
for i in $(seq 1 70); do
    code=$(visit "$IP1" "$BV_A" -o "$WORK/body.$i" -w '%{http_code}')
    echo "$code" >> "$WORK/codes"
    if [ "$code" = 429 ] && [ -z "$first_over" ]; then first_over=$i; fi
done
n200=$(grep -c '^200$' "$WORK/codes")
n429=$(grep -c '^429$' "$WORK/codes")
log_note "71 per-pass cap: one pass used 70 times -> ${n200} passed, ${n429} stopped with 429 (budget: ${PASS_BUDGET} at once, one a minute)"
if [ "$n200" -ge "$PASS_BUDGET" ] && [ "$n200" -le $((PASS_BUDGET + 2)) ]; then
    log_pass "one pass carries its holder through its budget ($n200 x 200) and no further"
else
    log_fail "expected about $((PASS_BUDGET + 1)) passes before the budget, got $n200 (codes: $(tr '\n' ' ' < "$WORK/codes"))"
fi
assert_eq $((70 - n200)) "$n429" "every request over the budget is stopped with 429 Too Many Requests"
if [ -n "$first_over" ]; then
    over_body=$(cat "$WORK/body.$first_over")
    assert_in '"reuse_limit"' "$over_body" "the challenge over the budget is recorded as reuse_limit"
    assert_in '"captcha_only"' "$over_body" "and it is CAPTCHA-only: a proof-of-work does not get past it"
fi
assert_in '"reason":"reuse_limit"' "$(over_api "$IP1" "$BV_A")" "an API client over the budget hears reuse_limit"

# --- 3. another nonce is the same pass --------------------------------------
# The verifier accepts any nonce that clears the difficulty for the seed, and
# a script finds the next one in a moment.  The plugin names the pass by the
# seed, so this cookie draws on the budget the first one spent.
BV_A2=$(solve 2)
if [ -n "$BV_A2" ] && [ "$BV_A2" != "$BV_A" ]; then
    assert_in '"reason":"reuse_limit"' "$(over_api "$IP1" "$BV_A2")" \
        "the same seed answered with another nonce is the same pass: still over its budget"
else
    log_fail "could not find a second nonce for the seed"
fi

# --- 4. a pass of another second is another pass ----------------------------
# A challenge is keyed on the second it is issued in (the seed is), so wait
# for the next second before asking again: that seed is a new pass, with a
# budget of its own -- the address is not over anything.
while [ "$(date +%s)" -le "$(cat "$WORK/challenge.issued")" ]; do sleep 0.1; done
fetch_challenge "$IP1" || { log_fail "could not fetch a second challenge for $IP1"; exit 1; }
BV_B=$(solve 1)
if [ -n "$BV_B" ] && [ "${BV_B%%.*}" != "${BV_A%%.*}" ]; then
    : > "$WORK/codes_b"
    for i in 1 2 3 4 5; do visit "$IP1" "$BV_B" -o /dev/null -w '%{http_code}\n' >> "$WORK/codes_b"; done
    assert_eq 5 "$(grep -c '^200$' "$WORK/codes_b")" \
        "a pass of another second from the same address has a budget of its own (5 x 200)"
else
    log_fail "could not get a pass of another second for $IP1"
fi
# The first pass is still over: a new pass did not lift its budget.
assert_in '"reason":"reuse_limit"' "$(over_api "$IP1" "$BV_A")" "the first pass is still over its own budget"

# --- 5. the CAPTCHA served over the budget is a new pass --------------------
# Solve it the way a browser over the budget does -- carrying the PoW pass,
# which the solve's entry goes in front of -- through the math CAPTCHA's API
# (scenario 04).  The solve is a pass of its own, with its own budget.
pct=$(captcha_page_ct "${BASE_URL}/unmask/challenge/" --max-time 8 -H "X-Forwarded-For: $IP1")
[ -n "$pct" ] || { log_fail "the challenge page carried no ct"; exit 1; }
new=$(curl -sk --max-time 8 -A "$UA_BROWSER" -H "X-Forwarded-For: $IP1" "${BASE_URL}/unmask/api/captcha/new?ct=$pct")
a=$(printf '%s' "$new" | grep -oE '"a":[0-9]+' | grep -oE '[0-9]+')
b=$(printf '%s' "$new" | grep -oE '"b":[0-9]+' | grep -oE '[0-9]+')
token=$(printf '%s' "$new" | grep -oE '"token":"[^"]+"' | sed -E 's/.*"token":"([^"]+)".*/\1/')
ct=$(printf '%s' "$new" | grep -oE '"ct":"[^"]+"' | sed -E 's/.*"ct":"([^"]+)".*/\1/')
BVC=""
if [ -n "$a" ] && [ -n "$b" ] && [ -n "$token" ]; then
    verify=$(curl -sk --max-time 8 -A "$UA_BROWSER" -H "X-Forwarded-For: $IP1" -H "Cookie: _bv=$BV_A" \
        -c "$WORK/jar" -H 'Content-Type: application/json' \
        -d "{\"token\":\"$token\",\"answer\":\"$((a + b))\",\"ct\":\"$ct\"}" \
        "${BASE_URL}/unmask/api/verify")
    assert_in '"ok":1' "$verify" "the CAPTCHA is solved with the pass over its budget"
    BVC=$(awk '$6 == "_bv" {print $7}' "$WORK/jar")
fi
if [ -n "$BVC" ] && [ "$BVC" != "$BV_A" ]; then
    : > "$WORK/codes_c"
    for i in 1 2 3 4 5; do visit "$IP1" "$BVC" -o /dev/null -w '%{http_code}\n' >> "$WORK/codes_c"; done
    assert_eq 5 "$(grep -c '^200$' "$WORK/codes_c")" "the solve is a new pass: its holder gets through (5 x 200)"
else
    log_fail "could not solve the CAPTCHA for $IP1 (captcha/new: $new)"
fi
assert_in '"reason":"reuse_limit"' "$(over_api "$IP1" "$BV_A")" "the proof-of-work pass on its own is still over"

# --- 6. the deny action -----------------------------------------------------
make_config deny > "$WORK/config.deny.yml" && put_config "$WORK/config.deny.yml"
if ! apply; then
    log_fail "the daemon did not come back after switching the action to deny"
    exit 1
fi
deny=$(over_api "$IP1" "$BV_A")
assert_in '"error":"rate_limited"' "$deny" "with action deny, the pass over its budget gets the deny response"
assert_in '"reason":"reuse_limit"' "$deny" "recorded as reuse_limit"

[ "${_E2E_FAILS:-0}" -eq 0 ]
