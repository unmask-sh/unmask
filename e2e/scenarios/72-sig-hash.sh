#!/bin/bash
# 72: the cookie signatures move to HMAC-SHA256 without a cliff.
#
# Every release so far signed the pass cookies and derived the proof-of-work
# seed with HMAC-SHA1.  The daemon and the module now verify both SHA-1 and
# SHA-256, and secret.sig_hash picks what is issued -- so an install moves
# once every nginx runs a module that verifies both, and the cookies signed
# before stay good for their window.  On the real stack (nginx + the plugin):
#
#   1. with the fixture as shipped (sig_hash unset) a 3-segment entry signed
#      with SHA-1 and one signed with SHA-256, both minted here from the
#      fixture's secret, verify in the module alike (the stack's debug
#      location echoes $bv_any_valid / $bv_kind), and a forged signature
#      does not; the honeypot path lets the signed one through and not the
#      forged one
#   2. with sig_hash: sha256 the challenge page's seed is the SHA-256 one
#      (HMAC-SHA256 of the same message, cut to 40 hex digits); a pass solved
#      against it verifies as a proof-of-work, and a CAPTCHA solved through
#      the API hands out a SHA-256-signed cookie the honeypot path honours
#   3. a pass solved against the SHA-1 seed of the same second -- a cookie
#      from before the move -- still verifies
#
# Needs the docker e2e stack and python3 on the host; skips otherwise.  The
# config is put back on exit.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
if ! command -v docker >/dev/null 2>&1 || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q unmask 2>/dev/null)" ]; then
    log_skip "72-sig-hash needs the docker e2e stack (unmask container) — skipped"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    log_skip "72-sig-hash needs python3 on the host — skipped"
    exit 0
fi
dc() { docker compose -f "$COMPOSE" "$@"; }
CFG=/etc/unmask/config.yml
IP1=203.0.113.72
HOST=localhost   # $host of BASE_URL, what the cookies are bound to

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
apply() {
    dc restart unmask >/dev/null 2>&1
    wait_healthz || return 1
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

dc exec -T unmask cat "$CFG" > "$WORK/config.orig.yml"
SECRET=$(sed -n 's/^[[:space:]]*bv_secret:[[:space:]]*//p' "$WORK/config.orig.yml" | head -1 | tr -d '"'"'")
[ -n "$SECRET" ] || { log_fail "pre-flight: the fixture config has no secret.bv_secret"; exit 1; }
grep -q '^secret:$' "$WORK/config.orig.yml" || { log_fail "pre-flight: the fixture config has no secret block"; exit 1; }

# mint <sha1|sha256> <kind> [issued]: a 3-segment entry for $IP1 and $HOST,
# signed the way cookies.IssueValueAtH signs.
mint() {
    python3 - "$SECRET" "$IP1" "$HOST" "$1" "$2" "${3:-}" <<'PY'
import sys, hmac, hashlib, time
secret, ip, host, alg, kind, issued = sys.argv[1:7]
issued = int(issued) if issued else int(time.time())
sig = hmac.new(secret.encode(), f"{issued}:{ip}:{host}:{kind}".encode(), getattr(hashlib, alg)).hexdigest()[:16]
print(f"{issued}.{sig}.{kind}")
PY
}
# seed <sha1|sha256> <issued>: the proof-of-work seed the daemon derives.
seed() {
    python3 - "$SECRET" "$IP1" "$HOST" "$1" "$2" <<'PY'
import sys, hmac, hashlib
secret, ip, host, alg, issued = sys.argv[1:6]
print(hmac.new(secret.encode(), f"{issued}:{ip}:{host}:pow_seed".encode(), getattr(hashlib, alg)).hexdigest()[:40])
PY
}
# verdict <cookie>: the module's own reading of the cookie, "<valid>/<kind>"
# from the stack's debug location (bv=$bv_any_valid, bv_kind=$bv_kind).
verdict() {
    local out
    out=$(curl -sk --max-time 8 -A "$UA_BROWSER" -H "X-Forwarded-For: $IP1" -H "Cookie: _bv=$1" "${BASE_URL}/__unmask_debug")
    printf '%s/%s' "$(printf '%s\n' "$out" | sed -n 's/^bv=//p')" "$(printf '%s\n' "$out" | sed -n 's/^bv_kind=//p')"
}
# trap <cookie>: the honeypot path (scenario 04): 403 without a pass, 200 with one.
trap_code() {
    curl -sk --max-time 8 -A "$UA_BROWSER" -H "X-Forwarded-For: $IP1" -H "Cookie: _bv=$1" -o /dev/null -w '%{http_code}' "${BASE_URL}/wp-login.php"
}
fetch_challenge() {
    local ch
    ch=$(curl -sk --max-time 8 -A "$UA_BROWSER" -H "X-Forwarded-For: $IP1" "${BASE_URL}/unmask/challenge/")
    SEED=$(printf '%s' "$ch" | grep -oE '__POW_SEED__\*/"[0-9a-f]+' | grep -oE '[0-9a-f]{40}' | head -1)
    ISSUED=$(printf '%s' "$ch" | grep -oE '__ISSUED_AT__\*/[0-9]+' | grep -oE '[0-9]{6,}' | head -1)
    DIFF=$(printf '%s' "$ch" | grep -oE '__POW_DIFFICULTY__\*/[0-9]+' | grep -oE '[0-9]+$' | head -1)
    [ -n "$SEED" ] && [ -n "$ISSUED" ]
}

# --- 1. both signatures verify, as shipped -----------------------------------
assert_eq "1/captcha" "$(verdict "$(mint sha1 captcha)")" "an entry signed with SHA-1 (every release so far) verifies in the module"
assert_eq "1/captcha" "$(verdict "$(mint sha256 captcha)")" "an entry signed with SHA-256 verifies too: the module tries both"
assert_eq "1/rebind" "$(verdict "$(mint sha256 rebind)")" "... whatever the kind"
bad=$(python3 -c 'import sys; e=sys.argv[1].split("."); e[1]="0123456789abcdef"; print(".".join(e))' "$(mint sha256 captcha)")
assert_eq "0/" "$(verdict "$bad")" "a forged signature verifies with neither"
assert_eq 200 "$(trap_code "$(mint sha256 captcha)")" "the honeypot path lets the SHA-256-signed pass through (200)"
assert_eq 403 "$(trap_code "$bad")" "and not the forged one (403)"

# --- 2. sig_hash: sha256 -----------------------------------------------------
python3 - "$WORK/config.orig.yml" > "$WORK/config.sha256.yml" <<'PY'
import sys
lines = open(sys.argv[1]).read().split("\n")
i = lines.index("secret:")
assert not any(l.startswith("    sig_hash:") for l in lines), "the fixture already names sig_hash"
lines[i + 1:i + 1] = ["  sig_hash: sha256"]   # the fixture indents by two
print("\n".join(lines), end="")
PY
put_config "$WORK/config.sha256.yml"
if ! apply; then
    log_fail "the daemon did not come back after setting sig_hash"
    exit 1
fi
fetch_challenge || { log_fail "could not fetch the challenge for $IP1"; exit 1; }
assert_eq "$(seed sha256 "$ISSUED")" "$SEED" "with sig_hash: sha256 the challenge page hands out the SHA-256 seed (40 hex digits)"
BV=$(python3 "$DIR/lib/powsolve.py" "$SEED" "$ISSUED" "${DIFF:-18}")
assert_eq "1/pow" "$(verdict "$BV")" "a pass solved against the SHA-256 seed verifies as a proof-of-work"

pct=$(captcha_page_ct "${BASE_URL}/unmask/challenge/" --max-time 8 -H "X-Forwarded-For: $IP1")
[ -n "$pct" ] || { log_fail "the challenge page carried no ct"; exit 1; }
new=$(curl -sk --max-time 8 -A "$UA_BROWSER" -H "X-Forwarded-For: $IP1" "${BASE_URL}/unmask/api/captcha/new?ct=$pct")
a=$(printf '%s' "$new" | grep -oE '"a":[0-9]+' | grep -oE '[0-9]+')
b=$(printf '%s' "$new" | grep -oE '"b":[0-9]+' | grep -oE '[0-9]+')
token=$(printf '%s' "$new" | grep -oE '"token":"[^"]+"' | sed -E 's/.*"token":"([^"]+)".*/\1/')
ct=$(printf '%s' "$new" | grep -oE '"ct":"[^"]+"' | sed -E 's/.*"ct":"([^"]+)".*/\1/')
BVC=""
if [ -n "$a" ] && [ -n "$b" ] && [ -n "$token" ]; then
    verify=$(curl -sk --max-time 8 -A "$UA_BROWSER" -H "X-Forwarded-For: $IP1" -c "$WORK/jar" -H 'Content-Type: application/json' \
        -d "{\"token\":\"$token\",\"answer\":\"$((a + b))\",\"ct\":\"$ct\"}" "${BASE_URL}/unmask/api/verify")
    assert_in '"ok":1' "$verify" "the CAPTCHA is solved"
    BVC=$(awk '$6 == "_bv" {print $7}' "$WORK/jar")
fi
if [ -n "$BVC" ]; then
    expect=$(mint sha256 captcha "${BVC%%.*}")
    assert_eq "$expect" "$BVC" "the solve's cookie is signed with SHA-256"
    assert_eq 200 "$(trap_code "$BVC")" "and the honeypot path lets it through (200)"
else
    log_fail "could not solve the CAPTCHA for $IP1 (captcha/new: $new)"
fi

# --- 3. a pass from before the move ------------------------------------------
OLD=$(python3 "$DIR/lib/powsolve.py" "$(seed sha1 "$ISSUED")" "$ISSUED" "${DIFF:-18}")
assert_eq "1/pow" "$(verdict "$OLD")" "a pass solved against the SHA-1 seed of the same second still verifies"
assert_eq "1/captcha" "$(verdict "$(mint sha1 captcha)")" "an entry signed with SHA-1 still verifies with sig_hash: sha256"

[ "${_E2E_FAILS:-0}" -eq 0 ]
