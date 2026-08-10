#!/bin/bash
# 57: a protected path whose mode ends in a CAPTCHA is not satisfied by a
# proof-of-work cookie (the protected-path twin of scenario 56).
#
# The reported hole: the "unmask" preset gates /unmask/admin/ in
# pow_then_captcha, but a request carrying only a PoW cookie sailed through --
# the pass gate's CAPTCHA-grade requirement keyed on the UA axis alone and never
# looked at $protected_mode.  A headless PoW-solver could reach a captcha-graded
# admin gate with a cookie it minted itself.
#
# What must NOT break: a pow-only protected path still accepts a PoW cookie, and
# the same PoW cookie still passes on ordinary (unprotected) paths.
#
# admin.yml protected_paths: /login/ = captcha, /pow-gate/ = pow.  Distinct
# X-Forwarded-For IPs (RFC 5737 TEST-NET-3) isolate from ban/honeypot state.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

IP_A=203.0.113.70

# A genuine PoW cookie, solved the way challenge.js solves it (same shape as
# scenario 56).  UA_CURL is on the install's pow_only path, so this mints a
# pow-grade _bv bound to IP_A + the host.
solve_bv() {
    local ip="$1" ch seed issued diff
    ch=$(curl -sk -A "$UA_CURL" -H "X-Forwarded-For: $ip" "${BASE_URL}/unmask/challenge/")
    seed=$(printf '%s' "$ch" | grep -oE '__POW_SEED__\*/"[0-9a-f]+' | grep -oE '[0-9a-f]{40}' | head -1)
    issued=$(printf '%s' "$ch" | grep -oE '__ISSUED_AT__\*/[0-9]+' | grep -oE '[0-9]{6,}' | head -1)
    diff=$(printf '%s' "$ch" | grep -oE '__POW_DIFFICULTY__\*/[0-9]+' | grep -oE '[0-9]+$' | head -1)
    [ -n "$seed" ] && [ -n "$issued" ] || { echo ""; return; }
    python3 "$DIR/lib/powsolve.py" "$seed" "$issued" "${diff:-18}"
}

bv=$(solve_bv "$IP_A")
if [ -z "$bv" ]; then
    log_fail "PoW solve produced no _bv"
    exit 1
fi

fails=0

# 1. THE FIX: a captcha-graded protected path (/login/) refuses the PoW cookie.
#    A browser UA is used so the ONLY thing forcing the challenge is the
#    protected axis (not the UA axis) -- exactly the reported shape.
btmp=$(mktemp)
code=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $IP_A" -H "Cookie: _bv=$bv" \
    -o "$btmp" -w '%{http_code}' "${BASE_URL}/login/")
if [ "$code" = "403" ] && grep -qF 'probe=' "$btmp"; then
    log_pass "a PoW cookie does not satisfy a captcha-graded protected path (= 403)"
else
    log_fail "captcha-protected /login/ with a PoW cookie: expected 403 + challenge, got code=$code"
    fails=$((fails+1))
fi
rm -f "$btmp"

# 2. Control: the same PoW cookie passes on an ordinary, unprotected path.
btmp=$(mktemp)
code=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $IP_A" -H "Cookie: _bv=$bv" \
    -o "$btmp" -w '%{http_code}' "${BASE_URL}/")
if [ "$code" = "200" ] && grep -qF '[unmask e2e]' "$btmp"; then
    log_pass "the same PoW cookie still passes on an unprotected path"
else
    log_fail "unprotected / with a PoW cookie: expected 200 + echo, got code=$code"
    fails=$((fails+1))
fi
rm -f "$btmp"

# 3. No over-block: a pow-mode protected path (/pow-gate/) still accepts the
#    PoW cookie -- only a captcha-ending mode demands a CAPTCHA grade.
code=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $IP_A" -H "Cookie: _bv=$bv" \
    -o /dev/null -w '%{http_code}' "${BASE_URL}/pow-gate/")
assert_eq 200 "$code" "a pow-mode protected path still accepts a PoW cookie" || fails=$((fails+1))

exit "$fails"
