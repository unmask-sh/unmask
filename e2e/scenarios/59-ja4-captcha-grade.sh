#!/bin/bash
# 59: a bot-verdict JA4 is not satisfied by a proof-of-work cookie.
#
# The by-fingerprint sibling of scenario 56.  Measured live (2026-08-20): a
# residential-proxy herd solved the 16-bit proof-of-work through rotating
# exits, then rode the minted cookies through content pages -- 1,086 riding
# addresses in one hour -- while the CAPTCHA the fingerprint rule asked for
# stopped it cold (0 solves in 3,060 serves).  The cookie was valid; it was
# simply not the credential the rule demanded.  Before the fix, the JA4 axis
# was the one grade source missing from $unmask_needs_captcha_grade (native)
# and the pass-cookie veto (forward-auth): a bot-verdict fingerprint was
# CAPTCHA-gated only while arriving bare.
#
# What must NOT break: the same cookie under a fingerprint with no verdict
# still passes -- and both wires must agree (the fixture rule has no explicit
# action, so the chain inherits the operating default -- pow_then_captcha --
# on each; that chain ends in a CAPTCHA, so the grade demand follows).
#
# UA choice, native leg: a challenge-target UA (curl), NOT a browser one.  The
# gate decides whether a cookie EXEMPTS a request, not whether the request is
# challenged in the first place -- and native's $final_challenge_base has no
# row that challenges on a bot JA4 alone, so with this install's
# known_browser_action=pass a browser UA is passed by the Global axis before
# the refusal can show.  curl is a challenge target on a pow_only chain here,
# so its cookie is the only thing standing between it and a challenge: exactly
# the isolation this scenario needs.  (Forward-auth's ja4Decide challenges a
# bot verdict on its own, so its leg reads the same either way.)
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

JA4_OK="t13ok000000000_xxx_yyy"   # no verdict -> no grade demand
JA4_BOT="t13e2e0bot01_xxx_yyy"    # admin.yml extra rule -> action=bot
IP_A=203.0.113.70

# A real proof-of-work cookie, solved the way challenge.js solves it (same
# helper shape as scenarios 36 / 56).  _bv binds to address + host, never to
# the TLS fingerprint, so presenting it under the bot JA4 is exactly what the
# herd's proxy-solved cookies look like when the exits rotate.
solve_bv() {
    local ip="$1" ch seed issued diff
    ch=$(curl -sk -A "$UA_CURL" -H "X-Forwarded-For: $ip" -H "X-Client-JA4: $JA4_OK" \
        "${BASE_URL}/unmask/challenge/")
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

# 1. Native wire: the bot fingerprint demands a CAPTCHA grade; pow is refused.
code=$(curl -sk -A "$UA_CURL" -H "X-Forwarded-For: $IP_A" -H "X-Client-JA4: $JA4_BOT" \
    -H "Cookie: _bv=$bv" -o /dev/null -w '%{http_code}' "${BASE_URL}/")
assert_eq 403 "$code" "native: a PoW cookie does not satisfy a bot-verdict fingerprint"

# 2. Native wire: the same cookie under a clean fingerprint still passes -- the
#    refusal is the fingerprint's doing, not the cookie being weak.
code=$(curl -sk -A "$UA_CURL" -H "X-Forwarded-For: $IP_A" -H "X-Client-JA4: $JA4_OK" \
    -H "Cookie: _bv=$bv" -o /dev/null -w '%{http_code}' "${BASE_URL}/")
assert_eq 200 "$code" "native: the same cookie passes where no verdict asks for a CAPTCHA"

# 3. Forward-auth wire: same pair of truths through auth_request's nginx.
#    Body-shape assertions like scenario 42 -- the backend marker either
#    survives (pass) or the challenge page replaces it.
fails=0
body=$(curl -s -A "$UA_BROWSER" -H "X-Forwarded-For: $IP_A" -H "X-Client-JA4: $JA4_BOT" \
    -H "Cookie: _bv=$bv" "${FA_NGINX_URL}/")
if printf '%s' "$body" | grep -qF "[fa-nginx backend]"; then
    log_fail "forward-auth: a PoW cookie satisfied a bot-verdict fingerprint"
    fails=$((fails+1))
else
    log_pass "forward-auth: a PoW cookie does not satisfy a bot-verdict fingerprint"
fi

body=$(curl -s -A "$UA_BROWSER" -H "X-Forwarded-For: $IP_A" -H "X-Client-JA4: $JA4_OK" \
    -H "Cookie: _bv=$bv" "${FA_NGINX_URL}/")
if printf '%s' "$body" | grep -qF "[fa-nginx backend]"; then
    log_pass "forward-auth: the same cookie passes under a clean fingerprint"
else
    log_fail "forward-auth: the cookie was refused where no verdict asks for a CAPTCHA"
    fails=$((fails+1))
fi

exit "$fails"
