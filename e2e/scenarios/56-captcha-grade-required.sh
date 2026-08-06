#!/bin/bash
# 56: a rule that ends in a CAPTCHA is not satisfied by a proof-of-work cookie.
#
# The hole this closes, measured on a production install: a crawler read the
# challenge page, solved the 16-bit proof-of-work in its own code -- never
# running challenge.js, which is why the load counter stayed at 1 for a week --
# minted the 4-segment cookie itself, and served itself 137,051 requests a day
# through a UA rule whose chain ends in a CAPTCHA.  Every request was a genuine
# pass on a valid cookie.  The cookie was simply not the one the rule asked for.
#
# What must NOT break: the same cookie on a UA with no such rule still passes,
# and a real CAPTCHA cookie passes everywhere.  And the two halves of the
# policy have to agree -- if the gate refuses a roamed credential while the
# challenge route keeps re-binding it, the client loops between them forever.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

# UnmaskGradeProbe is pinned to captcha_only in the e2e config, so it carries
# the requirement; a browser UA carries none.  The cookie is solved under
# UA_CURL, which this install puts on pow_only -- a _bv binds to the address
# and the host, never to the UA, so presenting it under another name is
# exactly what a client holding a proof-of-work cookie "from somewhere else"
# looks like.  That is the production shape: the crawler minted its own.
UA_TARGET="Mozilla/5.0 (compatible; UnmaskGradeProbe/1.0)"
UA_SOLVE="$UA_CURL"
UA_PLAIN="$UA_BROWSER"
IP_A=203.0.113.60
IP_B=203.0.113.61

# A real proof-of-work cookie, solved the way challenge.js solves it.  Same
# helper shape as scenario 36 -- read the seed the page hands out, do the work,
# present the result.  This is exactly the path the production crawler used,
# minus the crawler.
solve_bv() {
    local ip="$1" ch seed issued diff
    ch=$(curl -sk -A "$UA_SOLVE" -H "X-Forwarded-For: $ip" "${BASE_URL}/unmask/challenge/")
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

# 1. The rule says CAPTCHA; a proof-of-work cookie does not satisfy it.
code=$(curl -sk -A "$UA_TARGET" -H "X-Forwarded-For: $IP_A" -H "Cookie: _bv=$bv" \
    -o /dev/null -w '%{http_code}' "${BASE_URL}/")
assert_eq 403 "$code" "a PoW cookie does not satisfy a captcha-chain rule"

# 2. The same cookie on a UA with no such rule is untouched.
code=$(curl -sk -A "$UA_PLAIN" -H "X-Forwarded-For: $IP_A" -H "Cookie: _bv=$bv" \
    -o /dev/null -w '%{http_code}' "${BASE_URL}/")
assert_eq 200 "$code" "the same cookie still passes where no rule asks for a CAPTCHA"

# 3. No loop: roaming the refused credential to a new address must serve the
#    real challenge, not silently re-bind it into the same refusal again.
resp=$(curl -sk -A "$UA_TARGET" -H "X-Forwarded-For: $IP_B" -H "Cookie: _bv=$bv" \
    -D- -o /dev/null "${BASE_URL}/" 2>/dev/null)
printf '%s' "$resp" | grep -qi '^x-unmask-mode: rebind' \
    && log_fail "the challenge route re-bound a credential the gate will refuse -- this is the loop" \
    || log_pass "a credential the gate refuses is not silently re-bound"
