#!/bin/bash
# 52: a browser pinned to a stale Chromium major is escalated to a CAPTCHA,
# even though known_browser_action is "pass".
#
# Regression guard for the 2026-07-15 uic.io scraper: a distributed bot pinned
# one outdated Chrome build (Chrome/139 while stable was 150) across ~4k
# residential-proxy IPs and solved the transparent PoW headlessly, so its JA4
# and UA read as a real browser and it passed.  The stale-browser tier catches
# the frozen version and forces the CAPTCHA a headless PoW-solver cannot cheaply
# clear.
#
# admin.yml (e2e): stale_browser_challenge on, current 150 / lag 35 -> threshold
# 115.  So Chrome/120 (every other scenario's UA) stays fresh and passes, while
# Chrome/100 here is stale.  known_browser_action is "pass", so a pass here would
# mean the tier did nothing.  Three cases:
#   1. stale UA  + ordinary IP -> 403 challenge, chmode escalated to captcha_only
#   2. current UA + ordinary IP -> 200 pass          (no over-catch of real browsers)
#   3. stale UA  + bypass IP    -> 200 pass          (monitoring bypass wins, evaluated first)
#
# The realistic 150/11/139 threshold semantics are pinned by the Go unit tests
# (classify.IsStaleBrowser, uaDecide); this proves the end-to-end native wiring.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

UA_STALE='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36'
# A monitoring probe's IP (admin.yml nginx.bypass_ips).
BYPASS_IP=203.0.113.222

fails=0

# 1. stale browser on an ordinary IP: challenged, and the served challenge's
#    inlined chmode is captcha_only (PoW skipped) — the whole point of the tier.
btmp=$(mktemp)
code=$(curl -sk -A "$UA_STALE" -H 'X-Forwarded-For: 203.0.113.90' \
    -o "$btmp" -w '%{http_code}' "${BASE_URL}/")
if [ "$code" = "403" ] && grep -qF 'probe=' "$btmp"; then
    log_pass "stale browser (Chrome/100) → challenged (403)"
else
    log_fail "stale browser expected 403 + challenge HTML, got code=$code"
    fails=$((fails+1))
fi
# The challenge page inlines `challenge_mode: /*__CHMODE__*/"<mode>"`.
if grep -qE 'challenge_mode:[^,]*"captcha_only"' "$btmp"; then
    log_pass "stale browser → escalated to captcha_only (PoW skipped)"
else
    log_fail "stale browser challenge should be captcha_only; served chmode:\n$(grep -oE 'challenge_mode:[^,]*' "$btmp" | head -1)"
    fails=$((fails+1))
fi
rm -f "$btmp"

# 2. current browser (Chrome/120) on an ordinary IP: passes untouched, proving
#    the tier does not over-catch the real long tail (known_browser_action=pass).
btmp=$(mktemp)
code=$(curl -sk -A "$UA_BROWSER" -H 'X-Forwarded-For: 203.0.113.91' \
    -o "$btmp" -w '%{http_code}' "${BASE_URL}/")
if [ "$code" = "200" ] && grep -qF '[unmask e2e]' "$btmp"; then
    log_pass "current browser (Chrome/120) → passes (control, no over-catch)"
else
    log_fail "current browser expected 200 + echo, got code=$code body:\n$(cat "$btmp")"
    fails=$((fails+1))
fi
rm -f "$btmp"

# 3. stale browser from a trusted bypass IP (a monitoring probe): passes.  The
#    bypass veto is evaluated before the stale tier, so an old-UA probe is never
#    challenged (the handoff's admin1 monitoring requirement).
code=$(curl -sk -A "$UA_STALE" -H "X-Forwarded-For: $BYPASS_IP" \
    -o /dev/null -w '%{http_code}' "${BASE_URL}/")
if [ "$code" = "200" ]; then
    log_pass "stale UA from a bypass IP → passes (monitoring bypass wins)"
else
    log_fail "bypass IP + stale UA expected 200, got code=$code"
    fails=$((fails+1))
fi

exit "$fails"
