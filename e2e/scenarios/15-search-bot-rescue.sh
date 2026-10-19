#!/bin/bash
# 15: crawler rescue on the native nginx-module path — range-verified edition.
#
# "Never block a legitimate search bot" is the SEO-safe design principle, but
# since the range-verified inversion (uarange.go) the UA string alone no
# longer proves legitimacy for vendors that publish official IP ranges:
#   - a crawler UA WITHOUT a published range (PetalBot) keeps the pure
#     UA-string rescue — it must sail through even a protected path;
#   - a crawler UA WITH a published range (Googlebot / bingbot / GPTBot)
#     is rescued by IP instead.  This suite's client IP is not in any vendor
#     range, so those UAs are spoofs by definition and must NOT be exempt:
#     on a protected path they get the challenge like any other client.
#     (Before the inversion they walked through — the 2026-07-15 fake-
#     Googlebot botnet did exactly that.)
#
# The genuine-crawler side of the inversion (vendor-range source IP → pass)
# is scenario 51, which injects a range override; here we pin the spoof side
# and the range-less control.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

fails=0

# IP isolation: keep this scenario on a dedicated XFF so honeypot bans from
# prior scenarios (02 / 03 / 04) don't reject these UAs at the IP-ban gate
# before the UA / range logic has a chance to run.
CLIENT_IP=198.51.100.150

# /login/ is a captcha-protected path in the e2e config.yml: a client that is
# neither UA-rescued nor IP-rescued gets the challenge page there (no origin
# echo), which is what distinguishes "rescued" from "merely not challenged".
PROTECTED_PATH=/login/

# A rescued request reaches the @echo origin (body "[unmask e2e]"); a
# challenged one gets the challenge HTML instead (no echo marker).
fetch() {
    local ua="$1" path="$2" body_tmp="$3"
    curl -sk -A "$ua" -H "X-Forwarded-For: $CLIENT_IP" \
        -o "$body_tmp" -w '%{http_code}' "${BASE_URL}${path}"
}

check_rescued() {
    local name="$1" ua="$2" path="$3"
    local body_tmp code
    body_tmp=$(mktemp)
    code=$(fetch "$ua" "$path" "$body_tmp")
    if [ "$code" = "200" ] && grep -qF '[unmask e2e]' "$body_tmp"; then
        log_pass "$name UA → passed to origin on $path (= 200)"
    else
        log_fail "$name UA: expected 200 + origin echo on $path, got code=$code body:\n$(cat "$body_tmp")"
        fails=$((fails+1))
    fi
    rm -f "$body_tmp"
}

check_challenged() {
    local name="$1" ua="$2" path="$3"
    local body_tmp code
    body_tmp=$(mktemp)
    code=$(fetch "$ua" "$path" "$body_tmp")
    if grep -qF '[unmask e2e]' "$body_tmp"; then
        log_fail "$name UA: spoofed crawler reached the origin on $path (code=$code) — the range inversion is not in effect"
        fails=$((fails+1))
    else
        log_pass "$name UA → challenged on $path (code=$code, no origin echo)"
    fi
    rm -f "$body_tmp"
}

# Range-less crawler: pure UA rescue must survive, including on a protected path.
check_rescued "PetalBot" "$UA_PETALBOT" "/"
# A crawler known by its name alone clears the global posture and nothing else:
# a protected path, a honeypot it trips and the per-address budget are not
# opened by the name (its vendor publishes no range to verify it against).
check_challenged "PetalBot (name-only, protected path)" "$UA_PETALBOT" "$PROTECTED_PATH"
check_challenged "PetalBot (name-only, honeypot)" "$UA_PETALBOT" "/wp-login.php"
# (The GET / HEAD gate on the name is pinned by the render test
# named_rescue_render_test: in this suite's posture an unrescued crawler UA
# passes "/" like any ordinary client, so a POST shows no difference here.)
# The budget: 30 a minute per address by default (burst of one minute), so a
# fresh address gets its first fetches and loses the name past the bucket.
BUDGET_IP=198.51.100.151
first=$(curl -sk -A "$UA_PETALBOT" -H "X-Forwarded-For: $BUDGET_IP" -o /dev/null -w '%{http_code}' "${BASE_URL}/")
assert_eq 200 "$first" "PetalBot UA: the first fetch from a fresh address passes on the name" || fails=$((fails+1))
over=0
for i in $(seq 1 45); do
    c=$(curl -sk -A "$UA_PETALBOT" -H "X-Forwarded-For: $BUDGET_IP" -o /dev/null -w '%{http_code}' "${BASE_URL}/")
    [ "$c" = "200" ] || over=$((over+1))
done
if [ "$over" -gt 0 ]; then
    log_pass "PetalBot UA: past the per-address budget the name buys nothing ($over of 45 fetches answered with a challenge)"
else
    log_fail "PetalBot UA: 46 fetches in a row all passed on the name -- the name-only budget did not count them"
    fails=$((fails+1))
fi

# Range-verified vendors from a non-vendor IP (= spoofs): no UA exemption on
# the protected path.  ClaudeBot joined this list when Anthropic published
# bots.json — it used to be the range-less control above.
check_challenged "Googlebot (spoof)" "$UA_GOOGLEBOT" "$PROTECTED_PATH"
check_challenged "Bingbot (spoof)"   "$UA_BINGBOT"   "$PROTECTED_PATH"
check_challenged "GPTBot (spoof)"    "$UA_GPTBOT"    "$PROTECTED_PATH"
check_challenged "ClaudeBot (spoof)" "$UA_CLAUDEBOT" "$PROTECTED_PATH"

exit "$fails"
