#!/bin/bash
# 15: search / AI crawler rescue on the native nginx-module path.
#
# "Never block a legitimate search bot" is the SEO-safe design principle —
# a ranking incident is the one failure unmask must not cause.  Scenario 05
# covers this rescue on the auth_request endpoint; this one covers the
# primary native-module mode.
#
# A crawler UA listed in the embedded crawler-user-agents.json must reach the
# origin (= the e2e echo body "[unmask e2e]"), never the challenge page.
#
# This is the UA-match stage of the two-stage rescue.  The IP-range stage
# (an official Googlebot / Bingbot source IP) is not exercised here — it
# would need a pinned provider-IP fixture.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

fails=0

# IP isolation: keep this scenario on a dedicated XFF so honeypot bans from
# prior scenarios (02 / 03 / 04) don't reject these UAs at the IP-ban gate
# before the UA-rescue match has a chance to run.
CLIENT_IP=198.51.100.150

# A rescued request reaches the @echo origin (body "[unmask e2e]"); a
# challenged one gets the challenge HTML instead (no echo marker).
check_rescued() {
    local name="$1" ua="$2"
    local body_tmp code
    body_tmp=$(mktemp)
    code=$(curl -sk -A "$ua" -H "X-Forwarded-For: $CLIENT_IP" \
        -o "$body_tmp" -w '%{http_code}' "${BASE_URL}/")
    if [ "$code" = "200" ] && grep -qF '[unmask e2e]' "$body_tmp"; then
        log_pass "$name UA → passed to origin, not challenged (= 200)"
    else
        log_fail "$name UA: expected 200 + origin echo, got code=$code body:\n$(cat "$body_tmp")"
        fails=$((fails+1))
    fi
    rm -f "$body_tmp"
}

check_rescued "Googlebot" "$UA_GOOGLEBOT"
check_rescued "Bingbot"   "$UA_BINGBOT"
check_rescued "GPTBot"    "$UA_GPTBOT"
check_rescued "ClaudeBot" "$UA_CLAUDEBOT"

exit "$fails"
