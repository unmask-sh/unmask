#!/bin/bash
# 48: protect.inc at SERVER scope must not break the /unmask/ machinery.
#
# If protect.inc is included directly in server { } (the "whole site" install
# example) instead of inside a location { }, its rewrite-phase challenge gate
# also fires for /unmask/* — so /unmask/api/verify and /unmask/static/challenge.js
# get rewritten into the challenge and every human loops forever (bots still 403,
# so it looks "working" to the operator).  This is the self-DoS that hit
# unmask.sh on 2026-07-02.  The fix adds `if ($uri ~ "^/unmask/") { break; }`
# (classic) / `set $unmask_compose 0` (compose) so the machinery reaches its own
# `location ^~ /unmask/`.  The site body must still be challenged.
#
# vhost: SRV_SCOPE_URL (= :8444), protect.inc at server scope.  See
# e2e/docker/nginx/nginx.conf.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

fails=0
B="$SRV_SCOPE_URL"

# (1) machinery: verify API must NOT be challenged — it must reach the daemon
# (JSON), not the challenge HTML.  A _bv-less curl (challenge-class) is used so
# that, without the bypass, the gate would definitely rewrite it.
btmp=$(mktemp)
ct=$(curl -sk -A "$UA_CURL" -H 'X-Forwarded-For: 203.0.113.90' \
    -o "$btmp" -w '%{content_type}' -X POST -H 'Content-Type: application/json' \
    -d '{}' "${B}/unmask/api/verify")
if printf '%s' "$ct" | grep -qi 'application/json' && ! grep -qF 'probe=' "$btmp"; then
    log_pass "server-scope: /unmask/api/verify reaches the daemon (JSON, not challenged)"
else
    log_fail "server-scope: /unmask/api/verify should hit the daemon (JSON), got ct=$ct body:\n$(head -c 300 "$btmp")"
    fails=$((fails+1))
fi

# (2) machinery: challenge.js must be served as JS, not rewritten into the
# challenge HTML (a loop symptom).
ct=$(curl -sk -A "$UA_CURL" -H 'X-Forwarded-For: 203.0.113.91' \
    -o "$btmp" -w '%{content_type}' "${B}/unmask/static/challenge.js")
if printf '%s' "$ct" | grep -qi 'javascript'; then
    log_pass "server-scope: /unmask/static/challenge.js served as JS (not looped)"
else
    log_fail "server-scope: challenge.js expected javascript, got ct=$ct body:\n$(head -c 200 "$btmp")"
    fails=$((fails+1))
fi

# (3) the site body is STILL protected: a challenge-class visitor to / gets the
# challenge (403 + challenge HTML), proving the gate itself still works at
# server scope — only the /unmask/ machinery is exempted.
code=$(curl -sk -A "$UA_CURL" -H 'X-Forwarded-For: 203.0.113.92' \
    -o "$btmp" -w '%{http_code}' "${B}/")
if [ "$code" = "403" ] && grep -qF 'probe=' "$btmp"; then
    log_pass "server-scope: site / still challenged (403 + challenge HTML)"
else
    log_fail "server-scope: site / expected challenge (403 + challenge HTML), got code=$code body:\n$(head -c 300 "$btmp")"
    fails=$((fails+1))
fi

rm -f "$btmp"
exit "$fails"
