#!/bin/bash
# 44: the forward-auth DECISION endpoint /unmask/api/check is NOT publicly
# reachable through the front.  It is the handler that records bans and counts
# rate-limit by client IP, and is meant to be hit ONLY by the internal check
# (nginx /_unmask/check subrequest; apache-unmask.lua's luasocket call).  Left
# public, a direct client could POST it with a forged X-Original-IP / X-Real-IP +
# X-Original-URI and ban / rate-poison another IP (e.g. get a search engine
# banned) -- the exact harm unmask exists to prevent.
#
# Asserts both forward-auth fronts (stock-nginx fa-nginx + apache) return 404 for
# a direct /unmask/api/check, while the front is otherwise healthy (healthz still
# proxies) -- so the block is scoped to the decision endpoint, not the passthrough.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

fails=0

# Pre-flight: both fronts reachable?
for u in "$FA_NGINX_URL" "$APACHE_URL"; do
    if ! curl -fsS -o /dev/null --max-time 5 "${u}/unmask/healthz"; then
        log_fail "pre-flight: ${u}/unmask/healthz unreachable -- is the container up?"
        exit 1
    fi
done

for front in "$FA_NGINX_URL" "$APACHE_URL"; do
    # Direct hit on the decision endpoint with a forged victim IP + honeypot URI:
    # must be blocked at the front (404), never reaching the daemon's AuthCheck.
    code=$(curl -s -o /dev/null -w '%{http_code}' \
        -A "$UA_BROWSER" \
        -H 'X-Original-IP: 203.0.113.222' \
        -H 'X-Real-IP: 203.0.113.222' \
        -H 'X-Original-URI: /wp-login.php' \
        "${front}/unmask/api/check")
    assert_eq 404 "$code" "${front}: public /unmask/api/check blocked (404)" || fails=$((fails+1))

    # The block is scoped: the rest of the /unmask/ passthrough still works.
    code=$(curl -s -o /dev/null -w '%{http_code}' "${front}/unmask/healthz")
    assert_eq 200 "$code" "${front}: /unmask/healthz still proxied (200)" || fails=$((fails+1))
done

if [ "$fails" -eq 0 ]; then
    log_pass "/unmask/api/check is not publicly reachable on either forward-auth front"
    exit 0
fi
log_fail "/unmask/api/check public-exposure block failed in $fails check(s)"
exit 1
