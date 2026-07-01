#!/bin/bash
# 06: /unmask/healthz never challenges (= admin internal endpoint must always pass).
#
# Any UA, with or without a _bv cookie, must reach 200.  This guards against
# accidental challenge wiring on admin paths (= regression seen when the
# location block was missing `auth_request off;`).

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

fails=0

# browser UA
code=$(http_get /unmask/healthz -A "$UA_BROWSER")
assert_eq 200 "$code" "GET /unmask/healthz (= browser UA) returns 200" || fails=$((fails+1))

# curl UA
code=$(http_get /unmask/healthz -A "$UA_CURL")
assert_eq 200 "$code" "GET /unmask/healthz (= curl UA) returns 200" || fails=$((fails+1))

# Even when the same client is banned via honeypot, healthz must still respond.
# (= 02 may have banned 127.0.0.1; run.sh clears it pre-scenario, but issue an
# extra honeypot hit here so the ban state is present at the moment we probe.)
curl -sk -o /dev/null -A "$UA_BROWSER" "${BASE_URL}/wp-login.php" >/dev/null 2>&1 || true
code=$(http_get /unmask/healthz -A "$UA_BROWSER")
assert_eq 200 "$code" "GET /unmask/healthz (= post-honeypot, banned) returns 200" || fails=$((fails+1))

exit "$fails"
