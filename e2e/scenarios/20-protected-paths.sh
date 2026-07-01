#!/bin/bash
# 16: protected paths — a CAPTCHA gate on a configured path, verified on both
# the native nginx module and the Apache forward-auth path.
#
# unmask is configured (admin.yml protected_paths) with a custom /login/
# protected path in CAPTCHA mode.  Every visitor reaching /login/ — an
# ordinary browser UA included — must be challenged, while ordinary paths
# still pass.  This is the credential-stuffing use case: a transparent
# CAPTCHA gate in front of /login/ with no application change.
#
# Each case sends a distinct X-Forwarded-For IP (RFC 5737 TEST-NET-3); the
# e2e nginx and Apache both trust XFF, so the scenario is isolated from
# honeypot / ban state left on the shared docker IP by earlier scenarios.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

fails=0

# ---- native nginx module ----

# protected path: a browser UA hitting /login/ is challenged.
btmp=$(mktemp)
code=$(curl -sk -A "$UA_BROWSER" -H 'X-Forwarded-For: 203.0.113.30' \
    -o "$btmp" -w '%{http_code}' "${BASE_URL}/login/")
if [ "$code" = "403" ] && grep -qF 'probe=' "$btmp"; then
    log_pass "nginx: browser UA on /login/ → challenged (= 403)"
else
    log_fail "nginx: /login/ expected challenge (403 + challenge HTML), got code=$code body:\n$(cat "$btmp")"
    fails=$((fails+1))
fi
rm -f "$btmp"

# control: the same browser UA on an ordinary path still passes.
btmp=$(mktemp)
code=$(curl -sk -A "$UA_BROWSER" -H 'X-Forwarded-For: 203.0.113.31' \
    -o "$btmp" -w '%{http_code}' "${BASE_URL}/")
if [ "$code" = "200" ] && grep -qF '[unmask e2e]' "$btmp"; then
    log_pass "nginx: browser UA on / → passes (control)"
else
    log_fail "nginx: / expected pass (200 + echo), got code=$code body:\n$(cat "$btmp")"
    fails=$((fails+1))
fi
rm -f "$btmp"

# ---- Apache forward-auth ----

# protected path: a browser UA hitting /login/ is redirected to the challenge.
hdr=$(mktemp)
code=$(curl -s -A "$UA_BROWSER" -H 'X-Forwarded-For: 203.0.113.32' \
    -o /dev/null -D "$hdr" -w '%{http_code}' "${APACHE_URL}/login/")
loc=$(grep -i '^Location:' "$hdr" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
rm -f "$hdr"
if [ "$code" = "302" ] && echo "$loc" | grep -qF '/unmask/challenge/'; then
    log_pass "apache: browser UA on /login/ → challenged (= 302)"
else
    log_fail "apache: /login/ expected 302 → /unmask/challenge/, got code=$code loc=$loc"
    fails=$((fails+1))
fi

# control: the same browser UA on an ordinary path still passes.
code=$(curl -s -A "$UA_BROWSER" -H 'X-Forwarded-For: 203.0.113.33' \
    -o /dev/null -w '%{http_code}' "${APACHE_URL}/")
assert_eq "200" "$code" "apache: browser UA on / → passes (control)" || fails=$((fails+1))

exit "$fails"
