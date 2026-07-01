#!/bin/bash
# 37: /unmask/admin/ self-protection — the admin UI runs through protect.inc now
# (the "unmask" protected-path preset = captcha), so a _bv-less visitor hitting
# the admin login is challenged exactly like any other protected path, while the
# machinery paths (challenge serving, healthz) stay on the unprotected catch-all
# so they never loop.  Regression guard for the rate-limit / protected-path
# composition fix: path-scoped rate zones no longer render a shadow location
# that would strip protect.inc -- they apply via a path-conditional key inside
# protect.inc, so /unmask/admin/login keeps the challenge AND its 5 r/m zone.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

fails=0

# protected: a _bv-less visitor (any UA -- the preset is UA-agnostic) hitting
# the admin login is challenged, not handed the login form.
btmp=$(mktemp)
code=$(curl -sk -A "$UA_CURL" -H 'X-Forwarded-For: 203.0.113.50' \
    -o "$btmp" -w '%{http_code}' "${BASE_URL}/unmask/admin/login")
if [ "$code" = "403" ] && grep -qF 'probe=' "$btmp"; then
    log_pass "nginx: _bv-less /unmask/admin/login → challenged (403 + challenge HTML)"
else
    log_fail "nginx: /unmask/admin/login expected challenge (403 + challenge HTML), got code=$code body:\n$(head -c 400 "$btmp")"
    fails=$((fails+1))
fi
rm -f "$btmp"

# control: a machinery path (healthz) stays UNPROTECTED -- never challenged, or
# the challenge page (also served from /unmask/) would loop.
code=$(curl -sk -A "$UA_CURL" -H 'X-Forwarded-For: 203.0.113.51' \
    -o /dev/null -w '%{http_code}' "${BASE_URL}/unmask/healthz")
assert_eq "200" "$code" "nginx: /unmask/healthz → 200 (machinery unprotected, no loop)" || fails=$((fails+1))

exit "$fails"
