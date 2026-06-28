#!/bin/bash
# 42: forward-auth NGINX mode -- the JA4 gate (forward-auth-lbtrust.conf) adopts
# a client JA4 forwarded by a trusted LB and feeds it to the daemon's verdict.
# The nginx counterpart to scenario 14 (apache forward-auth) and 12 (direct to
# the daemon): it proves an LB-forwarded X-Client-JA4 is captured END-TO-END
# through a STOCK nginx (no plugin) -> auth_request /_unmask/check -> daemon.
#
# Setup (admin.yml): trusted_lb_extra=[0.0.0.0/0] so the rendered gate adopts the
# test client's forwarded JA4 (the gate keys on $realip_remote_addr = the docker
# peer); ja4_verdicts.extra has t13e2e0bot01_xxx_yyy -> action=bot; the global
# no-match fallback is "pass".  So the ONLY thing that flips pass->challenge is
# the JA4 -- the difference proves the gate captured + forwarded it.
#
# fa-nginx serves "[fa-nginx backend]" on pass; a bot verdict makes auth_request
# 401 -> @unmask_to_challenge -> the "Security check" challenge page.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

fails=0

# Pre-flight: fa-nginx reachable?  (run.sh only pre-flights the nginx BASE_URL.)
if ! curl -fsS -o /dev/null --max-time 5 "${FA_NGINX_URL}/unmask/healthz"; then
    log_fail "pre-flight: ${FA_NGINX_URL}/unmask/healthz unreachable -- is the fa-nginx container up?"
    exit 1
fi

JA4_BOT="t13e2e0bot01_xxx_yyy"   # admin.yml ja4_verdicts.extra -> action=bot
JA4_OK="t13ok000000000_xxx_yyy"  # not in any rule -> verdict ok
# A fresh client IP (via XFF; fa-nginx trusts it) isolates ban / honeypot state
# left on the shared docker IP by earlier scenarios.
XFF='X-Forwarded-For: 203.0.113.142'

# 1) baseline: regular UA, NO forwarded JA4 -> no trigger -> passes to backend.
body=$(curl -s -A "$UA_BROWSER" -H "$XFF" "${FA_NGINX_URL}/")
assert_in "[fa-nginx backend]" "$body" \
    "forward-auth nginx: no JA4 -> request passes to the backend" || fails=$((fails+1))

# 2) benign forwarded JA4 -> the gate adopts it, but the verdict is ok -> passes.
body=$(curl -s -A "$UA_BROWSER" -H "$XFF" -H "X-Client-JA4: $JA4_OK" "${FA_NGINX_URL}/")
assert_in "[fa-nginx backend]" "$body" \
    "forward-auth nginx: benign LB JA4 adopted, verdict ok -> passes" || fails=$((fails+1))

# 3) bot forwarded JA4 from the trusted-LB peer -> the gate adopts it -> daemon
#    verdict=bot -> challenged (the challenge page replaces the backend body).
body=$(curl -s -A "$UA_BROWSER" -H "$XFF" -H "X-Client-JA4: $JA4_BOT" "${FA_NGINX_URL}/")
if printf '%s' "$body" | grep -qF "[fa-nginx backend]"; then
    log_fail "forward-auth nginx: bot LB JA4 reached the backend (gate/verdict did not fire)"
    fails=$((fails+1))
elif printf '%s' "$body" | grep -qF "Security check"; then
    log_pass "forward-auth nginx: bot LB JA4 captured via the gate -> challenged"
else
    log_fail "forward-auth nginx: bot LB JA4 neither passed nor challenged; body:\n$body"
    fails=$((fails+1))
fi

exit "$fails"
