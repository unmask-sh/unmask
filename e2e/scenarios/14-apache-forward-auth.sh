#!/bin/bash
# 14: Apache forward-auth mode — the real shipped snippet on a real httpd.
#
# Unlike scenario 05 (which curls the /api/check endpoint directly), this
# drives a genuine Apache container running snippets/apache-forward-auth.conf
# + apache-unmask.lua.  Every request goes through the mod_lua AccessChecker,
# which does an internal /_unmask/check subrequest to unmask-admin and
# branches on X-Unmask-Action:
#
#   pass      : browser UA → DECLINED → Apache serves its DocumentRoot (200)
#   challenge : curl UA    → 302 redirect to /unmask/challenge/
#   skip      : /unmask/*  → bypassed by the lua, ProxyPass'd to admin (200)
#
# This is what guards the apache-web package: break the lua handler or the
# conf's ProxyPass wiring and this scenario goes red.
#
# block (403) is intentionally not covered here — it needs deterministic ban
# state setup; the endpoint-level verdicts are already covered by scenario 05.
#
# Each case sends a distinct X-Forwarded-For IP (RFC 5737 TEST-NET-3).  The
# e2e Apache trusts XFF via mod_remoteip, so r.useragent_ip — and thus the
# X-Original-IP the snippet forwards — is that fresh IP.  This isolates the
# scenario from honeypot / ban state left on the shared docker IP by earlier
# scenarios, the same way scenarios 05 / 12 / 13 inject X-Original-IP.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

fails=0

# Pre-flight: Apache reachable?  (run.sh only pre-flights the nginx BASE_URL.)
if ! curl -fsS -o /dev/null --max-time 5 "${APACHE_URL}/unmask/healthz"; then
    log_fail "pre-flight: ${APACHE_URL}/unmask/healthz unreachable — is the apache container up?"
    exit 1
fi

# --- pass: an ordinary browser is forwarded to the origin ---
code=$(curl -s -o /dev/null -w '%{http_code}' \
    -A "$UA_BROWSER" -H 'X-Forwarded-For: 203.0.113.10' "${APACHE_URL}/")
assert_eq "200" "$code" "pass: browser UA → 200 (forwarded to origin)" || fails=$((fails+1))
body=$(curl -s -A "$UA_BROWSER" -H 'X-Forwarded-For: 203.0.113.10' "${APACHE_URL}/")
assert_in "unmask e2e apache backend" "$body" "pass: origin DocumentRoot served" || fails=$((fails+1))

# --- challenge: a curl UA is redirected to the challenge page ---
hdr="$(mktemp)"
code=$(curl -s -o /dev/null -D "$hdr" -w '%{http_code}' \
    -A "$UA_CURL" -H 'X-Forwarded-For: 203.0.113.11' "${APACHE_URL}/some/private/path")
loc=$(grep -i '^Location:' "$hdr" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
rm -f "$hdr"
assert_eq "302" "$code" "challenge: curl UA → 302" || fails=$((fails+1))
assert_in "/unmask/challenge/" "$loc" "challenge: redirect to challenge page" || fails=$((fails+1))

# --- skip: /unmask/* is passed through by the lua and proxied to admin ---
code=$(curl -s -o /dev/null -w '%{http_code}' "${APACHE_URL}/unmask/healthz")
assert_eq "200" "$code" "skip: /unmask/healthz proxied to admin → 200" || fails=$((fails+1))

exit "$fails"
