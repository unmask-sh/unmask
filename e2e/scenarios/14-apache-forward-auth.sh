#!/bin/bash
# 14: Apache forward-auth mode — the real shipped snippet on a real httpd.
#
# Unlike scenario 05 (which curls the /api/check endpoint directly), this
# drives a genuine Apache container running snippets/apache-forward-auth.conf
# + apache-unmask.lua.  Every request goes through the mod_lua AccessChecker,
# which does an internal /_unmask/check subrequest to unmask and
# branches on X-Unmask-Action:
#
#   pass      : browser UA → DECLINED → Apache serves its DocumentRoot (200)
#   challenge : curl UA    → 302 redirect to /unmask/challenge/
#   block     : geo-denied → 302 redirect to /unmask/_ban (branded "blocked" page)
#   skip      : /unmask/*  → bypassed by the lua, ProxyPass'd to admin (200)
#
# This is what guards the apache-web package: break the lua handler or the
# conf's ProxyPass wiring and this scenario goes red.
#
# The block case uses a geo-denied IP (CN rule = deny via UNMASK_TEST_GEO_OVERRIDE)
# so it needs no persistent ban state, yet exercises the same lua block path a
# ban deny takes.
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

# --- block: a geo-denied visitor is redirected to the branded "blocked" page ---
# 192.0.2.82 -> CN via UNMASK_TEST_GEO_OVERRIDE; the CN geo rule = deny, so the
# lua redirects to /unmask/_ban (the same branded page native mode serves for a
# deny ban -- distinct from the challenge's /unmask/challenge/).
hdr="$(mktemp)"
code=$(curl -s -o /dev/null -D "$hdr" -w '%{http_code}' \
    -A "$UA_BROWSER" -H 'X-Forwarded-For: 192.0.2.82' "${APACHE_URL}/some/path")
loc=$(grep -i '^Location:' "$hdr" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
rm -f "$hdr"
assert_eq "302" "$code" "block: geo-denied visitor → 302" || fails=$((fails+1))
assert_in "/unmask/_ban/" "$loc" "block: redirect to the branded blocked page (not the challenge)" || fails=$((fails+1))

# follow the redirect: /unmask/_ban/ (ProxyPass'd to admin) serves the branded
# "blocked" page with a 403 + the ban-deny marker.
bbody="$(mktemp)"
bcode=$(curl -sL -o "$bbody" -w '%{http_code}' \
    -A "$UA_BROWSER" -H 'X-Forwarded-For: 192.0.2.82' "${APACHE_URL}/some/path")
assert_eq "403" "$bcode" "block: following the redirect lands on a 403 blocked page" || fails=$((fails+1))
assert_in "unmask:ban-deny" "$(cat "$bbody")" "block: branded ban-deny page served via Apache ProxyPass" || fails=$((fails+1))
assert_in "Access blocked" "$(cat "$bbody")" "block: persistent 'blocked' wording (not 'too many requests')" || fails=$((fails+1))
rm -f "$bbody"

# --- skip: /unmask/* is passed through by the lua and proxied to admin ---
code=$(curl -s -o /dev/null -w '%{http_code}' "${APACHE_URL}/unmask/healthz")
assert_eq "200" "$code" "skip: /unmask/healthz proxied to admin → 200" || fails=$((fails+1))

exit "$fails"
