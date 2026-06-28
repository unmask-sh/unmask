#!/bin/bash
# 43: forward-auth conn-peer gate -- a forwarded X-Client-JA4 is honored ONLY
# when the connecting peer reported in X-Unmask-Conn-Peer is a trusted LB.
#
# This is the daemon-side gate behind the Apache forward-auth JA4 path: Apache
# has no geo/map to gate the header in the web server, so apache-unmask.lua
# reports the real TCP peer in X-Unmask-Conn-Peer (= mod_rewrite
# %{CONN_REMOTE_ADDR}) and resolveForwardedJA4 drops the JA4 when that peer is
# outside the trusted-LB list.  Scenario 14 proves the TRUSTED path (the docker
# peer is in trusted_lb_extra); this isolates the DROP, which 14 can't because
# Apache always sets conn-peer to its own real peer.
#
# Hits /unmask/api/check directly (like 12/13) so the conn-peer header is set
# exactly.  admin.yml: trusted_lb_extra=RFC1918, so the docker connection peer
# passes the proxy-peer gate while a 203.0.113.x (RFC 5737 TEST-NET-3) conn-peer
# is untrusted; ja4_verdicts.extra t13e2e0bot01_xxx_yyy -> action=bot.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

ADMIN_URL=${ADMIN_URL:-http://127.0.0.1:19477}

JA4_BOT="t13e2e0bot01_xxx_yyy"   # admin.yml ja4_verdicts.extra -> action=bot

# check sends /api/check with a forwarded bot JA4 + the given conn-peer and
# prints status|action|reason.  An empty conn-peer omits the header entirely.
check() {
    local connpeer="$1"
    local hdrfile; hdrfile=$(mktemp)
    local code
    local hdrs=(-H "X-Original-URI: /restricted"
                -H "X-Original-IP: 203.0.113.200"
                -H "X-Client-JA4: $JA4_BOT")
    [ -n "$connpeer" ] && hdrs+=(-H "X-Unmask-Conn-Peer: $connpeer")
    code=$(curl -sk -o /dev/null -D "$hdrfile" -w '%{http_code}' \
        -A "$UA_BROWSER" "${hdrs[@]}" "${ADMIN_URL}/unmask/api/check")
    local action reason
    action=$(grep -i '^X-Unmask-Action:' "$hdrfile" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
    reason=$(grep -i '^X-Unmask-Reason:' "$hdrfile" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
    rm -f "$hdrfile"
    echo "$code|$action|$reason"
}

fails=0

# Control: a TRUSTED conn-peer (RFC1918, in trusted_lb_extra) -> JA4 honored ->
# the bot verdict fires -> challenge.  (If this goes red the proxy-peer gate is
# rejecting the docker connection itself, not the conn-peer -- widen
# trusted_lb_extra to cover the bridge.)
res=$(check "10.1.2.3")
log "trusted conn-peer   = $res"
assert_eq 401 "${res%%|*}" "trusted conn-peer: bot JA4 honored -> 401 challenge" || fails=$((fails+1))
[[ "$res" == *"ja4:e2e-fixture-bot"* ]] \
    || { log_fail "trusted conn-peer: reason missing ja4:e2e-fixture-bot, got $res"; fails=$((fails+1)); }

# Drop: a SPOOFED conn-peer from public space (not in trusted_lb_extra) -> the
# daemon drops the forwarded JA4 -> the bot verdict disappears -> pass.
res=$(check "203.0.113.50")
log "untrusted conn-peer = $res"
assert_eq 200 "${res%%|*}" "untrusted conn-peer: forged JA4 dropped -> 200 pass" || fails=$((fails+1))
[[ "$res" == *"|pass|"* ]] \
    || { log_fail "untrusted conn-peer: expected action=pass, got $res"; fails=$((fails+1)); }
if [[ "$res" == *"ja4:"* ]]; then
    log_fail "untrusted conn-peer: JA4 axis should be silent (gate must drop it), got $res"
    fails=$((fails+1))
fi

if [ "$fails" -eq 0 ]; then
    log_pass "conn-peer gate: trusted peer honors the JA4, spoofed public peer drops it"
    exit 0
fi
log_fail "conn-peer gate failed in $fails check(s)"
exit 1
