#!/bin/bash
# 73: a JA4 ban holds behind a trusted load balancer.
#
# Behind a load balancer that terminates TLS, a visitor's fingerprint reaches
# nginx in a header the balancer adds (X-Client-JA4 here; settings > Network
# names the trusted ranges and the header), and the daemon logs and bans by
# that forwarded value ($effective_ja4).  Until 0.1.54 the native plugin
# matched the ban file's "<ip>|<ja4>" and "|<ja4>" rows on its own
# handshake's fingerprint -- behind a balancer the balancer's -- so a JA4 ban
# the daemon placed (a honeypot ban's default scope, or a fingerprint-only
# ban) never matched there, with nothing logged.  The render now defines
# $unmask_ban_ja4 on $effective_ja4 and the plugin keys its lookup on it.
#
# The docker stack already plays the balancer: the nginx container trusts the
# docker-private peer (config.yml: trusted_lb_extra = RFC1918) and takes
# X-Client-JA4 from it, so the curl below IS a visitor behind the balancer.
# Rows are written into the nginx container's ban file as in scenario 40 (the
# plugin mtime-watches it; the daemon's 60s flush may overwrite them, so each
# attempt re-writes).  Skips cleanly off-stack.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
if ! command -v docker >/dev/null 2>&1 || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q nginx 2>/dev/null)" ]; then
    log_skip "73-ban-ja4-behind-lb needs the docker e2e stack (nginx container ban file) — skipped"
    exit 0
fi

# RFC 5737 test IP and a fixture fingerprint, both distinct from every other
# scenario so no ban state bleeds.  The fingerprint matches no ja4_verdicts
# pattern of config.yml (those start t13e2e0bot01), so only the ban decides.
BAN_IP=203.0.113.73
OTHER_IP=203.0.113.74
JA4_BANNED="t13e2e0ban01_aaaaaaaaaaaa_bbbbbbbbbbbb"
BAN_FILE_C=/var/lib/unmask/nginx/banned.txt
body_tmp=$(mktemp)

ban_write() { # ban_write <row>
    docker compose -f "$COMPOSE" exec -T --user root nginx sh -c \
        "mkdir -p /var/lib/unmask/nginx && printf '%s\n' '$1' >> '$BAN_FILE_C'" >/dev/null 2>&1
}
ban_clear() {
    docker compose -f "$COMPOSE" exec -T --user root nginx sh -c \
        "[ -f '$BAN_FILE_C' ] && grep -v -e '^${BAN_IP}|' -e '|${JA4_BANNED}|' '$BAN_FILE_C' > '${BAN_FILE_C}.t' 2>/dev/null && mv '${BAN_FILE_C}.t' '$BAN_FILE_C'" >/dev/null 2>&1 || true
}
cleanup() {
    rc=$?
    ban_clear
    rm -f "$body_tmp"
    [ "$rc" -eq 0 ] && [ "${_E2E_FAILS:-0}" -gt 0 ] && exit 1
    exit "$rc"
}
trap cleanup EXIT

# fetch <ip> <ja4|""> -> prints the status; the body goes to $body_tmp.  An
# empty ja4 sends no header: the plugin then sees curl's own handshake.
fetch() {
    local hdrs=(-A "$UA_BROWSER" -H "X-Forwarded-For: $1" -H "Accept: text/html")
    [ -n "$2" ] && hdrs+=(-H "X-Client-JA4: $2")
    curl -sk "${hdrs[@]}" -o "$body_tmp" -w '%{http_code}' "${BASE_URL}/"
}

# banned_with <row> <ip> <ja4>: writes the row and asks until the ban answers
# (or 12 tries pass); prints the last status.
banned_with() {
    local code=000
    for _ in $(seq 1 12); do
        ban_write "$1"
        code=$(fetch "$2" "$3")
        [ "$code" = 403 ] && grep -q 'unmask:ban-deny' "$body_tmp" && break
        sleep 0.5
    done
    echo "$code"
}

# (a) the trust path itself: the forwarded fingerprint is what nginx logs
#     and decides by.  If this is red the stack's LB trust changed, and the
#     rest of the scenario would not be testing the plugin.
ja4=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $BAN_IP" -H "X-Client-JA4: $JA4_BANNED" \
    "${BASE_URL}/__unmask_debug" | grep -E '^ja4=' | head -1 | tr -d '\r')
assert_eq "ja4=$JA4_BANNED" "$ja4" "the forwarded X-Client-JA4 is the effective fingerprint (trusted LB peer)" || exit 1

# (b) a fingerprint-only row ("|<ja4>", the ja4_only scope) bans the visitor
#     whose fingerprint arrived in the balancer's header
code=$(banned_with "|${JA4_BANNED}|manual|deny" "$BAN_IP" "$JA4_BANNED")
assert_eq 403 "$code" "a |ja4 ban matches the fingerprint forwarded by the trusted LB" || exit 1
assert_in "unmask:ban-deny" "$(cat "$body_tmp")" "...and serves the ban page"
ban_clear

# (c) the exact tuple ("<ip>|<ja4>", the honeypot ban's default scope) too
code=$(banned_with "${BAN_IP}|${JA4_BANNED}|honeypot|deny" "$BAN_IP" "$JA4_BANNED")
assert_eq 403 "$code" "an ip|ja4 ban matches the forwarded fingerprint from that address" || exit 1
assert_in "unmask:ban-deny" "$(cat "$body_tmp")" "...and serves the ban page"

# (d) controls, with the tuple row still in place: the same address without
#     the header (curl's own handshake is not the banned fingerprint), and
#     the banned fingerprint from another address, are not banned -- the row
#     is the tuple, not the address and not the fingerprint alone.
ban_write "${BAN_IP}|${JA4_BANNED}|honeypot|deny"
code=$(fetch "$BAN_IP" "")
if [ "$code" = 403 ] && grep -q 'unmask:ban-deny' "$body_tmp"; then
    log_fail "the address without the forwarded fingerprint met the ip|ja4 ban (the plugin keyed on the address alone)"
else
    log_pass "the same address with its own handshake is not banned (= $code)"
fi
code=$(fetch "$OTHER_IP" "$JA4_BANNED")
if [ "$code" = 403 ] && grep -q 'unmask:ban-deny' "$body_tmp"; then
    log_fail "the banned fingerprint from another address met the ip|ja4 ban (the plugin keyed on the fingerprint alone)"
else
    log_pass "the banned fingerprint from another address is not banned by the tuple row (= $code)"
fi
