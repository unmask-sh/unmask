#!/bin/bash
# 61: the HTTP->HTTPS redirect, its load-balancer health-check exemption, the
# fail-open scaffolding that exemption must not skip, and the ban gate the
# exemption must not skip either.
#
# server.inc, with nginx.https_redirect on, answers plaintext HTTP with a 301
# -- except for ACME and load-balancer health checks, which are not
# redirected and fall through to whatever serves the path.  Until 0.1.54 each
# exemption was a rewrite-phase `break`, which ends the server rewrite phase:
# everything server.inc did after it was skipped for that request.  The
# fail-open variables used to sit there, and every health check that reached
# a protected location then read them uninitialized (an nginx [warn] per
# probe on the gateway, for a week, while every functional test passed); the
# ban and the hard deny still sit there, so a banned client that named a
# health checker's user-agent walked past both to the ordinary challenge.
# The exemption is a flag now.  This scenario sends the kinds of request over
# the vhost's plain :8480 listener, reads nginx's log, and then bans an
# address and sends the health-check user-agent from it.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
if ! command -v docker >/dev/null 2>&1 || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q nginx 2>/dev/null)" ]; then
    log_skip "61-http-redirect-exempt needs the docker e2e stack (plain :8480 listener) — skipped"
    exit 0
fi
PLAIN="${E2E_PLAIN_URL:-http://localhost:8480}"
BROWSER="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0 Safari/537.36"

# (a) a browser over plaintext is sent to https, same host and path
code=$(curl -s -o /dev/null -w '%{http_code}' -A "$BROWSER" "$PLAIN/some/page?x=1")
loc=$(curl -s -o /dev/null -w '%{redirect_url}' -A "$BROWSER" "$PLAIN/some/page?x=1")
if [ "$code" != 301 ] || ! printf '%s' "$loc" | grep -q '^https://localhost/some/page?x=1$'; then
    log_fail "browser over plain http: want 301 to https://localhost/some/page?x=1, got $code -> $loc"
    exit 1
fi
log_pass "browser over plain http is redirected to https (301 -> $loc)"

# (b) a load-balancer health check is exempt: not redirected, falls through
#     to the protected location (here / is protected, so it meets the gate
#     rather than the backend -- what matters is that it is not a 301)
code=$(curl -s -o /dev/null -w '%{http_code}' -A "GoogleHC/1.0" "$PLAIN/")
if [ "$code" = 301 ] || [ "$code" = 302 ]; then
    log_fail "GoogleHC over plain http was redirected ($code); the health-check exemption is not working"
    exit 1
fi
log_pass "GoogleHC over plain http is not redirected (= $code)"

# (c) ...and nginx did not read the fail-open variables uninitialized for it
warn=$(docker compose -f "$COMPOSE" logs --no-color nginx 2>/dev/null | grep -c 'using uninitialized' || true)
if [ "${warn:-0}" != 0 ]; then
    log_fail "nginx logged $warn 'using uninitialized' warning(s): a server.inc directive runs before the fail-open scaffolding"
    docker compose -f "$COMPOSE" logs --no-color nginx 2>/dev/null | grep 'using uninitialized' | head -3
    exit 1
fi
log_pass "no uninitialized-variable warning in nginx's log after the exempt request"

# (d) ...and the exemption withholds only the redirect: a banned address that
#     names the health checker's user-agent still meets the ban.  Until 0.1.54
#     the exemption's `break` skipped the ban and deny gates, so this request
#     was answered with the ordinary challenge (or the page itself).
#     Deterministic ban state, as in scenario 40: an IP-only deny row written
#     into the nginx container's ban file (the plugin mtime-watches it); the
#     daemon's 60s flush may overwrite it, so it is re-written per attempt.
BAN_IP=203.0.113.61
BAN_FILE_C=/var/lib/unmask/nginx/banned.txt
body_tmp=$(mktemp)
ban_write() {
    docker compose -f "$COMPOSE" exec -T --user root nginx sh -c \
        "mkdir -p /var/lib/unmask/nginx && printf '%s\n' '${BAN_IP}||manual|deny' >> '$BAN_FILE_C'" >/dev/null 2>&1
}
ban_clear() {
    docker compose -f "$COMPOSE" exec -T --user root nginx sh -c \
        "[ -f '$BAN_FILE_C' ] && grep -v '^${BAN_IP}|' '$BAN_FILE_C' > '${BAN_FILE_C}.t' 2>/dev/null && mv '${BAN_FILE_C}.t' '$BAN_FILE_C'" >/dev/null 2>&1 || true
}
cleanup() {
    rc=$?
    ban_clear
    rm -f "$body_tmp"
    [ "$rc" -eq 0 ] && [ "${_E2E_FAILS:-0}" -gt 0 ] && exit 1
    exit "$rc"
}
trap cleanup EXIT

code=000
for _ in $(seq 1 12); do
    ban_write
    code=$(curl -s -A "GoogleHC/1.0" -H "X-Forwarded-For: $BAN_IP" -H "Accept: text/html" \
        -o "$body_tmp" -w '%{http_code}' "$PLAIN/")
    [ "$code" = 403 ] && grep -q 'unmask:ban-deny' "$body_tmp" && break
    sleep 0.5
done
if [ "$code" = 301 ] || [ "$code" = 302 ]; then
    log_fail "banned GoogleHC over plain http was redirected ($code): the exemption no longer applies to it"
    exit 1
fi
assert_eq 403 "$code" "a banned address naming the health-check user-agent still meets the ban (not the challenge)" || exit 1
assert_in "unmask:ban-deny" "$(cat "$body_tmp")" "the exempt-from-redirect request was answered by the ban page"
