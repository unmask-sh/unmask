#!/bin/bash
# 61: the HTTP->HTTPS redirect, its load-balancer health-check exemption, and
# the fail-open scaffolding that exemption must not skip.
#
# server.inc, with nginx.https_redirect on, answers plaintext HTTP with a 301
# -- except for ACME and load-balancer health checks, which `break` out of
# the redirect and fall through to whatever serves the path.  A `break` ends
# the server rewrite phase, so everything server.inc sets after it is skipped
# for that request; the fail-open variables used to sit there, and every
# health check that reached a protected location then read them
# uninitialized (an nginx [warn] per probe on the gateway, for a week, while
# every functional test passed).  This scenario sends both kinds of request
# over the vhost's plain :8480 listener and then reads nginx's log.
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
