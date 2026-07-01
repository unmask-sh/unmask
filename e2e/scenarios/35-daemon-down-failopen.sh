#!/bin/bash
# 35: daemon-down fail-open (native mode) -- when the admin daemon is
# unreachable, the site must behave as if unmask was not installed.
#
# Rendered-config contract under test (server.inc / protect.inc):
#   - protect.inc's challenge gate saves $unmask_orig_path/_args before
#     rewriting into /unmask/challenge/.
#   - the /unmask/* proxy locations hook 502/503/504 into
#     @unmask_daemon_down, which replays the saved original URI through the
#     vhost's own locations ($unmask_failopen suppresses the gate on the
#     replay pass, so it cannot loop).
#   - direct /unmask/* hits have nothing to replay -> 503 + Retry-After.
#
# Flow:
#   1. baseline (admin up): curl UA is challenged (403).
#   2. docker compose stop admin.
#   3. curl UA GET /            -> 200 + the @echo marker (= original content,
#                                  no PoW / CAPTCHA, not a raw 502).
#   4. curl UA GET /?q=1        -> 200 (query string survives the replay).
#   5. GET /unmask/admin/       -> 503 with Retry-After (no replay target).
#   6. docker compose start admin, wait for healthz.
#   7. curl UA GET /            -> 403 again (= protection resumed).
#
# Needs the docker e2e stack (it stops/starts the admin container); skips
# cleanly when the suite targets a remote BASE_URL.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
if ! command -v docker >/dev/null 2>&1 || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q admin 2>/dev/null)" ]; then
    log_skip "35-daemon-down-failopen needs the docker e2e stack (admin container) — skipped"
    exit 0
fi

# Distinct XFF IPs (RFC 5737) so no rate-limit / ban state bleeds in.
IP_BASE=203.0.113.71
IP_QUERY=203.0.113.72
IP_AFTER=203.0.113.73

healthz() {
    curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "${BASE_URL}/unmask/healthz"
}

wait_healthz_eq() {
    # wait_healthz_eq EXPECTED TRIES -- poll until healthz returns EXPECTED.
    local want="$1" tries="$2" i code
    for i in $(seq 1 "$tries"); do
        code=$(healthz)
        [ "$code" = "$want" ] && return 0
        sleep 1
    done
    return 1
}

# Always bring the admin back, then re-apply assert.sh's exit-guard semantics
# (a bare `trap ... EXIT` here would overwrite the guard installed by
# assert.sh, silently swallowing mid-scenario assertion failures).
ADMIN_STOPPED=0
cleanup() {
    local rc=$?
    if [ "$ADMIN_STOPPED" = "1" ]; then
        docker compose -f "$COMPOSE" start admin >/dev/null 2>&1 || true
        if wait_healthz_eq 200 30; then
            log "cleanup: admin container restarted (healthz 200)"
        else
            log_fail "cleanup: admin container did not come back healthy"
            rc=1
        fi
    fi
    if [ "$rc" -eq 0 ] && [ "${_E2E_FAILS:-0}" -gt 0 ]; then
        printf '%b\n' "  ${RED}FAIL${RESET}  ${_E2E_FAILS} assertion(s) failed earlier in this scenario" >&2
        exit 1
    fi
    exit "$rc"
}
trap cleanup EXIT

# 1. baseline: with the daemon up, a curl UA gets the challenge.
c0=$(http_get / -A "$UA_CURL" -H "X-Forwarded-For: $IP_BASE")
assert_eq 403 "$c0" "baseline (admin up): curl UA is challenged on / (403)" || exit 1

# 2. stop the admin daemon.
docker compose -f "$COMPOSE" stop admin >/dev/null 2>&1
ADMIN_STOPPED=1
if ! wait_healthz_eq 503 15; then
    log_fail "admin did not go down (healthz still $(healthz))"
    exit 1
fi
log "admin container stopped (healthz now $(healthz))"

# 3. fail-open: the same not-yet-passed visitor now gets the ORIGINAL page --
#    no PoW / CAPTCHA, no raw 502.  The @echo marker proves the request was
#    served by the vhost's own content location after the replay.
body=$(curl -sk -A "$UA_CURL" -H "X-Forwarded-For: $IP_BASE" "${BASE_URL}/")
code=$(http_get / -A "$UA_CURL" -H "X-Forwarded-For: $IP_BASE")
assert_eq 200 "$code" "daemon down: curl UA gets the original page on / (200, no challenge)"
assert_in "[unmask e2e]" "$body" "daemon down: response body is the real backend content"

# 4. the query string survives the save/replay round-trip.
code=$(http_get "/?q=1&x=y" -A "$UA_CURL" -H "X-Forwarded-For: $IP_QUERY")
assert_eq 200 "$code" "daemon down: query-string request also passes (200)"

# 5. a direct /unmask/* hit has no original URI to replay -> 503 + Retry-After.
hdrs=$(curl -sk -D- -o /dev/null -A "$UA_CURL" -H "X-Forwarded-For: $IP_BASE" "${BASE_URL}/unmask/admin/")
code=$(echo "$hdrs" | head -1 | grep -oE '[0-9]{3}' | head -1)
assert_eq 503 "$code" "daemon down: direct /unmask/admin/ answers 503 (not a raw 502)"
assert_in "Retry-After" "$hdrs" "daemon down: the 503 carries Retry-After"

# 5b. forward-auth fronts must ALSO fail open while the daemon is down -- this is
#     higher-stakes than native because forward-auth calls the daemon on EVERY
#     request, so a broken fail-open is a full-site outage.  fa-nginx: the
#     auth_request /_unmask/check 502 -> @unmask_fail_open (return 204) -> the
#     request proceeds to the backend.  apache: apache-unmask.lua's daemon call
#     fails -> DECLINED -> apache serves its DocumentRoot.  The fronts themselves
#     are still up (only the admin container was stopped); skip a front cleanly
#     if it is not part of this stack (curl -> 000).
fa_code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 \
    -A "$UA_CURL" -H "X-Forwarded-For: 203.0.113.74" "${FA_NGINX_URL}/")
if [ "$fa_code" != "000" ]; then
    fa_body=$(curl -sk --max-time 6 -A "$UA_CURL" -H "X-Forwarded-For: 203.0.113.74" "${FA_NGINX_URL}/")
    assert_eq 200 "$fa_code" "daemon down: forward-auth nginx fails open -> backend (200, not 502/blocked)"
    assert_in "[fa-nginx backend]" "$fa_body" "daemon down: fa-nginx serves the real backend"
else
    log "fa-nginx not reachable -- skipping its fail-open check"
fi

ap_code=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 \
    -A "$UA_CURL" -H "X-Forwarded-For: 203.0.113.75" "${APACHE_URL}/")
if [ "$ap_code" != "000" ]; then
    ap_body=$(curl -sk --max-time 6 -A "$UA_CURL" -H "X-Forwarded-For: 203.0.113.75" "${APACHE_URL}/")
    assert_eq 200 "$ap_code" "daemon down: forward-auth apache fails open -> backend (200, not 502/blocked)"
    assert_in "unmask e2e apache backend" "$ap_body" "daemon down: apache serves the real backend"
else
    log "apache not reachable -- skipping its fail-open check"
fi

# 6. bring the admin back.
docker compose -f "$COMPOSE" start admin >/dev/null 2>&1
if ! wait_healthz_eq 200 30; then
    log_fail "admin did not come back up (healthz $(healthz))"
    exit 1
fi
ADMIN_STOPPED=0
log "admin container restarted (healthz 200)"

# 7. protection resumes automatically: the next unpassed visitor is challenged.
c1=$(http_get / -A "$UA_CURL" -H "X-Forwarded-For: $IP_AFTER")
assert_eq 403 "$c1" "admin back up: curl UA is challenged again on / (403)"
