#!/bin/bash
# 35: daemon-down fail-open (native mode) -- when the unmask daemon is
# unreachable, the site must behave as if unmask was not installed.
#
# Rendered-config contract under test (server.inc / protect.inc):
#   - protect.inc's challenge gate saves $unmask_orig_path/_args before
#     rewriting into /unmask/challenge/.
#   - the /unmask/* proxy locations hook 502/503/504 into
#     @unmask_daemon_down, which replays the saved original URI through the
#     vhost's own locations ($unmask_failopen suppresses the gate on the
#     replay pass, so it cannot loop).
#   - the mark lasts the whole request: a replayed page that nginx answers
#     through another internal redirect (an index file, a try_files URI
#     fallback) is not gated again on that hop.
#   - direct /unmask/* hits have nothing to replay -> 503 + Retry-After.
#   - with protect.inc at SERVER scope (the :8444 vhost) the replay works
#     too: the compose recovery keys on $unmask_co_armed, which the redirect
#     pass into /unmask/ cannot clear (it keyed on $unmask_compose, which
#     that pass sets to 0, and every visitor got the 503).
#   - bans hold on both vhosts: a deny ban answers 403, and a captcha_only
#     ban answers 503 even with a crafted ?_orig=.
#
# Flow:
#   1. baseline (admin up): curl UA is challenged (403), on / and on the
#      internal-redirect locations /fo-dir/ and /fo-app/, and on :8444.
#   2. docker compose stop unmask.
#   3. curl UA GET /            -> 200 + the @echo marker (= original content,
#                                  no PoW / CAPTCHA, not a raw 502).
#   4. curl UA GET /?q=1        -> 200 (query string survives the replay).
#   4b. curl UA GET /fo-dir/    -> 200 + its index file; GET /fo-app/missing
#                                  -> 200 + the try_files fallback.
#   4c. :8444 GET /             -> 200 + its own marker; deny-banned -> 403;
#       captcha_only-banned GET /?_orig=/ -> 503 on both vhosts;
#       :8444 GET /unmask/challenge/?_orig=/ -> 503.
#   5. GET /unmask/admin/       -> 503 with Retry-After (no replay target).
#   6. docker compose start unmask, wait for healthz.
#   7. curl UA GET /            -> 403 again (= protection resumed).
#
# Needs the docker e2e stack (it stops/starts the unmask container); skips
# cleanly when the suite targets a remote BASE_URL.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"
. "$DIR/lib/stack.sh"

COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
if ! command -v docker >/dev/null 2>&1 || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q unmask 2>/dev/null)" ]; then
    log_skip "35-daemon-down-failopen needs the docker e2e stack (unmask container) — skipped"
    exit 0
fi

# Distinct XFF IPs (RFC 5737) so no rate-limit / ban state bleeds in.
IP_BASE=203.0.113.71
IP_QUERY=203.0.113.72
IP_AFTER=203.0.113.73
IP_DIR=203.0.113.76
IP_APP=203.0.113.78
IP_SRV=203.0.113.79

srv_get() {
    # srv_get PATH CURL_ARGS... -- http_get against the server-scope vhost.
    local path="$1"; shift
    curl -sk -o /dev/null -w '%{http_code}' "$@" "${SRV_SCOPE_URL}${path}"
}

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
# A deny-banned address, to prove the ban holds while the daemon is down (a
# bare 403, never the fail-open handler's 503), and a captcha_only-banned one,
# whose challenge rewrite has to keep failing closed (503) with a crafted
# ?_orig= -- the replay target a banned client would try to smuggle through
# the outage.  Both rows go in one write, so the deny row answering 403 also
# says the plugin has the captcha_only one.  The ban file is driven directly,
# as 40-ban-deny does; the plugin re-reads it on mtime change.
BAN_IP=203.0.113.235
BAN2_IP=203.0.113.237
BAN_FILE_C=/var/lib/unmask/nginx/banned.txt
ban_write() {
    docker compose -f "$COMPOSE" exec -T --user root nginx sh -c \
        "mkdir -p /var/lib/unmask/nginx && printf '%s\n' '${BAN_IP}||manual|deny' '${BAN2_IP}||manual|captcha_only' >> '$BAN_FILE_C'" >/dev/null 2>&1
}
ban_clear() {
    docker compose -f "$COMPOSE" exec -T --user root nginx sh -c \
        "[ -f '$BAN_FILE_C' ] && grep -v -e '^${BAN_IP}|' -e '^${BAN2_IP}|' '$BAN_FILE_C' > '${BAN_FILE_C}.t' 2>/dev/null && mv '${BAN_FILE_C}.t' '$BAN_FILE_C'" >/dev/null 2>&1 || true
}
ADMIN_STOPPED=0
cleanup() {
    local rc=$?
    ban_clear
    if [ "$ADMIN_STOPPED" = "1" ]; then
        stack_start "$COMPOSE" || true
        if wait_healthz_eq 200 30; then
            log "cleanup: unmask container restarted (healthz 200)"
        else
            log_fail "cleanup: unmask container did not come back healthy"
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
# 1a. the internal-redirect locations are protected the same way.
c0=$(http_get /fo-dir/ -A "$UA_CURL" -H "X-Forwarded-For: $IP_DIR")
assert_eq 403 "$c0" "baseline (admin up): curl UA is challenged on a directory URL (403)" || exit 1
c0=$(http_get /fo-app/missing -A "$UA_CURL" -H "X-Forwarded-For: $IP_APP")
assert_eq 403 "$c0" "baseline (admin up): curl UA is challenged on a try_files fallback (403)" || exit 1
c0=$(srv_get / -A "$UA_CURL" -H "X-Forwarded-For: $IP_SRV")
assert_eq 403 "$c0" "baseline (admin up): curl UA is challenged on the server-scope vhost (403)" || exit 1

# 1b. a deny ban on BAN_IP, seen by the plugin before the daemon goes down.
bcode=000
for _ in $(seq 1 12); do
    ban_write
    bcode=$(http_get / -A "$UA_CURL" -H "X-Forwarded-For: $BAN_IP")
    [ "$bcode" = 403 ] && break
    sleep 0.5
done
assert_eq 403 "$bcode" "baseline (admin up): the deny-banned address is refused (403)" || exit 1

# 2. stop the unmask daemon.
stack_stop "$COMPOSE"
ADMIN_STOPPED=1
if ! wait_healthz_eq 503 15; then
    log_fail "admin did not go down (healthz still $(healthz))"
    exit 1
fi
log "unmask container stopped (healthz now $(healthz))"

# 3. fail-open: the same not-yet-passed visitor now gets the ORIGINAL page --
#    no PoW / CAPTCHA, no raw 502.  The @echo marker proves the request was
#    served by the vhost's own content location after the replay.
body=$(curl -sk -A "$UA_CURL" -H "X-Forwarded-For: $IP_BASE" "${BASE_URL}/")
code=$(http_get / -A "$UA_CURL" -H "X-Forwarded-For: $IP_BASE")
assert_eq 200 "$code" "daemon down: curl UA gets the original page on / (200, no challenge)"
assert_in "[unmask e2e]" "$body" "daemon down: response body is the real backend content"

# 3b. the ban holds while the daemon is down: a bare 403 from the ban
#     location's own fail-closed hook -- not the fail-open handler's 503,
#     which is what a banned client got until 0.1.44 (the shared proxy
#     template's fail-open error_page was written first and nginx keeps the
#     first one for a code; found by 62-restart-race in the 0.1.44 gate).
code=$(http_get / -A "$UA_CURL" -H "X-Forwarded-For: $BAN_IP")
assert_eq 403 "$code" "daemon down: a deny-banned client still gets 403 (fails closed, not 503)"

# 4. the query string survives the save/replay round-trip.
code=$(http_get "/?q=1&x=y" -A "$UA_CURL" -H "X-Forwarded-For: $IP_QUERY")
assert_eq 200 "$code" "daemon down: query-string request also passes (200)"

# 4b. content nginx answers through a second internal redirect.  The server
#     rewrite phase runs again on that hop; until the mark's default moved
#     out of it (a map in http.inc), the hop cleared the mark, the request
#     was challenged into the dead daemon again, and the second 502 surfaced
#     raw -- error_page does not recurse.
body=$(curl -sk -A "$UA_CURL" -H "X-Forwarded-For: $IP_DIR" "${BASE_URL}/fo-dir/")
code=$(http_get /fo-dir/ -A "$UA_CURL" -H "X-Forwarded-For: $IP_DIR")
assert_eq 200 "$code" "daemon down: a directory URL is served by its index file (200, not a raw 502)"
assert_in "[unmask e2e index]" "$body" "daemon down: the directory URL returns its index file"
body=$(curl -sk -A "$UA_CURL" -H "X-Forwarded-For: $IP_APP" "${BASE_URL}/fo-app/missing")
code=$(http_get /fo-app/missing -A "$UA_CURL" -H "X-Forwarded-For: $IP_APP")
assert_eq 200 "$code" "daemon down: a try_files URI fallback is served (200, not a raw 502)"
assert_in "[unmask e2e fallback]" "$body" "daemon down: the fallback returns its page"

# 4c. protect.inc at SERVER scope.  The module's redirect into /unmask/ runs
#     the server rewrite phase again, and protect.inc with it: its machinery
#     bypass clears $unmask_compose there, so a recovery keyed on that flag
#     had nothing to replay and answered 503 to every visitor not yet passed.
body=$(curl -sk -A "$UA_CURL" -H "X-Forwarded-For: $IP_SRV" "${SRV_SCOPE_URL}/")
code=$(srv_get / -A "$UA_CURL" -H "X-Forwarded-For: $IP_SRV")
assert_eq 200 "$code" "daemon down: the server-scope vhost serves the original page (200, not 503)"
assert_in "[unmask e2e srv-scope]" "$body" "daemon down: the server-scope vhost returns its own content"
code=$(srv_get / -A "$UA_CURL" -H "X-Forwarded-For: $BAN_IP")
assert_eq 403 "$code" "daemon down: a deny-banned client still gets 403 on the server-scope vhost"
#     The recovery's gate: a challenge-type ban rewrites to /unmask/challenge/
#     with the client's own args, so ?_orig= is the client's choice.  It must
#     not become a replay target on either vhost, and neither may a direct
#     hit on the challenge URL.
code=$(srv_get "/?_orig=/" -A "$UA_CURL" -H "X-Forwarded-For: $BAN2_IP")
assert_eq 503 "$code" "daemon down: a captcha_only-banned client with a crafted _orig gets 503 on the server-scope vhost"
code=$(http_get "/?_orig=/" -A "$UA_CURL" -H "X-Forwarded-For: $BAN2_IP")
assert_eq 503 "$code" "daemon down: a captcha_only-banned client with a crafted _orig gets 503 on the location-scope vhost"
code=$(srv_get "/unmask/challenge/?_orig=/" -A "$UA_CURL" -H "X-Forwarded-For: $IP_SRV")
assert_eq 503 "$code" "daemon down: a direct challenge URL with _orig is not replayed on the server-scope vhost (503)"

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
#     are still up (only the unmask container was stopped); skip a front cleanly
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
stack_start "$COMPOSE"
if ! wait_healthz_eq 200 30; then
    log_fail "admin did not come back up (healthz $(healthz))"
    exit 1
fi
ADMIN_STOPPED=0
log "unmask container restarted (healthz 200)"

# 7. protection resumes automatically: the next unpassed visitor is challenged.
c1=$(http_get / -A "$UA_CURL" -H "X-Forwarded-For: $IP_AFTER")
assert_eq 403 "$c1" "admin back up: curl UA is challenged again on / (403)"
