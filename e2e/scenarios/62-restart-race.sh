#!/bin/bash
# 62: daemon restart race (native mode) -- a deploy restarts the admin
# daemon while visitors keep arriving.  Every request that lands in the
# window must get either the challenge (daemon answered) or the original
# page (fail-open replayed it); never a 5xx.
#
# 35-daemon-down-failopen covers a daemon that is DOWN (connect refused).
# This covers the transition itself: the old process closing its listener
# and its keepalive connections mid-request, the new one not yet listening.
# Motivation: one raw 502 on the production host at the exact second of a
# fleet restart (2026-09-10), not reproduced here -- this pins that the
# rendered config keeps it that way.
#
# Flow:
#   1. baseline (admin up): curl UA is challenged (403).
#   2. hammer GET / (curl UA, rotating XFF so no rate zone fills) for ~8 s
#      while `docker compose restart admin` runs in the middle.
#   3. assert: no 5xx at all; every answer is 403 or 200.
#   4. healthz back to 200; curl UA challenged again.
#
# Needs the docker e2e stack (it restarts the admin container); skips
# cleanly when the suite targets a remote BASE_URL.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
if ! command -v docker >/dev/null 2>&1 || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q admin 2>/dev/null)" ]; then
    log_skip "62-restart-race needs the docker e2e stack (admin container) — skipped"
    exit 0
fi

healthz() {
    curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "${BASE_URL}/unmask/healthz"
}

wait_healthz_eq() {
    local want="$1" tries="$2" i code
    for i in $(seq 1 "$tries"); do
        code=$(healthz)
        [ "$code" = "$want" ] && return 0
        sleep 1
    done
    return 1
}

# Restart failures leave the admin down; bring it back before the verdict.
cleanup() {
    local rc=$?
    if ! wait_healthz_eq 200 3; then
        docker compose -f "$COMPOSE" start admin >/dev/null 2>&1 || true
        wait_healthz_eq 200 30 || { log_fail "cleanup: admin did not come back healthy"; rc=1; }
    fi
    if [ "$rc" -eq 0 ] && [ "${_E2E_FAILS:-0}" -gt 0 ]; then
        printf '%b\n' "  ${RED}FAIL${RESET}  ${_E2E_FAILS} assertion(s) failed earlier in this scenario" >&2
        exit 1
    fi
    exit "$rc"
}
trap cleanup EXIT

# 1. baseline
c0=$(http_get / -A "$UA_CURL" -H "X-Forwarded-For: 203.0.113.9")
assert_eq 403 "$c0" "baseline (admin up): curl UA is challenged on / (403)" || exit 1

# 2. hammer + restart.  ~10 req/s for the whole restart; each request its
#    own address in 203.0.113.0/24 so no rate zone or ban state builds up.
OUT=$(mktemp)
(
    for i in $(seq 1 200); do
        curl -sk -o /dev/null -w '%{http_code}\n' --max-time 6 \
            -A "$UA_CURL" -H "X-Forwarded-For: 203.0.113.$((10 + i % 200))" "${BASE_URL}/" >> "$OUT" 2>&1
        sleep 0.04
    done
) &
HAMMER=$!
sleep 2
docker compose -f "$COMPOSE" restart admin >/dev/null 2>&1
wait "$HAMMER"

# 3. verdict: nothing but the challenge or the replayed page.
total=$(wc -l < "$OUT")
n5xx=$(grep -cE '^5[0-9][0-9]$' "$OUT")
n200=$(grep -c '^200$' "$OUT")
n403=$(grep -c '^403$' "$OUT")
other=$((total - n5xx - n200 - n403))
log "restart window: $total requests -> 403=$n403 200=$n200 5xx=$n5xx other=$other"
assert_eq 0 "$n5xx" "no request in the restart window got a 5xx (fail-open covers the transition)"
assert_eq 0 "$other" "every answer was the challenge (403) or the replayed page (200)"
rm -f "$OUT"

# 4. protection resumes.
wait_healthz_eq 200 30 || log_fail "admin did not come back (healthz $(healthz))"
c1=$(http_get / -A "$UA_CURL" -H "X-Forwarded-For: 203.0.113.8")
assert_eq 403 "$c1" "after the restart: curl UA is challenged again (403)"
