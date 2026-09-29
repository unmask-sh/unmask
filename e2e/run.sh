#!/bin/bash
# Run all scenarios.  Exit code = number of failed scenarios.
#
# usage:
#   ./run.sh                              # default BASE_URL = https://localhost:8443
#   BASE_URL=https://example.com ./run.sh # arbitrary host
#   ./run.sh 02 04                        # filter by scenario number

set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

# pre-flight: can we reach BASE_URL?
if ! curl -sk -o /dev/null -w '%{http_code}' --max-time 5 "${BASE_URL}/unmask/healthz" \
        | grep -q '^200$'; then
    log_fail "pre-flight: ${BASE_URL}/unmask/healthz did not return 200"
    log "→ verify admin and nginx are up, and that BASE_URL is correct"
    exit 99
fi
log "pre-flight: ${BASE_URL}/unmask/healthz OK"

# pre-flight: if the honeypot ban file is still banning 127.0.0.1 from a prior
# test, scenario 03 (= curl pass-through) and 04 (= _bv pass-through) will
# fail.  Empty the ban file at e2e start (= demo / dev assumption; production
# should use a different path).
#
# Override the path via UNMASK_BAN_FILE.  If BASE_URL is not the demo
# (= 127.0.0.1), do nothing (= safety so we don't wipe a production ban list).
BAN_FILE="${UNMASK_BAN_FILE:-./demo/conf/honeypot-banned.txt}"
if [ -f "$BAN_FILE" ] && echo "${BASE_URL}" | grep -qE '127\.0\.0\.1|localhost'; then
    rm -f "$BAN_FILE"
    log "pre-flight: cleared $BAN_FILE for clean test"
fi
echo

# If args are passed, treat them as a scenario filter (= '02' selects 02-*.sh only).
filter="${*:-}"

# Scenarios that can't run when admin listens on a unix socket -- skipped (not
# failed) in socket mode (UNMASK_E2E_SOCKET=1):
#   - 05/10/12/13/16/43/51/52-asn-deny talk to the admin TCP port directly
#     (an exact source IP, a header, /api/check with the original address)
#   - 14/20/22/29 exercise the Apache forward-auth path, and Apache talks plain
#     TCP to admin (no shared socket volume), so it is parked in socket mode.
#   - 42/44/45/58/59 go through fa-nginx, which cannot reach a socket in
#     another container and is parked in socket mode too.
# The list had not kept up with the scenarios after 29, and fa-nginx kept the
# socket stack from coming up at all.  An entry is a number, or a whole name
# where two scenarios share the number.
SOCKET_INCOMPAT="05 10 12 13 14 16 20 22 29 42 43 44 45 51 52-asn-deny 58 59"

passed=0
failed=0
skipped=0
failed_names=()
skipped_names=()

# Clear the ban file + DB ban table before each scenario.
# Scenario 02 bans 127.0.0.1, so 03/04 would flake on the leftover ban.
# Override via UNMASK_BAN_FILE / UNMASK_DB_PATH env vars.
clear_ban_state() {
    if [ -f "$BAN_FILE" ] && echo "${BASE_URL}" | grep -qE '127\.0\.0\.1|localhost'; then
        rm -f "$BAN_FILE"
    fi
    # Also clear the unmask_ban DB table (= sqlite; mariadb would use a different path).
    DB_PATH="${UNMASK_DB_PATH:-./demo/unmask.sqlite}"
    if [ -f "$DB_PATH" ] && command -v sqlite3 >/dev/null 2>&1 && \
       echo "${BASE_URL}" | grep -qE '127\.0\.0\.1|localhost'; then
        sqlite3 "$DB_PATH" "DELETE FROM unmask_ban;" 2>/dev/null || true
    fi
    # Brief wait so the nginx-module mtime watch picks up the change (~100 ms).
    sleep 0.2
}

# Measurements scenarios want surfaced after the run (see log_note).
E2E_NOTES=$(mktemp); export E2E_NOTES
SCENARIO_OUT=$(mktemp)
trap 'rm -f "$E2E_NOTES" "$SCENARIO_OUT"' EXIT

# Is this run against the docker stack of this checkout?  Several scenarios
# need it (they restart the daemon, read its files) and skip themselves when
# they cannot find it, which is right against a remote BASE_URL.  Against the
# stack itself such a skip is a defect: when the compose service was renamed,
# seven scenarios went on looking for the old name, skipped, and the suite
# stayed green without them for two releases.  So with the stack up, a
# scenario that says it could not find the stack has failed.
# Only when BASE_URL is that stack: against another host, a stack that happens
# to be up locally says nothing about the run.
STACK_UP=""
case "$BASE_URL" in
    *://localhost:*|*://localhost/*|*://localhost|*://127.0.0.1:*|*://127.0.0.1/*|*://127.0.0.1)
        if command -v docker >/dev/null 2>&1 && [ -n "$(docker compose -f "$DIR/docker/docker-compose.yml" ps -q nginx 2>/dev/null)" ]; then
            STACK_UP=1
        fi
        ;;
esac
NO_STACK_RE='needs the docker e2e stack|compose not reachable|container not running locally|needs python3 with sqlite3'

# stack_report <since>: what the containers did while a scenario that failed
# was running.  Printed here because nothing later can: the target that runs
# this suite takes the stack down on its way out, before the CI job's own
# "dump the logs" step gets to look, and a scenario that restarts the daemon
# and does not get it back says only that -- not whether the daemon was slow,
# refused its config, or never started.
stack_report() {
    [ -n "$STACK_UP" ] || return 0
    local c="$DIR/docker/docker-compose.yml" svc
    echo "  ---- the stack while this scenario ran (since $1) ----"
    docker compose -f "$c" ps -a --format '{{.Service}}: {{.State}} ({{.Status}})' 2>&1 | sed 's/^/  /'
    for svc in unmask nginx; do
        echo "  ---- $svc ----"
        docker compose -f "$c" logs --no-color --no-log-prefix --timestamps --since "$1" "$svc" 2>&1 \
            | grep -vE '"?(GET|POST|HEAD) [^ ]+ ?(HTTP/[0-9.]+"?)? [0-9]{3} ' \
            | grep -vE 'field [a-z0-9_]+ not found in type|unrecognized or misplaced keys' \
            | tail -n 60 | cut -c1-260 | sed 's/^/  /'
    done
    echo "  ----"
}

for s in "$DIR"/scenarios/[0-9]*.sh; do
    name=$(basename "$s" .sh)
    num="${name%%-*}"
    if [ -n "$filter" ] && ! echo " $filter " | grep -q " $num "; then
        continue
    fi
    if [ "${UNMASK_E2E_SOCKET:-}" = "1" ] && echo " $SOCKET_INCOMPAT " | grep -qE " ($num|$name) "; then
        echo "[$name] SKIP (not applicable in socket mode)"
        echo
        skipped=$((skipped + 1))
        skipped_names+=("$name")
        continue
    fi
    echo "[$name]"
    # Clear ban state before each scenario (= flake prevention).
    clear_ban_state
    started=$(date -u +%Y-%m-%dT%H:%M:%SZ)
    bash "$s" 2>&1 | tee "$SCENARIO_OUT"
    rc=${PIPESTATUS[0]}
    if [ "$rc" -eq 0 ] && [ -n "$STACK_UP" ] && grep -qE "$NO_STACK_RE" "$SCENARIO_OUT"; then
        echo "  FAIL  the docker stack is up and this scenario skipped for want of it -- it is looking for a service or a path that is not there"
        rc=1
    fi
    if [ "$rc" -eq 0 ]; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
        failed_names+=("$name")
        stack_report "$started"
    fi
    echo
done

# After every scenario: nginx must not have logged an uninitialized-variable
# warning.  server.inc initialises the fail-open variables in the server
# rewrite phase; a directive that ends that phase early (an exemption
# `break`, a `return`) placed before them leaves a request reading them
# uninitialized, and nginx says so once per request -- which is what the
# gateway's health checks did for a week while every functional test passed.
# Docker stack only (the logs are the containers').
if command -v docker >/dev/null 2>&1 && [ -n "$(docker compose -f "$DIR/docker/docker-compose.yml" ps -q nginx 2>/dev/null)" ]; then
    echo "[nginx-error-log]"
    warn=$(docker compose -f "$DIR/docker/docker-compose.yml" logs --no-color nginx 2>/dev/null | grep -c 'using uninitialized' || true)
    if [ "${warn:-0}" = 0 ]; then
        echo "  PASS  nginx logged no 'using uninitialized' variable warning across the suite"
        passed=$((passed + 1))
    else
        echo "  FAIL  nginx logged $warn 'using uninitialized' variable warning(s) -- a server.inc directive runs before the variable scaffolding:"
        docker compose -f "$DIR/docker/docker-compose.yml" logs --no-color nginx 2>/dev/null | grep 'using uninitialized' | head -3 | sed 's/^/        /'
        failed=$((failed + 1))
        failed_names+=("nginx-error-log")
    fi
    echo
fi

echo "----------------------------------------"
if [ -s "$E2E_NOTES" ]; then
    echo "  measured:"
    sed 's/^/    /' "$E2E_NOTES"
    echo "----------------------------------------"
fi
echo "  total: passed=$passed  failed=$failed  skipped=$skipped"
if [ "$failed" -gt 0 ]; then
    echo "  failed: ${failed_names[*]}"
fi
if [ "$skipped" -gt 0 ]; then
    echo "  skipped: ${skipped_names[*]}"
fi

exit "$failed"
