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
#   - 05/10/12/13/16 hit the admin TCP port directly (exact source IP / header)
#   - 14/20/22/29 exercise the Apache forward-auth path, and Apache talks plain
#     TCP to admin (no shared socket volume), so it is parked in socket mode.
SOCKET_INCOMPAT="05 10 12 13 14 16 20 22 29"

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

for s in "$DIR"/scenarios/[0-9]*.sh; do
    name=$(basename "$s" .sh)
    num="${name%%-*}"
    if [ -n "$filter" ] && ! echo " $filter " | grep -q " $num "; then
        continue
    fi
    if [ "${UNMASK_E2E_SOCKET:-}" = "1" ] && echo " $SOCKET_INCOMPAT " | grep -q " $num "; then
        echo "[$name] SKIP (admin TCP-direct; not applicable in socket mode)"
        echo
        skipped=$((skipped + 1))
        skipped_names+=("$name")
        continue
    fi
    echo "[$name]"
    # Clear ban state before each scenario (= flake prevention).
    clear_ban_state
    if bash "$s"; then
        passed=$((passed + 1))
    else
        failed=$((failed + 1))
        failed_names+=("$name")
    fi
    echo
done

echo "----------------------------------------"
echo "  total: passed=$passed  failed=$failed  skipped=$skipped"
if [ "$failed" -gt 0 ]; then
    echo "  failed: ${failed_names[*]}"
fi
if [ "$skipped" -gt 0 ]; then
    echo "  skipped: ${skipped_names[*]}"
fi

exit "$failed"
