#!/bin/bash
# 49: the ban file's action column survives a daemon restart.
#
# The regression this pins (found on tool1-jp, 2026-07-14): Manager.Start() writes
# the ban file immediately (initial flush), and flush() resolves every row whose
# action column is empty (= "inherit the source default") through EffectiveAction.
# main.go used to register the per-source action resolver ~100 lines AFTER
# Start(), so that first flush ran with no resolver installed and EffectiveAction
# fell back to its safe hard-ban default -- rewriting every inherit-action ban as
# "deny".  Result: on EVERY daemon restart (package upgrade, reboot, config
# reload) a honeypot ban the operator had configured as pow_then_captcha /
# captcha_only silently became a hard 403 with no way through, until some later
# ban add re-flushed the file.  Over-blocking, in production, invisibly.
#
# ban.restart_flush_test.go pins the ban package's contract; this pins the wiring
# order in cmd/unmask/main.go, which no Go test can reach.
#
# Flow:
#   1. trip a honeypot through the Apache forward-auth vhost -> the admin creates
#      a REAL honeypot ban whose action column is empty (the wordpress preset
#      carries no per-rule override).
#   2. read the ban file the daemon wrote: the row must carry the INHERITED action
#      (pow_then_captcha, since honeypot.default_action is unset in admin.yml).
#   3. restart the admin container.
#   4. read the ban file again: the row must STILL carry pow_then_captcha.
#      Before the fix it came back as "deny" here.
#
# Needs the docker e2e stack (it restarts the admin container and reads the file
# from inside it); skips cleanly when the suite targets a remote BASE_URL.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
if ! command -v docker >/dev/null 2>&1 || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q admin 2>/dev/null)" ]; then
    log_skip "49-ban-file-action-restart needs the docker e2e stack (admin container) — skipped"
    exit 0
fi

# RFC 5737 test IP, distinct from every other scenario so no ban state bleeds.
BAN_IP=203.0.113.49
# The shipped default path.  Same string as the plugin's directive, but this is
# the ADMIN container's copy (nginx has its own; scenario 40 hand-writes that
# one), so the two scenarios never race.
BAN_FILE=/var/lib/unmask/nginx/banned.txt
# honeypot.default_action is unset in admin.yml, so an inherit-action honeypot ban
# resolves to the chain default.
WANT_ACTION=pow_then_captcha

healthz() {
    curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "${BASE_URL}/unmask/healthz"
}
wait_healthz_200() {
    local i
    for i in $(seq 1 30); do
        [ "$(healthz)" = 200 ] && return 0
        sleep 1
    done
    return 1
}
ban_line() {
    # The ban file line for our IP, or "" when absent.  Forward-auth honeypot bans
    # carry no JA4, so the key is "<ip>|".
    docker compose -f "$COMPOSE" exec -T --user root admin \
        sh -c "grep '^${BAN_IP}|' '$BAN_FILE' 2>/dev/null | head -1" 2>/dev/null | tr -d '\r'
}
db_drop_ban() {
    docker compose -f "$COMPOSE" exec -T --user root admin \
        sh -c "command -v sqlite3 >/dev/null 2>&1 && sqlite3 /var/lib/unmask/unmask.sqlite \
               \"DELETE FROM unmask_ban WHERE ip='${BAN_IP}';\"" >/dev/null 2>&1 || true
}

# Leave no ban behind, bring the admin back if we stopped it, and preserve
# assert.sh's exit guard (a bare `trap ... EXIT` would shadow _e2e_exit_guard and
# silently swallow mid-scenario FAILs).
ADMIN_STOPPED=0
cleanup() {
    local rc=$?
    if [ "$ADMIN_STOPPED" = "1" ]; then
        docker compose -f "$COMPOSE" start admin >/dev/null 2>&1 || true
        wait_healthz_200 || { log_fail "cleanup: admin did not come back healthy"; rc=1; }
    fi
    db_drop_ban
    if [ "$rc" -eq 0 ] && [ "${_E2E_FAILS:-0}" -gt 0 ]; then
        exit 1
    fi
    exit "$rc"
}
trap cleanup EXIT

# Pre-flight: Apache is the forward-auth surface we trip the honeypot through.
if ! curl -fsS -o /dev/null --max-time 5 "${APACHE_URL}/unmask/healthz"; then
    log_skip "49-ban-file-action-restart needs the apache container (forward-auth honeypot trip) — skipped"
    exit 0
fi
db_drop_ban   # a leftover row from an earlier run would mask a real regression

# 1. Trip the honeypot: the admin's honeypotDecide adds a real ban whose action
#    column is empty, because the wordpress preset carries no per-rule override.
curl -s -o /dev/null --max-time 5 -A "$UA_BROWSER" \
    -H "X-Forwarded-For: $BAN_IP" "${APACHE_URL}/wp-login.php"

# The add flushes the ban file immediately, but the request is async on the
# admin side -- give it a moment to land.
line=""
for _ in $(seq 1 10); do
    line=$(ban_line)
    [ -n "$line" ] && break
    sleep 1
done
if [ -z "$line" ]; then
    log_fail "honeypot trip did not produce a ban file row for $BAN_IP (is honeypot.ban_file_path set in admin.yml?)"
    exit 1
fi

# 2. Before the restart the row carries the inherited action.
assert_in "|honeypot|${WANT_ACTION}" "$line" \
    "fresh honeypot ban resolves to the inherited action (${WANT_ACTION})" || exit 1

# 3. Restart the admin daemon -- this is the initial-flush path that used to
#    rewrite the row.
docker compose -f "$COMPOSE" stop admin >/dev/null 2>&1
ADMIN_STOPPED=1
docker compose -f "$COMPOSE" start admin >/dev/null 2>&1
if ! wait_healthz_200; then
    log_fail "admin did not come back after restart (healthz $(healthz))"
    exit 1
fi
ADMIN_STOPPED=0
log "admin restarted (healthz 200)"

# 4. The regression: the row must NOT have been rewritten as a hard deny.
line=$(ban_line)
if [ -z "$line" ]; then
    log_fail "ban file row for $BAN_IP vanished across the restart"
    exit 1
fi
assert_not_in "|honeypot|deny" "$line" \
    "restart must NOT rewrite an inherit-action honeypot ban as a hard deny (over-block regression)"
assert_in "|honeypot|${WANT_ACTION}" "$line" \
    "ban file still carries the operator's configured action after a restart (${WANT_ACTION})"
