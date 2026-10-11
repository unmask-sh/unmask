#!/bin/bash
# 66: monitor mode on the nginx-module path lets the judged request through,
# and does not loop.
#
# Monitor mode used to live in the daemon: nginx sent a cookie-less visitor to
# the challenge route, the daemon answered with a redirect back to the page and
# no cookie, and nginx -- which judges by the cookie alone -- sent them to the
# challenge route again.  Every first visit to a module install looped for as
# long as the mode was on (seen on this stack: six redirects in a row, never a
# cookie).  The mode is rendered into nginx now: protect.inc's gate, the rate
# zone keys and the deny / ban rewrites read $unmask_observe, the access log
# says ob=1, and the daemon's challenge route is never reached.
#
# Flow: a honeypot path answers 403 (baseline).  Turn the mode on in
# config.yml, restart the daemon (it re-renders http.inc into the shared
# volume), reload nginx.  The same request now reaches the origin -- 200 from
# the echo, with the judgement still in it (fc=1) -- twice (no loop), with no
# observe page and no cookie; the rendered log line carries ob=.  Then back:
# mode off, restart, reload, 403 again.
#
# Needs the docker e2e stack (it restarts the daemon and reloads nginx).
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"
# shellcheck source=../lib/stack.sh
. "$DIR/lib/stack.sh"

COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
if ! command -v docker >/dev/null 2>&1 || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q unmask 2>/dev/null)" ] || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q nginx 2>/dev/null)" ]; then
    log_skip "66-monitor-mode-native needs the docker e2e stack (unmask + nginx containers) — skipped"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    log_skip "66-monitor-mode-native needs python3 to edit the fixture — skipped"
    exit 0
fi

# RFC 5737 addresses of this scenario's own: the honeypot trip records a ban
# for the first, so the closing check uses the second.
IP_ON=198.51.100.166
IP_OFF=198.51.100.167
PROT=/wp-login.php
CFG=/etc/unmask/config.yml
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

healthz() {
    curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "${BASE_URL}/unmask/healthz"
}
wait_healthz_200() {
    local i
    for i in $(seq 1 60); do
        [ "$(healthz)" = 200 ] && return 0
        sleep 1
    done
    return 1
}
# get <path> <client ip>: prints "<status>|<X-Unmask-Mode>|<_bv cookies set>";
# the body is left in $WORK/body.
get() {
    local code mode bv
    code=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $2" -D "$WORK/hdr" -o "$WORK/body" \
        -w '%{http_code}' --max-time 10 "${BASE_URL}$1")
    mode=$(grep -i '^x-unmask-mode:' "$WORK/hdr" | tr -d '\r' | sed 's/^[^:]*: *//')
    bv=$(grep -ic '^set-cookie: _bv=' "$WORK/hdr" || true)
    echo "${code}|${mode}|${bv:-0}"
}
# switch_config <file>: install it as the daemon's config, restart the daemon
# (its start re-renders http.inc), reload nginx so it reads the render.
switch_config() {
    local c
    c=$(docker compose -f "$COMPOSE" ps -q unmask)
    docker cp "$1" "$c:$CFG" >/dev/null 2>&1 || { log "docker cp into the unmask container failed"; return 1; }
    stack_restart "$COMPOSE" || return 1
    wait_healthz_200 || { log "daemon did not come back (healthz $(healthz))"; return 1; }
    docker compose -f "$COMPOSE" exec -T nginx /usr/sbin/nginx -c /etc/nginx/nginx.conf -s reload >/dev/null 2>&1 \
        || { log "nginx -s reload failed"; return 1; }
    sleep 1
}

C=$(docker compose -f "$COMPOSE" ps -q unmask)
docker cp "$C:$CFG" "$WORK/orig.yml" >/dev/null 2>&1 || { log_fail "could not read the daemon's config.yml"; exit 1; }
python3 - "$WORK/orig.yml" "$WORK/observe.yml" <<'PY'
import sys
src = open(sys.argv[1]).read().splitlines(keepends=True)
out, state = [], 0
for line in src:
    out.append(line)
    if state == 0 and line.startswith("challenge:"):
        state = 1
    elif state == 1 and line.startswith("  default:"):
        out.append("    observe_only: true\n")
        state = 2
assert state == 2, "challenge.default block not found in the fixture"
open(sys.argv[2], "w").write("".join(out))
PY

nginx_emerg_count() {
    docker compose -f "$COMPOSE" exec -T nginx sh -c 'grep -c "\[emerg\]" /var/log/nginx/error.log 2>/dev/null || true' | tr -d '\r'
}

fails=0
r=$(get "$PROT" "$IP_ON")
assert_eq 403 "${r%%|*}" "baseline: ${PROT} is challenged (403) while monitor mode is off" || fails=$((fails+1))
emerg_before=$(nginx_emerg_count)

if ! switch_config "$WORK/observe.yml"; then
    log_fail "could not switch the stack to monitor mode"
    exit 1
fi
# A refused reload (nginx keeps the old configuration and logs [emerg]) would
# look like "still challenged" below; name it when it happens.
emerg_after=$(nginx_emerg_count)
assert_eq "$emerg_before" "$emerg_after" "monitor mode: nginx reloaded into the render (no new [emerg] in its error log)" || fails=$((fails+1))

# The render carries the mode: the log line says ob=, the gate reads the
# enforced decision.
inc=$(docker compose -f "$COMPOSE" exec -T nginx sh -c 'grep -c "ob=\$unmask_observe" /etc/unmask/http.inc; grep -c "^set \$unmask_gate \"\${unmask_enforce}" /etc/unmask/protect.inc' 2>/dev/null | tr -d '\r' | tr '\n' ' ')
assert_eq "1 1 " "$inc" "monitor mode: rendered into http.inc (ob= in the log line) and protect.inc (the gate)" || fails=$((fails+1))

r1=$(get "$PROT" "$IP_ON")
body1=$(cat "$WORK/body")
r2=$(get "$PROT" "$IP_ON")
assert_eq 200 "${r1%%|*}" "monitor mode: ${PROT} reaches the origin (200), not a challenge" || fails=$((fails+1))
assert_eq 200 "${r2%%|*}" "monitor mode: the second request reaches the origin too (no loop)" || fails=$((fails+1))
assert_eq "" "$(echo "$r1" | cut -d'|' -f2)" "monitor mode: no observe page from the daemon (no X-Unmask-Mode)" || fails=$((fails+1))
assert_eq 0 "$(echo "$r1" | cut -d'|' -f3)" "monitor mode: no pass cookie handed out" || fails=$((fails+1))
if printf '%s' "$body1" | grep -q '^\[unmask e2e\]' && printf '%s' "$body1" | grep -q '^fc=1$'; then
    log_pass "monitor mode: the body is the origin's, and the judgement still fired in it (fc=1)"
else
    log_fail "monitor mode: body is not the origin's echo with fc=1:\n$body1"
    fails=$((fails+1))
fi

if ! switch_config "$WORK/orig.yml"; then
    log_fail "could not switch the stack back out of monitor mode"
    exit 1
fi
r=$(get "$PROT" "$IP_OFF")
assert_eq 403 "${r%%|*}" "monitor mode off again: ${PROT} is challenged (403)" || fails=$((fails+1))
inc=$(docker compose -f "$COMPOSE" exec -T nginx sh -c 'grep -c "unmask_observe" /etc/unmask/http.inc' 2>/dev/null | tr -d '\r')
assert_eq 0 "$inc" "monitor mode off again: nothing of the mode left in the render" || fails=$((fails+1))

[ "$fails" -eq 0 ]
