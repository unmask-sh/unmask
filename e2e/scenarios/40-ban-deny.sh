#!/bin/bash
# 40: a deny-action BAN serves the branded "blocked" page (native mode).
#
# A rate-limit deny is transient (clears when the client slows down) -- scenario
# 38 covers its "too many requests / retry" page.  A ban is persistent until the
# operator lifts it, so it gets a DISTINCT page: "Access blocked", no retry
# framing, and a separate unmask:ban-deny marker.  This pins the native-mode
# end-to-end path: the $unmask_ban_action="deny" branch in server.inc rewrites to
# /unmask/_ban<uri>, which the admin renders.
#
# Needs deterministic ban state, so it drives the ban file directly in the
# nginx container (the plugin mtime-watches it) and skips cleanly off-stack.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
if ! command -v docker >/dev/null 2>&1 || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q nginx 2>/dev/null)" ]; then
    log_skip "40-ban-deny needs the docker e2e stack (nginx container ban file) — skipped"
    exit 0
fi

# RFC 5737 test IP, distinct from other scenarios so no ban/rate state bleeds.
BAN_IP=203.0.113.40
BAN_FILE_C=/var/lib/unmask/nginx/banned.txt
body_tmp=$(mktemp)

# IP-only ban entry ("<ip>||<source>|<action>"): the native plugin's Pass-3
# lookup matches "<ip>|" and returns action=deny for any JA4 from that IP.
ban_write() {
    docker compose -f "$COMPOSE" exec -T --user root nginx sh -c \
        "mkdir -p /var/lib/unmask/nginx && printf '%s\n' '${BAN_IP}||manual|deny' >> '$BAN_FILE_C'" >/dev/null 2>&1
}
ban_clear() {
    docker compose -f "$COMPOSE" exec -T --user root nginx sh -c \
        "[ -f '$BAN_FILE_C' ] && grep -v '^${BAN_IP}|' '$BAN_FILE_C' > '${BAN_FILE_C}.t' 2>/dev/null && mv '${BAN_FILE_C}.t' '$BAN_FILE_C'" >/dev/null 2>&1 || true
}

# Clean up the test ban + temp file, and preserve assert.sh's exit guard (a bare
# `trap ... EXIT` would shadow _e2e_exit_guard and mask mid-scenario FAILs).
cleanup() {
    rc=$?
    ban_clear
    rm -f "$body_tmp"
    [ "$rc" -eq 0 ] && [ "${_E2E_FAILS:-0}" -gt 0 ] && exit 1
    exit "$rc"
}
trap cleanup EXIT

# The admin flushes the DB -> ban file every 60s and our entry is not in the DB,
# so re-write it each attempt; the plugin re-reads on mtime change.  A handful of
# tries is plenty to land a request inside a window where the entry is present.
code=000
for _ in $(seq 1 12); do
    ban_write
    code=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $BAN_IP" -H "Accept: text/html" \
        -o "$body_tmp" -w '%{http_code}' "${BASE_URL}/")
    [ "$code" = 403 ] && grep -q 'unmask:ban-deny' "$body_tmp" && break
    sleep 0.5
done

assert_eq 403 "$code" "deny-action ban returns 403 on a normal path" || exit 1
assert_in "unmask:ban-deny" "$(cat "$body_tmp")" "ban serves the branded ban-deny page (marker present)"
assert_in "Access blocked" "$(cat "$body_tmp")" "ban page carries the persistent 'blocked' wording"

# It must be the BAN page, not the rate-limit deny page (different semantics).
body="$(cat "$body_tmp")"
if printf '%s' "$body" | grep -q 'unmask:rate-deny'; then
    log_fail "ban page carries the rate-limit deny marker — ban and rate-limit deny are not differentiated"
else
    log_pass "ban page is distinct from the rate-limit deny page (no rate-deny marker)"
fi
if printf '%s' "$body" | grep -qiE 'too many requests'; then
    log_fail "ban page shows the transient 'too many requests' copy — wrong for a persistent ban"
else
    log_pass "ban page does not invite a retry (no 'too many requests' copy)"
fi
