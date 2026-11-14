#!/bin/bash
# 74: the module reads the bypass list at run time.
#
# The daemon writes bypass-ip.txt beside the ban file at every render, and the
# module answers $unmask_bypass_ip_rt from it, so a range added or dropped
# there applies without a reload -- the hub's crawler ranges, an operator's
# row.  The docker stack's nginx has no list of its own (the daemon writes
# into its own container), which leaves the ranges rendered into http.inc in
# force: the fall-back this scenario starts and ends with.  It writes the file
# in the nginx container itself, as 40 writes the ban file:
#   1. no list: a client the stack challenges (the curl UA), from an address
#      in no bypass range, is challenged (403)
#   2. a list naming its /28: the same request passes, without a reload
#   3. a list without it: challenged again -- the list's answer wins, so a
#      range it drops stops passing
#   4. no list again: challenged (the rendered ranges do not hold it), from a
#      second address, so the first one's rate budget is not in the way
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
if ! command -v docker >/dev/null 2>&1 || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q nginx 2>/dev/null)" ]; then
    log_skip "74-bypass-runtime-list needs the docker e2e stack (a file in the nginx container) — skipped"
    exit 0
fi

# RFC 5737, apart from the addresses other scenarios use.  A challenged
# request counts against its address's rate budget, so the last step has an
# address of its own.
IP=203.0.113.181
IP_LAST=203.0.113.190
LIST_C=/var/lib/unmask/nginx/bypass-ip.txt

# Written whole and renamed into place, as the daemon does.
list_write() {
    docker compose -f "$COMPOSE" exec -T --user root nginx sh -c \
        "mkdir -p /var/lib/unmask/nginx && printf '%s\n' '# e2e 74' '$1' > '$LIST_C.t' && chmod 644 '$LIST_C.t' && mv -f '$LIST_C.t' '$LIST_C'" >/dev/null 2>&1
}
list_clear() {
    docker compose -f "$COMPOSE" exec -T --user root nginx rm -f "$LIST_C" >/dev/null 2>&1 || true
}
# Leave no list behind, and keep assert.sh's exit guard (a bare `trap ... EXIT`
# would shadow it and hide a FAIL).
cleanup() {
    rc=$?
    list_clear
    [ "$rc" -eq 0 ] && [ "${_E2E_FAILS:-0}" -gt 0 ] && exit 1
    exit "$rc"
}
trap cleanup EXIT

code_of() {
    curl -sk -A "$UA_CURL" -H "X-Forwarded-For: $1" \
        -o /dev/null -w '%{http_code}' "${BASE_URL}/"
}
# A worker looks at the file at most once a second: poll a few seconds,
# stopping at the first answer that is the expected one.
expect_code() {
    local want="$1" ip="$2" got=000
    for _ in $(seq 1 8); do
        got=$(code_of "$ip")
        [ "$got" = "$want" ] && break
        sleep 0.5
    done
    assert_eq "$want" "$got" "$3"
}

list_clear
expect_code 403 "$IP" "no run-time list: an address in no bypass range is challenged"
list_write "203.0.113.176/28"
expect_code 200 "$IP" "the list names its /28: the request passes, without a reload"
list_write "198.51.100.0/24"
expect_code 403 "$IP" "the list no longer names it: challenged again (the list's answer wins)"
list_clear
expect_code 403 "$IP_LAST" "no list again: the rendered ranges apply, and they do not hold it"
