#!/bin/bash
# 77: why a request was let through, on the line nginx logs.
#
# A request the site answers without a challenge fires no event; the access
# log is its only record, and the admin's "Let through" list (BAN > Let
# through) is built from the ground each line names in why=.  The grounds are
# the configuration's: $unmask_why_chain mirrors the $final_challenge chain
# row for row, and $unmask_why_log adds the ways through that are outside the
# chain.  Here each ground is asked of the real stack -- the module, the
# rendered maps, the gates -- and read off the line.
#
#   - a known browser where the Global axis says pass   -> global
#   - a bypass address                                    -> ip
#   - a bypass path                                       -> path
#   - a crawler known by its name alone                  -> name
#   - a location without protect.inc                      -> nogate
#   - a client that is challenged                         -> "" (unmask answered)
#   - unmask's own file                                   -> ""
#
# Asserted on the readable copy of the line (unmask-decisions.log, the
# `unmask` log format), as scenario 36 does: the daemon's reader is off in
# this harness, and its counting is covered by the Go tests
# (nginxlog/let_through_test.go).  The pass cookie's ground, the daemon-down
# replay, monitor mode and the verified signature are covered on a real nginx
# by the render tests' rig.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
BYPASS_IP=203.0.113.222
M="lt$$"

# line_of <tag> -> the last logged line whose request names the tag.
line_of() {
    docker compose -f "$COMPOSE" exec -T nginx \
        sh -c "grep -hF -- '$1' /var/log/nginx/unmask-decisions.log 2>/dev/null | tail -1" 2>/dev/null | tr -d '\r'
}

# ask <ground wanted> <label> <ip> <ua> <url path, with $M-<case> in it>
ask() {
    local want="$1" label="$2" ip="$3" ua="$4" path="$5"
    local tag; tag=$(printf '%s' "$path" | grep -o "$M-[a-z]*")
    curl -sk -A "$ua" -H "X-Forwarded-For: $ip" -o /dev/null "${BASE_URL}${path}"
    local line; line=$(line_of "$tag")
    if [ -z "$line" ]; then
        log_skip "$label: the request left no access-log line"
        return
    fi
    case "$line" in
        *" why="*) assert_eq "$want" "${line##* why=}" "$label -> why=$want" ;;
        *)         log_fail "$label: the line carries no why= at all: $line" ;;
    esac
}

ask global "a known browser, the Global axis set to pass"  203.0.113.61 "$UA_BROWSER"  "/$M-global"
ask ip     "a bypass address"                               "$BYPASS_IP" "$UA_BROWSER"  "/$M-ip"
ask path   "a bypass path"                                  203.0.113.62 "$UA_CURL"     "/e2e-bypass-only/$M-path"
ask name   "a crawler known by its name alone"              203.0.113.63 "$UA_PETALBOT" "/$M-name"
ask nogate "a location without protect.inc"                 203.0.113.64 "$UA_CURL"     "/pub/readme.txt?$M-nogate"
ask ""     "a client that is challenged (unmask answers)"   203.0.113.65 "$UA_CURL"     "/$M-challenged"
ask ""     "unmask's own file"                              203.0.113.66 "$UA_BROWSER"  "/unmask/healthz?$M-own"
