#!/bin/bash
# 25: a stale packaged challenge.js (an old djb2 build with no pow_seed) must be
# IGNORED -- the daemon must serve the embedded seed-bound copy instead.
#
# This is the production root cause as an end-to-end guard.  A 2026-05-25 djb2
# challenge.js left at /usr/share/unmask/challenge/ across a plugin upgrade
# looped every visitor; loadChallengeJS now skips an override that lacks the
# pow_seed marker.  Writes into the admin container, so it skips against a
# remote BASE_URL (the same guard is also unit-tested).
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

COMPOSE="$DIR/docker/docker-compose.yml"
dc() { docker compose -f "$COMPOSE" exec -T admin sh -c "$1"; }

if ! command -v docker >/dev/null 2>&1 || [ -z "$(docker compose -f "$COMPOSE" ps -q admin 2>/dev/null)" ]; then
    log "SKIP: admin container not running locally (remote BASE_URL?) -- guard is also unit-tested"
    exit 0
fi

OVR=/usr/share/unmask/challenge/challenge.js
BAK=/tmp/challenge.js.e2e-bak

# Stash the real override and drop a stale djb2 build with no pow_seed marker.
dc "cp $OVR $BAK 2>/dev/null; printf 'function djb2(s){var h=5381;return h;} // stale, no seed\n' > $OVR"
restore() { dc "[ -f $BAK ] && mv $BAK $OVR || rm -f $OVR" >/dev/null 2>&1; }
trap restore EXIT

# The guard must skip the seedless override and serve the embedded copy.
js=$(curl -sk -A "$UA_BROWSER" "${BASE_URL}/unmask/static/challenge.js")
assert_in 'pow_seed' "$js" "stale override ignored -> embedded seed-bound challenge.js served" || exit 1
djb2=$(printf '%s' "$js" | grep -ciE 'djb2')
assert_eq 0 "$djb2" "served challenge.js is the embedded build, not the stale djb2 override"
