#!/bin/bash
# 19: multi-site phase 1.5 -- per-vhost Branding + ProtectedPaths overrides.
#
# Self-contained scenario: brings up its own docker compose (nginx + admin,
# 2 vhosts on :8444) so it doesn't interfere with the main e2e stack on
# :8443.  The real assertions live in scenarios/multi-site-basic/run.sh; this
# wrapper just delegates so the main run.sh's scenarios/[0-9]*.sh discovery
# picks it up alongside the other numbered cases.
#
# Skips cleanly when docker / docker compose is unavailable (= bare-metal
# runs that hit a remote BASE_URL).

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

if ! command -v docker >/dev/null 2>&1; then
    log_skip "19-multi-site-basic needs docker (= the scenario runs its own stack) -- skipped"
    exit 0
fi

exec bash "$DIR/scenarios/multi-site-basic/run.sh"
