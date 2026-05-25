#!/bin/bash
# 20: multi-site phase 2.2 -- per-vhost ProtectedPaths overrides via the
# native ngx_http_unmask_module path (= rendered $protected_mode_host_<host>
# + $protected_mode_disable map blocks in /etc/unmask/native/http.inc).
#
# Companion to 19-multi-site-basic (= auth_request path).  Phase 2.2's
# deliverable is "Resolve(site) takes effect on both modes", so the two
# scenarios run side-by-side; if either one regresses the per-site
# Override wire is broken on that mode.
#
# Self-contained docker compose stack on :8445 (= multi-site-basic uses
# :8444; main e2e uses :8443; no collisions).

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

if ! command -v docker >/dev/null 2>&1; then
    log_skip "20-multi-site-native needs docker (= the scenario runs its own stack) -- skipped"
    exit 0
fi

exec bash "$DIR/scenarios/multi-site-native/run.sh"
