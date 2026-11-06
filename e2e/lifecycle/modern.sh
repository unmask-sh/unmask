#!/bin/bash
# Host-side runner for the package-lifecycle scenarios on current
# distributions: install, upgrade, the module fail-safe and removal, through
# each distribution's own package manager and nginx.
#
#   e2e/lifecycle/modern.sh                 # ubuntu, almalinux, alpine
#   e2e/lifecycle/modern.sh alpine          # one of them
#
# Expects dist/ to hold what e2e/lifecycle/build.sh makes: the module for the
# nginx each of the three ships, and the three packages at two versions (so
# the upgrade has something to upgrade FROM).  `make e2e-lifecycle-modern`
# runs that first.
#
# Each distribution gets a fresh container, with dist/ mounted read-only.
# The containers reach the network for their distribution's nginx.
#
# Exit 0 only when every check of every distribution passes.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
DIST="$REPO/dist"

declare -A IMAGE=(
    [ubuntu]=ubuntu:24.04      # deb, nginx 1.24.0, loader in /etc/nginx/modules-enabled
    [almalinux]=almalinux:9    # rpm, nginx 1.20.1, loader in /usr/share/nginx/modules
    [alpine]=alpine:3.23       # apk, nginx 1.28.3 on musl (3.22 and older build nginx without --with-compat)
)
WANT=("$@")
[ "${#WANT[@]}" -gt 0 ] || WANT=(ubuntu almalinux alpine)

for f in unmask-0.1.0-1.x86_64.rpm unmask_0.1.1-1_amd64.deb unmask_0.1.1-r1_x86_64.apk; do
    [ -f "$DIST/$f" ] || { echo "missing $DIST/$f -- run e2e/lifecycle/build.sh (or \`make e2e-lifecycle-modern\`)"; exit 2; }
done

failed=()
for name in "${WANT[@]}"; do
    image="${IMAGE[$name]:-}"
    [ -n "$image" ] || { echo "unknown distribution '$name' (ubuntu, almalinux, alpine)"; exit 2; }
    echo ">>> package lifecycle on $image ..."
    out=$(docker run --rm \
        -v "$DIST:/work:ro" \
        -v "$REPO/e2e/lifecycle/modern-scenario.sh:/scenario.sh:ro" \
        "$image" sh /scenario.sh 2>&1) || true
    echo "$out"
    echo "---------------------------------------------"
    if echo "$out" | grep -qE '^lifecycle: passed=[0-9]+ failed=0$'; then
        echo "LIFECYCLE $name: OK"
    else
        echo "LIFECYCLE $name: FAILED"
        failed+=("$name")
    fi
done

if [ "${#failed[@]}" -gt 0 ]; then
    echo "LIFECYCLE: FAILED on ${failed[*]}"
    exit 1
fi
echo "LIFECYCLE: OK (${WANT[*]})"
