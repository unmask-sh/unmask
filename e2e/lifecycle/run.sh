#!/bin/bash
# Host-side runner for the unmask package-lifecycle scenarios.
#
# Expects dist/ to already hold BOTH the v0.1.0 and v0.1.1 rpms -- the
# `make e2e-lifecycle` target builds them first (two versions so the upgrade
# scenario has something to upgrade FROM).  Fetches the CentOS 6 initscripts rpm
# host-side (the minimal centos:6 image lacks /etc/rc.d/init.d/functions +
# `service`, and its OpenSSL 1.0 can't TLS to vault), caches it under
# build/lifecycle-cache/, then runs scenario.sh in a fresh centos:6 container.
#
# Exit 0 only when every scenario check passes.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
DIST="$REPO/dist"
CACHE="${UNMASK_LIFECYCLE_CACHE:-$REPO/build/lifecycle-cache}"
V1=0.1.0
V2=0.1.1

for v in "$V1" "$V2"; do
    for p in unmask unmask-plugin-nginx unmask-web-nginx; do
        f="$DIST/$p-$v-1.x86_64.rpm"
        [ -f "$f" ] || { echo "missing $f -- run \`make e2e-lifecycle\` (it builds v$V1 + v$V2)"; exit 2; }
    done
done

mkdir -p "$CACHE"
INITSCRIPTS="$CACHE/initscripts.rpm"
if [ ! -f "$INITSCRIPTS" ]; then
    echo ">>> fetching CentOS 6 initscripts (vault.centos.org, host-side) ..."
    fn=$(curl -s --max-time 30 https://vault.centos.org/6.10/os/x86_64/Packages/ \
         | grep -oE 'initscripts-[0-9][^"]*\.x86_64\.rpm' | head -1)
    [ -n "$fn" ] || { echo "could not locate initscripts on vault.centos.org"; exit 2; }
    curl -fsS --max-time 120 -o "$INITSCRIPTS" "https://vault.centos.org/6.10/os/x86_64/Packages/$fn"
    echo "    cached $fn"
fi

echo ">>> running package-lifecycle scenarios in centos:6 ..."
out=$(docker run --rm \
    -v "$DIST:/work:ro" \
    -v "$CACHE:/work-pkgs:ro" \
    -v "$REPO/e2e/lifecycle/scenario.sh:/scenario.sh:ro" \
    centos:6 sh /scenario.sh 2>&1) || true
echo "$out"
echo "---------------------------------------------"
if echo "$out" | grep -qE '^lifecycle: passed=[0-9]+ failed=0$'; then
    echo "LIFECYCLE: OK"
    exit 0
fi
echo "LIFECYCLE: FAILED"
exit 1
