#!/bin/bash
# Build what e2e/lifecycle/modern.sh installs, into dist/:
#
#   1. the module for the nginx each of the three test distributions ships
#      (AlmaLinux 9: 1.20.1, Ubuntu 24.04: 1.24.0, Alpine 3.23: 1.28.3);
#   2. the three packages -- unmask, unmask-plugin-nginx, unmask-web-nginx --
#      as rpm, deb and apk, at two versions, unsigned.
#
# The modules are built in an AlmaLinux 9 container through the Makefile's own
# build-module-multi (so with the options and the check every module build
# gets): its glibc, 2.34, is old enough for all three distributions and for
# Alpine's gcompat, which a module built against the runner's newer one is
# not.  The plugin package then bundles exactly those three (make -o keeps
# package-plugin-nginx-fat from going on to build the other ABIs and
# versions, which the release does and this test has no use for).
#
# Needs docker, go, nfpm (the Makefile's header names the version) and
# envsubst.  Everything it writes is under dist/ and build/.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$REPO"

NGINX_VERSIONS="1.20.1 1.24.0 1.28.3"
V1=0.1.0
V2=0.1.1

echo ">>> modules for nginx $NGINX_VERSIONS (AlmaLinux 9 container) ..."
docker run --rm -v "$REPO:/work" -w /work almalinux:9 sh -c "
    set -e
    dnf -q -y install gcc make pcre-devel pcre2-devel zlib-devel openssl-devel perl-interpreter tar gzip binutils >/dev/null
    make --no-print-directory build-module-multi PLUGIN_NGINX_VERSIONS='$NGINX_VERSIONS' >/tmp/build.log 2>&1 || { tail -40 /tmp/build.log; exit 1; }
    grep -E 'check-so-hardening|saved:|cached:' /tmp/build.log
    # The container is root: hand what it wrote back to the invoking user.
    chown -R $(id -u):$(id -g) /work/dist /work/build
"
for v in $NGINX_VERSIONS; do
    [ -f "dist/multi-modules/$v/ngx_http_unmask_module.so" ] || { echo "no module was built for nginx $v"; exit 1; }
done

mkdir -p build
LOG="$REPO/build/lifecycle-packages.log"
for v in "$V1" "$V2"; do
    echo ">>> packages at v$v (unsigned) ..."
    make --no-print-directory -o build-module-multi-all \
        package-rpm package-deb package-apk package-plugin-nginx-fat package-web-nginx \
        UNMASK_VERSION="$v" NFPM_APK_KEY_FILE= NFPM_RPM_KEY_FILE= >"$LOG" 2>&1 \
        || { tail -40 "$LOG"; exit 1; }
    echo "    $(grep -c 'created package' "$LOG") packages"
done
ls dist/ | grep -E '\.(rpm|deb|apk)$' | sed 's/^/    /'
