#!/bin/sh
# build-one.sh — build one nginx version's OpenSSL-1.1-linked plugin .so inside
# the AlmaLinux 8 builder container.
#
# Call: build-one.sh <nginx-version>     (ex: build-one.sh 1.24.0)
#
# Input (= the repo bind-mounted at /work):
#   /work/nginx-module/src/ngx_http_unmask_module.c
#   /work/nginx-module/config
#
# Output: /work/dist/multi-modules-openssl11[-<arch>]/<ver>/ngx_http_unmask_module.so
#   The arch suffix is taken from the CONTAINER's own uname -m, so the same
#   image (run natively or under `--platform=linux/arm64` qemu) lands amd64 in
#   multi-modules-openssl11/ and aarch64 in multi-modules-openssl11-arm64/ --
#   matching the Makefile's MULTI_OPENSSL11_DIR path scheme.  This keeps an
#   aarch64 .so from ever being written into the amd64 cache the placer trusts.
set -eu

NGX_VER="${1:-}"
if [ -z "$NGX_VER" ]; then
    echo "usage: build-one.sh <nginx-version>" >&2
    exit 1
fi

WORKDIR=/work
case "$(uname -m)" in
    x86_64)  ARCH_SUFFIX= ;;
    aarch64) ARCH_SUFFIX=-arm64 ;;
    *)       ARCH_SUFFIX=-$(uname -m) ;;
esac
OUT_DIR="$WORKDIR/dist/multi-modules-openssl11${ARCH_SUFFIX}/$NGX_VER"
mkdir -p "$OUT_DIR"

# The tarball is fetched, checked against the sha256 pinned in the repo and
# unpacked by the same script every other module build path uses.
SRC_DIR="/tmp/nginx-${NGX_VER}"
"$WORKDIR/tools/fetch-nginx-src.sh" "$NGX_VER" /tmp

# compat=0 for very old nginx versions that predate --with-compat.
COMPAT=1
case "$NGX_VER" in
    1.10.*|1.11.[0-4]) COMPAT=0 ;;
esac

cd "$SRC_DIR"
# 1.11.5+ : --with-compat alone gives the dlopen ABI contract.
# 1.10.x  : no --with-compat, so enable --with-http_ssl_module explicitly to
#           turn on the SSL struct members (= ngx_connection_t.ssl).
# The options every build path gives the module (nginx-module/hardening.sh);
# this recipe used to pass none.
CC_OPT="$(sh "$WORKDIR/nginx-module/hardening.sh" cc)"
LD_OPT="$(sh "$WORKDIR/nginx-module/hardening.sh" ld)"
if [ "$COMPAT" = "1" ]; then
    ./configure --with-compat --with-cc-opt="$CC_OPT" --with-ld-opt="$LD_OPT" --add-dynamic-module="$WORKDIR/nginx-module" >/dev/null
else
    ./configure --with-http_ssl_module --with-cc-opt="$CC_OPT" --with-ld-opt="$LD_OPT" --add-dynamic-module="$WORKDIR/nginx-module" >/dev/null
fi
make modules

SO="$SRC_DIR/objs/ngx_http_unmask_module.so"
if [ ! -f "$SO" ]; then
    echo "build failed: $SO not found" >&2
    exit 2
fi
# Read the options back out of the .so: one that lost them does not reach
# the cache.
sh "$WORKDIR/tools/check-so-hardening.sh" "$SO"

cp -v "$SO" "$OUT_DIR/ngx_http_unmask_module.so"
# Confirm the link target is libssl.so.1.1 (= the whole point of this builder).
ldd "$OUT_DIR/ngx_http_unmask_module.so" 2>&1 | grep -E "libssl|libcrypto" || true
echo ">>> built: $OUT_DIR/ngx_http_unmask_module.so (nginx $NGX_VER, OpenSSL 1.1, $(uname -m))"
