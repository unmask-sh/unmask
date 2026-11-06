#!/bin/sh
# build-one.sh -- build one nginx version's OpenSSL-1.0-linked plugin .so
# inside the CentOS 7 builder container.
#
# Call: build-one.sh <nginx-version>     (ex: build-one.sh 1.18.0)
#
# Input (= the repo bind-mounted at /work):
#   /work/nginx-module/            the module source and its config
#   /work/tools/fetch-nginx-src.sh the pinned-sha256 download of the nginx source
#
# Output: /work/dist/multi-modules-openssl10/<ver>/ngx_http_unmask_module.so
#   Written through the bind mount, so it lands in the host's dist/.
set -eu

NGX_VER="${1:-}"
if [ -z "$NGX_VER" ]; then
    echo "usage: build-one.sh <nginx-version>" >&2
    exit 1
fi

WORKDIR=/work
OUT_DIR="$WORKDIR/dist/multi-modules-openssl10/$NGX_VER"
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
# CentOS 7's gcc 4.8 defaults to gnu89, which rejects the C99 the module is
# written in (declarations inside blocks and for-init), so the C standard is
# forced.  The OpenSSL 1.1 / 3 builders run gcc 8+, where gnu11 is already the
# default and the flag would change nothing.
# 1.11.5+ : --with-compat alone gives the dlopen ABI contract.
# 1.10.x  : no --with-compat, so enable --with-http_ssl_module explicitly to
#           turn on the SSL struct members (= ngx_connection_t.ssl).
# After it, the options every build path gives the module
# (nginx-module/hardening.sh); this recipe used to pass the standard alone.
CC_OPT="-std=gnu99 $(sh "$WORKDIR/nginx-module/hardening.sh" cc)"
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
# Confirm the link target is libssl.so.10 (= the whole point of this builder).
ldd "$OUT_DIR/ngx_http_unmask_module.so" 2>&1 | grep -E "libssl|libcrypto" || true
echo ">>> built: $OUT_DIR/ngx_http_unmask_module.so (nginx $NGX_VER, OpenSSL 1.0)"
