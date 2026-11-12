#!/bin/sh
# tools/build-test-nginx.sh -- build one nginx, with the unmask module, for
# the renderer's `nginx -t` test (TestNginxAcceptsTheRender in
# admin/internal/nginxconf).
#
#   usage: tools/build-test-nginx.sh <nginx-version> <dir>
#
# Fetches the pinned source into <dir> (fetch-nginx-src.sh) and builds the
# binary and the module there.  The last two lines printed are the test's
# environment:
#
#   UNMASK_TEST_NGINX=<dir>/nginx-<version>/objs/nginx
#   UNMASK_TEST_NGINX_MODULE=<dir>/nginx-<version>/objs/ngx_http_unmask_module.so
#
# This binary exists to parse configuration and nothing else.  It is not how
# any package's nginx or module is built, it serves no request, and its
# options are the ones the rendered files need: TLS, realip, auth_request,
# and IPv6 addresses in geo blocks.  That is what lets it be the oldest
# supported nginx on a current compiler:
#
#   - before 1.11.5 IPv6 is a configure option and --with-compat does not
#     exist;
#   - up to 1.14.1 ngx_user.c writes crypt_data.current_salt, a field glibc
#     dropped in 2.28.  The line is removed: the function hashes passwords
#     for auth_basic, which nothing here uses;
#   - what a newer compiler adds as a warning is not an error.
set -eu

ver="${1:-}"
dir="${2:-}"
if [ -z "$ver" ] || [ -z "$dir" ]; then
    echo "usage: $0 <nginx-version> <dir>" >&2
    exit 2
fi
here="$(cd "$(dirname "$0")" && pwd)"
module="$(cd "$here/../nginx-module" && pwd)"

mkdir -p "$dir"
dir="$(cd "$dir" && pwd)"
"$here/fetch-nginx-src.sh" "$ver" "$dir"
src="$dir/nginx-$ver"

# x.y.z as one number, to compare versions.
code=$(echo "$ver" | awk -F. '{ print $1 * 1000000 + $2 * 1000 + $3 }')

opts="--with-http_ssl_module --with-http_realip_module --with-http_auth_request_module"
if [ "$code" -lt 1011005 ]; then
    opts="$opts --with-ipv6"
else
    opts="$opts --with-compat"
fi
if [ "$code" -le 1014001 ]; then
    sed -i '/cd\.current_salt\[0\] = ~salt\[0\];/d' "$src/src/os/unix/ngx_user.c"
fi

cd "$src"
# shellcheck disable=SC2086  # $opts is a list of options
if ! ./configure $opts --with-cc-opt=-Wno-error \
        --add-dynamic-module="$module" >configure.log 2>&1; then
    tail -n 30 configure.log >&2
    echo "ERROR: configure failed for nginx $ver" >&2
    exit 1
fi
jobs=$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)
if ! make -j"$jobs" >make.log 2>&1; then
    tail -n 40 make.log >&2
    echo "ERROR: build failed for nginx $ver" >&2
    exit 1
fi
[ -x objs/nginx ] && [ -f objs/ngx_http_unmask_module.so ] || {
    echo "ERROR: nginx $ver built neither objs/nginx nor the module" >&2
    exit 1
}
objs/nginx -v
echo "UNMASK_TEST_NGINX=$src/objs/nginx"
echo "UNMASK_TEST_NGINX_MODULE=$src/objs/ngx_http_unmask_module.so"
