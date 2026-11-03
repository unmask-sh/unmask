#!/bin/sh
# tools/fetch-nginx-src.sh -- download one nginx source tarball, check it
# against the pinned sha256, and unpack it.
#
#   usage: tools/fetch-nginx-src.sh <nginx-version> [<dir>]
#
# Downloads nginx-<version>.tar.gz into <dir> (default: the current
# directory), refuses it unless nginx-module/nginx-sha256sums.txt carries a
# matching line, and leaves <dir>/nginx-<version>/ unpacked; the tarball is
# removed.  A version with no pin is an error, not a warning: add the line
# first (the header of the sums file says how).
#
# Every path that compiles the module reads this one script -- the Makefile's
# build-module, the builder containers of build-module-multi-*, CI's module
# jobs and the e2e nginx image -- so the pin cannot be checked on one path
# and skipped on another.  (The product Dockerfile checks the same file in
# its own module stage.)
#
# Environment:
#   NGINX_SHA256SUMS     the pin file.  Default: nginx-module/nginx-sha256sums.txt
#                        next to this script's parent directory.
#   NGINX_DOWNLOAD_BASE  where the tarballs are.  Default https://nginx.org/download.
#                        The CentOS 6 builder sets the http:// form because
#                        that TLS stack cannot reach nginx.org; the sha256
#                        check is what vouches for the bytes, not the transport.
set -eu

ver="${1:-}"
dir="${2:-.}"
if [ -z "$ver" ]; then
    echo "usage: $0 <nginx-version> [<dir>]" >&2
    exit 2
fi
here="$(cd "$(dirname "$0")" && pwd)"
sums="${NGINX_SHA256SUMS:-$here/../nginx-module/nginx-sha256sums.txt}"
base="${NGINX_DOWNLOAD_BASE:-https://nginx.org/download}"
tgz="nginx-$ver.tar.gz"

[ -f "$sums" ] || { echo "ERROR: pin file $sums not found" >&2; exit 2; }
expected=$(awk -v f="$tgz" '$2 == f {print $1}' "$sums")
if [ -z "$expected" ]; then
    echo "ERROR: nginx $ver has no pinned sha256 in $sums -- add it before building" >&2
    exit 1
fi

mkdir -p "$dir"
cd "$dir"
rm -f "$tgz"
if command -v curl >/dev/null 2>&1; then
    curl -fsSL -o "$tgz" "$base/$tgz"
else
    wget -q -O "$tgz" "$base/$tgz"
fi

actual=$(sha256sum "$tgz" | cut -d' ' -f1)
if [ "$expected" != "$actual" ]; then
    echo "ERROR: $tgz sha256 mismatch (supply-chain check failed):" >&2
    echo "  expected $expected" >&2
    echo "  actual   $actual" >&2
    rm -f "$tgz"
    exit 1
fi
echo ">>> verified $tgz sha256 ($actual)"

rm -rf "nginx-$ver"
tar -xzf "$tgz"
rm -f "$tgz"
[ -f "nginx-$ver/configure" ] || { echo "ERROR: $tgz did not unpack to nginx-$ver/" >&2; exit 1; }
