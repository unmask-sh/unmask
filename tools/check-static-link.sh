#!/bin/sh
# tools/check-static-link.sh <nginx source dir>
#
# The module compiled INTO nginx (--add-module) must leave OpenSSL to nginx.
#
# nginx-module/config is read by nginx's configure before nginx adds its own
# libraries, so a library the module names lands ahead of them on the link
# line.  It named -lcrypto: with an nginx configured --with-openssl=DIR (a
# static OpenSSL, what hosting panels build) the linker then took the SYSTEM's
# shared libcrypto first and resolved nginx's libssl.a against it -- two
# OpenSSL releases in one binary, which segfaults at its first start.  Nothing
# said so: configure and make both pass.
#
# This runs configure only (a few seconds, no compiler work beyond its feature
# tests) in a build directory of its own and reads the link line back:
#
#   1. --with-openssl=DIR: nginx's libssl.a and libcrypto.a are there, and no
#      -lcrypto is anywhere on the line;
#   2. the system's OpenSSL: the only -lcrypto is nginx's own, after its -lssl;
#   3. an nginx without TLS is refused at configure time, in words.
#
# The module's own (dynamic) build is not touched by any of this and is what
# every other check here covers.
set -u
SRC=${1:?usage: check-static-link.sh <nginx source dir>}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
[ -f "$SRC/configure" ] || [ -f "$SRC/auto/configure" ] || { echo "check-static-link: $SRC is not an nginx source tree" >&2; exit 2; }
CONFIGURE=./configure
[ -f "$SRC/configure" ] || CONFIGURE=./auto/configure
BD=objs-static-link-check
fail=0
ok()  { echo "  ok   $1"; }
bad() { echo "  FAIL $1"; fail=1; }

# The words of the link rule of the nginx binary, one per line.
link_words() {
    awk -v out="$BD/nginx" '
        index($0, "-o " out) { on = 1 }
        on { print }
        on && !/\\$/ { exit }
    ' "$SRC/$BD/Makefile" | tr -s ' \t\\' '\n' | sed '/^$/d'
}
configure() {
    ( cd "$SRC" && rm -rf "$BD" && $CONFIGURE --builddir="$BD" \
        --without-http_rewrite_module --without-http_gzip_module "$@" ) > "$SRC/$BD.log" 2>&1
}

echo "check-static-link: nginx $(sed -n 's/^#define NGINX_VERSION  *"\(.*\)"/\1/p' "$SRC/src/core/nginx.h")"

# 1. a static OpenSSL.  The directory need not exist: configure only writes
#    its path into the Makefile.
if configure --with-http_ssl_module --with-openssl=/nonexistent/openssl --add-module="$ROOT/nginx-module"; then
    words=$(link_words)
    if printf '%s\n' "$words" | grep -q '/nonexistent/openssl/.openssl/lib/libcrypto\.a$'; then
        ok "static OpenSSL: nginx links its own libcrypto.a"
    else
        bad "static OpenSSL: no libcrypto.a on the link line"
    fi
    if printf '%s\n' "$words" | grep -qx -- '-lcrypto'; then
        bad "static OpenSSL: -lcrypto on the link line beside nginx's static libcrypto.a (position $(printf '%s\n' "$words" | grep -nx -- '-lcrypto' | head -1 | cut -d: -f1), libcrypto.a at $(printf '%s\n' "$words" | grep -n 'libcrypto\.a$' | head -1 | cut -d: -f1))"
    else
        ok "static OpenSSL: no -lcrypto of the module's"
    fi
else
    bad "configure --with-openssl=DIR --add-module failed: $(tail -n 3 "$SRC/$BD.log" | tr '\n' ' ')"
fi

# 2. the system's OpenSSL (needs its headers, as every build of the module does).
if configure --with-http_ssl_module --add-module="$ROOT/nginx-module"; then
    words=$(link_words)
    n=$(printf '%s\n' "$words" | grep -cx -- '-lcrypto')
    ssl_at=$(printf '%s\n' "$words" | grep -nx -- '-lssl' | head -1 | cut -d: -f1)
    crypto_at=$(printf '%s\n' "$words" | grep -nx -- '-lcrypto' | head -1 | cut -d: -f1)
    if [ "$n" = 1 ] && [ -n "$ssl_at" ] && [ "$crypto_at" -gt "$ssl_at" ]; then
        ok "system OpenSSL: one -lcrypto, nginx's, after its -lssl"
    else
        bad "system OpenSSL: expected nginx's -lssl -lcrypto and nothing more (-lcrypto x$n, first at ${crypto_at:-none}; -lssl at ${ssl_at:-none})"
    fi
else
    bad "configure --add-module (system OpenSSL) failed: $(tail -n 3 "$SRC/$BD.log" | tr '\n' ' ')"
fi

# 3. no TLS in the nginx: refused, and the reason is in the output.
if configure --add-module="$ROOT/nginx-module"; then
    bad "an nginx without --with-http_ssl_module took the module compiled in"
elif grep -q 'ngx_http_unmask_module needs an nginx with TLS' "$SRC/$BD.log"; then
    ok "no TLS: configure refuses and says why"
else
    bad "no TLS: configure failed without the reason: $(tail -n 2 "$SRC/$BD.log" | tr '\n' ' ')"
fi

rm -rf "$SRC/$BD" "$SRC/$BD.log"
[ "$fail" = 0 ] && echo "check-static-link: OK" || { echo "check-static-link: FAILED"; exit 1; }
