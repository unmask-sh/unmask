#!/bin/sh
# The compiler and linker options every ngx_http_unmask_module.so is built
# with.  The .so parses TLS ClientHello bytes and a client-set cookie on every
# request, and it is built along six paths -- the Makefile, the three
# container recipes under build-docker/, the gateway image, CI -- which used
# to carry these options each for itself: two of the container recipes passed
# none, and the third only the C standard.  They all ask here now, and
# tools/check-so-hardening.sh reads the result back out of each .so.
#
#   hardening.sh cc [compiler]   options for nginx's --with-cc-opt
#   hardening.sh ld              options for nginx's --with-ld-opt
#
# cc: -O2 and a stack protector.  -fstack-protector-strong needs gcc 4.9; the
#     compilers of the OpenSSL 1.0 and glibc 2.12 builders are older and get
#     -fstack-protector.  _FORTIFY_SOURCE is undefined and stays off: the
#     fortified calls it emits (__snprintf_chk, __memcpy_chk) exist only in
#     glibc, and the glibc-built .so is also dlopen()ed by Alpine's musl
#     nginx through gcompat, which provides none of them -- a module built
#     with it failed to load there ("__snprintf_chk: symbol not found") and
#     the fail-safe stripped it.  Some toolchains predefine the macro (at 3),
#     and nginx builds with -Werror, so it is undefined explicitly.
# ld: RELRO and BIND_NOW, so the GOT is read-only once the module is loaded.
#     BIND_NOW also turns a symbol the host cannot resolve into a refused
#     load at start, where lazy binding would crash a worker at first use.
#
# This file is part of what tools/module-src-hash.sh hashes: changing an
# option here makes every cached .so stale, as changing the source does.
set -eu

case "${1:-}" in
cc)
	cc="${2:-${CC:-cc}}"
	sp=-fstack-protector
	if echo 'int main(void){return 0;}' | "$cc" -fstack-protector-strong -x c -c -o /dev/null - >/dev/null 2>&1; then
		sp=-fstack-protector-strong
	fi
	echo "-O2 $sp -U_FORTIFY_SOURCE"
	;;
ld)
	echo "-Wl,-z,relro,-z,now"
	;;
*)
	echo "usage: hardening.sh cc [compiler] | ld" >&2
	exit 2
	;;
esac
