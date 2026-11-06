#!/bin/sh
# Read back, out of a built ngx_http_unmask_module.so, what
# nginx-module/hardening.sh asked the compiler and the linker for:
#
#   - a GNU_RELRO segment and BIND_NOW (the GOT is read-only once loaded);
#   - a reference to __stack_chk_fail (the stack protector is compiled in);
#   - no fortified libc call (__snprintf_chk and friends): they exist only in
#     glibc, and the same .so is loaded by Alpine's musl nginx through
#     gcompat, which has none of them.
#
# The options are easy to lose on the way to a binary -- a build path that
# does not pass them, a toolchain that predefines _FORTIFY_SOURCE, a cached
# .so from before a change -- and nothing but the file says so.  Every build
# path runs this on what it produced.
#
#   check-so-hardening.sh <file.so>...      exit 1 when any file fails
set -u

command -v readelf >/dev/null 2>&1 || { echo "check-so-hardening: readelf not found (binutils)" >&2; exit 2; }
[ "$#" -gt 0 ] || { echo "usage: check-so-hardening.sh <file.so>..." >&2; exit 2; }

rc=0
for f in "$@"; do
	if [ ! -f "$f" ]; then
		echo "check-so-hardening: $f: no such file" >&2
		rc=1
		continue
	fi
	segments=$(readelf -lW "$f" 2>/dev/null)
	dynamic=$(readelf -dW "$f" 2>/dev/null)
	symbols=$(readelf -sW "$f" 2>/dev/null)
	bad=""
	echo "$segments" | grep -q 'GNU_RELRO' || bad="$bad no GNU_RELRO segment;"
	# BIND_NOW shows as its own entry, in FLAGS, or as NOW in FLAGS_1,
	# depending on the linker.
	echo "$dynamic" | grep -Eq '\(BIND_NOW\)|\(FLAGS\).*BIND_NOW|\(FLAGS_1\).*NOW' || bad="$bad not BIND_NOW;"
	echo "$symbols" | grep -q '__stack_chk_fail' || bad="$bad no stack protector (__stack_chk_fail is not referenced);"
	fortified=$(echo "$symbols" | grep -oE '__[a-z0-9_]+_chk(@[A-Za-z0-9_.]+)?$' | sed 's/@.*//' | sort -u | tr '\n' ' ')
	[ -z "$fortified" ] || bad="$bad fortified libc calls ($fortified);"
	if [ -n "$bad" ]; then
		echo "check-so-hardening: $f:$bad" >&2
		rc=1
	else
		echo "check-so-hardening: $f: RELRO, BIND_NOW, stack protector, no fortified calls"
	fi
done
exit $rc
