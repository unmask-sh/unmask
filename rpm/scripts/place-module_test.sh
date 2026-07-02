#!/bin/bash
# Unit test for resolve_libcrypto() in place-module.sh (= v0.1.1 harness, #4).
#
# Covers the OpenSSL ABI detection that the manual unmask.sh install exposed:
# nginx.org / self-built nginx links OpenSSL statically, so `ldd nginx` shows no
# libcrypto and detection must fall back to `nginx -V` then to the system SONAME.
# No VM / no nginx needed — the probe hooks are overridden per case.
#
# Run: bash rpm/scripts/place-module_test.sh
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"

# Source only the functions (the guard stops before install side effects).
PLACE_MODULE_TEST=1
# shellcheck source=./place-module.sh
. "$DIR/place-module.sh"

fails=0
check() { # <desc> <expected> <actual>
    if [ "$2" = "$3" ]; then printf 'PASS  %s\n' "$1"
    else printf 'FAIL  %s (expected="%s" got="%s")\n' "$1" "$2" "$3"; fails=$((fails+1)); fi
}

# --- case 1: ldd reports libcrypto directly (normal distro nginx) ---
_rl_ldd_soname() { echo "libcrypto.so.3"; }
_rl_nginx_v() { echo ""; }
_rl_have_so() { return 1; }
check "distro nginx: ldd libcrypto.so.3" "libcrypto.so.3" "$(resolve_libcrypto)"

_rl_ldd_soname() { echo "libcrypto.so.1.1"; }
check "distro nginx: ldd libcrypto.so.1.1" "libcrypto.so.1.1" "$(resolve_libcrypto)"

# --- case 2: ldd silent, nginx -V says OpenSSL 3.x (unmask.sh's static build) ---
_rl_ldd_soname() { echo ""; }
_rl_nginx_v() { echo "built with OpenSSL 3.6.2 7 Apr 2026 (running with OpenSSL 3.6.2)"; }
_rl_have_so() { return 1; }
check "static OpenSSL 3.6.2 via nginx -V" "libcrypto.so.3" "$(resolve_libcrypto)"

_rl_nginx_v() { echo "built with OpenSSL 1.1.1w  11 Sep 2023"; }
check "static OpenSSL 1.1.1w via nginx -V" "libcrypto.so.1.1" "$(resolve_libcrypto)"

_rl_nginx_v() { echo "built with OpenSSL 1.0.2k-fips"; }
check "static OpenSSL 1.0.2k via nginx -V" "libcrypto.so.10" "$(resolve_libcrypto)"

# --- case 3: ldd silent AND nginx -V inconclusive -> system SONAME ---
_rl_ldd_soname() { echo ""; }
_rl_nginx_v() { echo "built with LibreSSL 3.8.2"; }          # no OpenSSL version
_rl_have_so() { [ "$1" = "libcrypto.so.1.1" ]; }             # only 1.1 present
check "LibreSSL -> falls back to system SONAME (1.1)" "libcrypto.so.1.1" "$(resolve_libcrypto)"

_rl_nginx_v() { echo "built with BoringSSL"; }
_rl_have_so() { [ "$1" = "libcrypto.so.3" ]; }               # only 3 present
check "BoringSSL -> system SONAME (3)" "libcrypto.so.3" "$(resolve_libcrypto)"

# --- case 4: everything silent -> empty (caller warns + defaults to openssl3) ---
_rl_ldd_soname() { echo ""; }
_rl_nginx_v() { echo ""; }
_rl_have_so() { return 1; }
check "no ldd/no -V/no SONAME -> empty" "" "$(resolve_libcrypto)"

echo "----"
[ "$fails" -eq 0 ] && echo "ALL PASS" || echo "$fails FAILED"
exit "$fails"
