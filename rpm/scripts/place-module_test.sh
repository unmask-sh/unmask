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

# --- case 5: install_so — primary writable / read-only-primary fallback ---
# (the immutable-/usr path: modules dir unwritable -> /var/lib fallback)
T=$(mktemp -d)
trap 'chmod -R u+w "$T" 2>/dev/null; rm -rf "$T"' EXIT
printf 'SOBYTES' > "$T/src.so"

mkdir -p "$T/primary" "$T/fallback"
got=$(install_so "$T/src.so" "$T/primary" "$T/fallback")
check "install_so -> primary when writable" "$T/primary/$SO_NAME" "$got"
check "install_so primary content" "SOBYTES" "$(cat "$T/primary/$SO_NAME")"

mkdir -p "$T/ro"
chmod a-w "$T/ro"
got=$(install_so "$T/src.so" "$T/ro" "$T/fallback")
check "install_so -> fallback when primary read-only" "$T/fallback/$SO_NAME" "$got"
check "install_so fallback content" "SOBYTES" "$(cat "$T/fallback/$SO_NAME")"
if [ -e "$T/ro/$SO_NAME" ]; then
    check "install_so leaves nothing in read-only primary" "absent" "present"
else
    check "install_so leaves nothing in read-only primary" "absent" "absent"
fi

# Unwritable primary whose PARENT allows mkdir of a missing dir: missing
# primary is created (the normal first-install path).
got=$(install_so "$T/src.so" "$T/newdir/modules" "$T/fallback")
check "install_so mkdirs a missing primary" "$T/newdir/modules/$SO_NAME" "$got"

# --- case 6: so_in_place -- an identical module is left alone ---
# The point is the inode: replacing even an identical file gives the path a new
# one, and nginx loads a module only at startup, so the host would need an nginx
# restart for an upgrade that did not change the module.
mkdir -p "$T/live" "$T/live_fb"
printf 'SOBYTES' > "$T/live/$SO_NAME"
ino_before=$(stat -c %i "$T/live/$SO_NAME")
got=$(so_in_place "$T/src.so" "$T/live" "$T/live_fb"); rc=$?
check "so_in_place finds the identical module" "0 $T/live/$SO_NAME" "$rc $got"
check "so_in_place leaves the file's inode alone" "$ino_before" "$(stat -c %i "$T/live/$SO_NAME")"

# Same bytes but only in the fallback location (immutable-/usr host) counts too.
rm -f "$T/live/$SO_NAME"
printf 'SOBYTES' > "$T/live_fb/$SO_NAME"
got=$(so_in_place "$T/src.so" "$T/live" "$T/live_fb"); rc=$?
check "so_in_place finds it in the fallback" "0 $T/live_fb/$SO_NAME" "$rc $got"

# Different bytes: not in place, so the caller replaces it -- and the
# replacement really is a new file.
printf 'OLDBYTES' > "$T/live/$SO_NAME"
ino_before=$(stat -c %i "$T/live/$SO_NAME")
so_in_place "$T/src.so" "$T/live" "$T/nowhere" >/dev/null; rc=$?
check "so_in_place reports a changed module" "1" "$rc"
got=$(install_so "$T/src.so" "$T/live" "$T/live_fb")
check "a changed module is replaced" "SOBYTES" "$(cat "$T/live/$SO_NAME")"
[ "$(stat -c %i "$T/live/$SO_NAME")" != "$ino_before" ] && r=new || r=same
check "the replacement is a new inode (nginx restart territory)" "new" "$r"

# Nothing there at all: not in place.
so_in_place "$T/src.so" "$T/empty1" "$T/empty2" >/dev/null; rc=$?
check "so_in_place with no module installed" "1" "$rc"

echo "----"
[ "$fails" -eq 0 ] && echo "ALL PASS" || echo "$fails FAILED"
exit "$fails"
