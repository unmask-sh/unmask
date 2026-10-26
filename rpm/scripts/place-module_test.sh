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

# --- case 7: the fail-safe, in and out (hooks overridden: nothing on the host is touched) ---
# The marker drives `unmask render-nginx`: while it exists the render is the
# degraded one (no module), and http.inc stays linked so a vhost that includes
# server.inc still starts.  On the way back the full render is checked once
# more and stripped again if it does not load, which cannot loop.
FAILSAFE_MARKER="$T/fs/.native-failsafe"
HTTP_INC_LINKS="$T/confd/00-unmask.conf"
mkdir -p "$T/confd"
_pm_strip_module() { STRIPPED=$((STRIPPED+1)); }
_pm_render() {
    RENDERS=$((RENDERS+1))
    if [ -e "$FAILSAFE_MARKER" ]; then RENDER_MODES="$RENDER_MODES degraded"; else RENDER_MODES="$RENDER_MODES full"; fi
    return "$RENDER_RC"
}
# nginx -t answers one return code per call, in the order ngx_seq lists them.
# The script reads it through `$(...)`, a subshell, so the sequence and the
# call count live in files rather than variables.
_pm_nginx_t() {
    _rc=$(head -1 "$T/ngx_seq" 2>/dev/null); _rc=${_rc:-0}
    sed -i '1d' "$T/ngx_seq" 2>/dev/null
    echo call >> "$T/ngx_calls"
    printf '%s\n' "$NGINX_T_OUT"
    return "$_rc"
}
ngx_seq() { printf '%s\n' "$@" > "$T/ngx_seq"; : > "$T/ngx_calls"; }
ngx_calls() { wc -l < "$T/ngx_calls" | tr -d ' '; }
_pm_module_wired() { [ "$WIRED" = 1 ]; }
fs_reset() {
    STRIPPED=0; RENDERS=0; RENDER_MODES=""; RENDER_RC=0; WIRED=1
    : > "$T/ngx_seq"; : > "$T/ngx_calls"
    rm -f "$FAILSAFE_MARKER"; : > "$T/confd/00-unmask.conf"
}
linked() { [ -e "$T/confd/00-unmask.conf" ] && echo linked || echo dropped; }

# 7a: nginx -t fails on unmask's own wiring -> the module is stripped, the
# marker names the cause, the configuration is rendered degraded, http.inc
# stays linked, and nginx -t is run again to report.
fs_reset
ngx_seq 1 0; NGINX_T_OUT='nginx: [emerg] unknown directive "unmask_bv_secret" in /var/lib/unmask/nginx/http.inc:52'
verify_or_disable >/dev/null
check "7a strips the module once" "1" "$STRIPPED"
check "7a writes the marker with the cause" 'reason: nginx: [emerg] unknown directive "unmask_bv_secret" in /var/lib/unmask/nginx/http.inc:52' "$(grep '^reason:' "$FAILSAFE_MARKER")"
check "7a renders once, degraded (the marker is there first)" "1 degraded" "$RENDERS$RENDER_MODES"
check "7a keeps http.inc linked" "linked" "$(linked)"
check "7a re-tests after the render" "2" "$(ngx_calls)"

# 7b: nginx -t fails on the operator's own config -> nothing of unmask's is touched.
fs_reset
ngx_seq 1; NGINX_T_OUT='nginx: [emerg] unknown directive "foo" in /etc/nginx/conf.d/site.conf:3'
verify_or_disable >/dev/null
check "7b leaves the module alone" "0" "$STRIPPED"
check "7b writes no marker" "absent" "$([ -e "$FAILSAFE_MARKER" ] && echo present || echo absent)"
check "7b renders nothing" "0" "$RENDERS"

# 7c: no bundled module (the picker's own path) and unmask cannot render ->
# http.inc is dropped from nginx as before, so nginx still starts.
fs_reset; RENDER_RC=1
ngx_seq 0; NGINX_T_OUT=""
disable_unmask_module "no bundled module for host nginx 1.99.0" >/dev/null
check "7c strips the module" "1" "$STRIPPED"
check "7c writes the marker" "reason: no bundled module for host nginx 1.99.0" "$(grep '^reason:' "$FAILSAFE_MARKER")"
check "7c drops http.inc when it cannot render" "dropped" "$(linked)"

# 7d: the way back: the marker is there, a module is in place and nginx -t
# passes -> the marker goes, the full configuration is rendered and checked.
fs_reset
: > "$FAILSAFE_MARKER"
ngx_seq 0 0; NGINX_T_OUT=""
verify_or_disable >/dev/null
check "7d clears the marker" "absent" "$([ -e "$FAILSAFE_MARKER" ] && echo present || echo absent)"
check "7d renders once, full (the marker is gone first)" "1 full" "$RENDERS$RENDER_MODES"
check "7d checks the full configuration" "2" "$(ngx_calls)"
check "7d strips nothing" "0" "$STRIPPED"

# 7e: the marker is there and nginx -t passes, but no module is in place
# (the web-nginx postinstall's --verify on a host whose module is gone): the
# degraded configuration stays, nothing is rendered.
fs_reset; WIRED=0
: > "$FAILSAFE_MARKER"
ngx_seq 0; NGINX_T_OUT=""
verify_or_disable >/dev/null
check "7e keeps the marker without a module" "present" "$([ -e "$FAILSAFE_MARKER" ] && echo present || echo absent)"
check "7e renders nothing" "0" "$RENDERS"

# 7f: the way back, but the full configuration does not load (the cause is
# still there): stripped again, the marker is back, the degraded configuration
# is rendered again -- and the check is not repeated (no loop).
fs_reset
: > "$FAILSAFE_MARKER"
ngx_seq 0 1 0; NGINX_T_OUT='nginx: [emerg] "map_hash_bucket_size" directive is duplicate in /var/lib/unmask/nginx/http.inc:30'
verify_or_disable >/dev/null
check "7f strips again" "1" "$STRIPPED"
check "7f marker is back with the cause" 'reason: nginx: [emerg] "map_hash_bucket_size" directive is duplicate in /var/lib/unmask/nginx/http.inc:30' "$(grep '^reason:' "$FAILSAFE_MARKER")"
check "7f renders full, then degraded" "2 full degraded" "$RENDERS$RENDER_MODES"
check "7f runs nginx -t three times, no more" "3" "$(ngx_calls)"

echo "----"
[ "$fails" -eq 0 ] && echo "ALL PASS" || echo "$fails FAILED"
exit "$fails"
