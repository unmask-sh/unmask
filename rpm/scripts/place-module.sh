#!/bin/sh
# place-module.sh -- pick + place the unmask nginx native module for the host
# nginx.  Shipped on-disk at /usr/share/unmask/plugin/place-module.sh and run by
# BOTH the unmask-plugin-nginx postinstall AND the nginx.service ExecStartPre
# drop-in (10-unmask-repick.conf).  Running it before every nginx start is what
# closes the host-nginx-upgrade .so orphan: when the host upgrades nginx, the
# matching bundled .so is re-picked -- or, if none matches the new version, the
# wiring is fail-safe-stripped (disable_unmask_module) so nginx still starts
# WITHOUT the module instead of dying on an ABI-incompatible load_module.
# Idempotent and ALWAYS exits 0 (= never blocks nginx).
#
# Only systemd hosts get the automatic per-start re-pick (via the drop-in).
# Non-systemd hosts (Alpine OpenRC -- which ships no nginx service at all -- and
# SysV) have no equivalent hook, so after upgrading the host nginx, re-run this
# script manually, or call it from the nginx service's pre-start (OpenRC
# start_pre) so every start re-picks.  The plugin postinstall prints the same
# reminder on non-systemd installs.
#
# Flow:
#   1. Get the host nginx version (= X.Y.Z) from `nginx -v`.
#   2. Look up the host nginx's libcrypto dependency to determine the
#      OpenSSL ABI (= 1.1 or 3).
#   3. Find /usr/share/unmask/plugin/{openssl11,openssl3}/ngx_http_unmask_module-X.Y.Z.so:
#      (a) exact match (= e.g. host 1.18.0 -> -1.18.0.so under the matching ABI dir)
#      (b) closest within the same minor branch (= host 1.18.4 -> -1.18.0.so, assuming patch ABI compatibility)
#      (c) none -> disable_unmask_module (= strip wiring so nginx still starts) + exit 0
#   4. Extract --modules-path= from `nginx -V`.
#   5. Copy the chosen .so to $modules_path/ngx_http_unmask_module.so —
#      or, when the modules path is unwritable (immutable /usr, ostree-style
#      distros), to /var/lib/unmask/plugin/ and point load_module there.
#   6. restorecon if selinux is in use.

PLUGIN_BASE=/usr/share/unmask/plugin
SO_NAME=ngx_http_unmask_module.so
# Fallback .so home for hosts whose /usr is read-only at runtime (Fedora
# Silverblue / ostree and friends).  The distro-conventional modules path is
# still preferred when writable: it inherits the right SELinux label and
# matches what nginx tooling expects.
FALLBACK_SO_DIR=/var/lib/unmask/plugin
# Breadcrumb dropped when the fail-safe strips the native wiring (nginx -t failed
# referencing unmask).  `unmask doctor` surfaces it so an operator sees native
# protection is silently OFF rather than assuming install-and-go worked.  Cleared
# on the next successful `nginx -t`.
FAILSAFE_MARKER=/var/lib/unmask/nginx/.native-failsafe

# disable_unmask_module: strip every piece of unmask nginx wiring so a stock
# nginx still starts.  Used when no bundled .so matches the host nginx (= the
# host upgraded nginx to a version we don't ship a module for).  Leaving the old
# load_module + http.inc + an ABI-incompatible .so in place makes nginx fail to
# start ENTIRELY -- the "host-nginx-upgrade orphan" outage.  Coming up WITHOUT
# native protection (degraded; forward-auth still works) beats a dead web
# server.  The bundled .so files stay under $PLUGIN_BASE for a later re-pick.
disable_unmask_module() {
    mp=$(nginx -V 2>&1 | tr ' ' '\n' | sed -n 's|^--modules-path=||p' | head -1)
    rm -f /etc/nginx/modules-enabled/50-mod-unmask.conf \
          /etc/nginx/modules.d/50-mod-unmask.conf \
          /usr/share/nginx/modules/50-mod-unmask.conf 2>/dev/null
    rm -f /etc/nginx/conf.d/00-unmask.conf /etc/nginx/http.d/00-unmask.conf 2>/dev/null
    [ -n "$mp" ] && rm -f "$mp/$SO_NAME" 2>/dev/null
    rm -f "$FALLBACK_SO_DIR/$SO_NAME" 2>/dev/null
    if [ -w /etc/nginx/nginx.conf ] && grep -q 'load_module.*ngx_http_unmask_module' /etc/nginx/nginx.conf 2>/dev/null; then
        t="/etc/nginx/nginx.conf.unmask-disable.$$"
        if grep -v 'load_module.*ngx_http_unmask_module' /etc/nginx/nginx.conf > "$t" 2>/dev/null; then
            mv -f "$t" /etc/nginx/nginx.conf
        else
            rm -f "$t"
        fi
    fi
    echo "  fail-safe: stripped unmask nginx wiring (load_module + http.inc + .so) so nginx still starts without the module."
    mkdir -p /var/lib/unmask/nginx 2>/dev/null
    { echo "native wiring stripped by place-module fail-safe ($(date 2>/dev/null))"
      [ -n "${1:-}" ] && echo "reason: $1"
    } > "$FAILSAFE_MARKER" 2>/dev/null || true
}

# verify_or_disable: run `nginx -t` and, if it fails *because of unmask*, strip
# the wiring (disable_unmask_module) so nginx still starts.  A failure whose
# error does NOT reference unmask is a pre-existing host config error -- leave
# unmask alone and let the operator fix it (never mask their own bug).  This is
# the catch-all for a bad render: a missing community-bans map, a stale http.inc,
# an unknown directive -- anything that would otherwise leave nginx unable to
# start/reload after install.  Called at the end of the picker's own flow and,
# via `--verify`, by the web-nginx postinstall, so whichever wires last runs the
# final check.
verify_or_disable() {
    command -v nginx >/dev/null 2>&1 || return 0
    if err=$(nginx -t 2>&1); then
        rm -f "$FAILSAFE_MARKER" 2>/dev/null   # wiring is healthy now -> clear any stale breadcrumb
        return 0
    fi
    # Classify by OUR OWN wiring artifacts only: the module itself
    # (ngx_http_unmask...), our autoload/symlink confs (00-unmask*,
    # 50-mod-unmask) and the render output (/var/lib/unmask/nginx/).  A bare
    # "unmask" match is too broad: an OPERATOR conf that includes a shipped
    # forward-auth snippet (/etc/unmask/forward-auth/server.inc, per the
    # web-nginx install instructions) mentions an unmask path too -- and when
    # that file is transiently absent (mid-transaction on a reinstall: this
    # runs from the plugin postinstall BEFORE web-nginx lays its files down),
    # the broad match stripped a perfectly healthy native module.  Stripping
    # can never fix those errors anyway (we don't touch operator vhosts), so
    # leave them to the operator / the rest of the transaction.
    if printf '%s\n' "$err" | grep -qiE 'ngx_http_unmask|00-unmask|50-mod-unmask|/var/lib/unmask/nginx/'; then
        echo "  !! nginx -t failed and the error references unmask -- disabling unmask wiring (fail-safe) so nginx still starts:"
        printf '%s\n' "$err" | sed 's/^/       /'
        disable_unmask_module "$(printf '%s\n' "$err" | grep -iE 'ngx_http_unmask|00-unmask|50-mod-unmask|map_hash|/var/lib/unmask/nginx/' | head -1)"
    else
        echo "  nginx -t failed, but the error does NOT reference unmask (= pre-existing host config error). Leaving unmask in place:"
        printf '%s\n' "$err" | sed 's/^/       /'
    fi
}

if ! command -v nginx >/dev/null 2>&1; then
    cat <<EOF
unmask-plugin-nginx: nginx is not installed, so skipped placing the module.
  Install nginx and then re-place by one of:
    1. dnf reinstall unmask-plugin-nginx
    2. Copy /usr/share/unmask/plugin/openssl{11,3}/ngx_http_unmask_module-<version>.so by hand to
       \$(nginx -V 2>&1 | tr ' ' '\n' | grep modules-path)
EOF
    exit 0
fi

# --verify: only re-test the already-placed wiring and fail-safe-disable it if
# *unmask* breaks `nginx -t` (no re-pick).  The web-nginx postinstall calls this
# after it (re)wires http.inc, so whichever package wires last runs the final
# check and a bad render never leaves nginx unable to start.
if [ "${1:-}" = "--verify" ]; then
    verify_or_disable
    exit 0
fi

# Detect musl libc (= Alpine / similar).  The bundled .so files are built
# against glibc; nginx on Alpine is linked against musl and cannot dlopen a
# glibc .so directly.  Alpine's `gcompat` package provides a glibc compat
# layer that lets dlopen + symbol resolution succeed.  If gcompat is present
# we proceed normally; otherwise we skip with a hint so apk add gcompat
# unblocks the operator.
if ldd --version 2>&1 | grep -qi musl \
   || [ -e /lib/ld-musl-x86_64.so.1 ] \
   || [ -e /lib/ld-musl-aarch64.so.1 ]; then
    if [ -e /lib/ld-linux-x86-64.so.2 ] || [ -e /lib/ld-linux-aarch64.so.1 ]; then
        echo "unmask-plugin-nginx: musl libc + gcompat detected (= Alpine with glibc compat). Proceeding with glibc-built module."
    else
        cat <<'EOF'
================================================================
unmask-plugin-nginx: musl libc without gcompat detected (= Alpine).
================================================================

The bundled module .so files are glibc-built.  Alpine's nginx is musl-
linked and cannot dlopen a glibc .so without the gcompat glibc compat
layer.  Install gcompat and rerun the unmask-plugin-nginx install:

  sudo apk add gcompat
  sudo apk add --no-cache unmask-plugin-nginx

(gcompat is listed as a soft `depends` in the apk metadata, so a plain
`apk add unmask-plugin-nginx` should already pull it in -- this branch
fires only when gcompat was explicitly excluded.)

Alternatively, run unmask in forward-auth mode -- the main `unmask`
package alone is enough; nginx subrequests the admin daemon.  See
https://unmask.sh/install/  ->  pick "nginx · auth_request".

The .so binaries stay under /usr/share/unmask/plugin/ for inspection.
================================================================
EOF
        exit 0
    fi
fi

# ---- 0.5. Determine the host nginx's OpenSSL ABI ----
# Look at the version of libcrypto.so the nginx binary links against, and
# pick the plugin .so built against the matching ABI.  Thanks to the
# custom ClientHello parser (= ja4_parser.c), the same source is ABI-
# compatible across OpenSSL 0.9.7+, and we ship one .so per ABI built
# from the same source.
PLUGIN_DIR=""
# Also detect glibc version (= CentOS 6 = 2.12 / CentOS 7 = 2.17 / RHEL 8 = 2.28 etc.).
# Pick the CentOS 6 family glibc 2.12 build (= ships its own libcrypto.so.10)
# when glibc is older than 2.14.
GLIBC_VER=""
if command -v ldd >/dev/null 2>&1; then
    GLIBC_VER=$(ldd --version 2>/dev/null | head -1 | sed -n 's|.*[ ]\([0-9][0-9]*\.[0-9][0-9]*\)$|\1|p')
fi
glibc_lt_214() {
    # arg: e.g. "2.12" / "2.17".  Returns 0 (true) for < 2.14 (= 2.0 .. 2.13.999).
    case "$1" in
        2.[0-9]|2.[0-9].*|2.1[0-3]|2.1[0-3].*) return 0 ;;
        *) return 1 ;;
    esac
}

# resolve_libcrypto: print the libcrypto SONAME the host nginx uses, or "" if
# undetermined.  Order: (1) ldd of the nginx binary, (2) `nginx -V`'s "built
# with OpenSSL X" (nginx.org / self-built nginx links OpenSSL statically, so
# ldd is silent), (3) newest libcrypto SONAME present on the system.
# Pure-ish + test-injectable (= v0.1.1): tests override these hooks —
#   _rl_ldd_soname  : echoes the SONAME ldd would find ("" = none)
#   _rl_nginx_v     : echoes `nginx -V` output
#   _rl_have_so     : `_rl_have_so <soname>` returns 0 if that SONAME exists
# The default hooks below implement the real probes; place-module_test.sh
# redefines them to exercise ldd-silent / static-OpenSSL / LibreSSL cases.
_rl_ldd_soname() {
    command -v ldd >/dev/null 2>&1 || { echo ""; return; }
    ldd "$(command -v nginx)" 2>/dev/null | sed -n 's|.*\(libcrypto\.so\.[0-9.]*\).*|\1|p' | head -1
}
_rl_nginx_v() { nginx -V 2>&1; }
_rl_have_so() {
    for d in /lib64 /usr/lib64 /lib /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu; do
        [ -e "$d/$1" ] && return 0
    done
    return 1
}

# install_so <src> <primary-dir> <fallback-dir>: atomically install the .so
# into primary-dir; when that fails (read-only /usr on an immutable distro),
# fall back to fallback-dir.  Prints the installed path on stdout, returns
# non-zero when neither landed.  tmp + rename(2) so a running nginx worker
# that still mmaps the old .so doesn't hit ETXTBSY mid-upgrade, and a SIGKILL
# during the copy can't leave a half-written .so on disk.
install_so() {
    _is_src=$1
    for _is_dir in "$2" "$3"; do
        [ -d "$_is_dir" ] || mkdir -p "$_is_dir" 2>/dev/null || continue
        _is_tmp="$_is_dir/$SO_NAME.tmp.$$"
        if cp -f "$_is_src" "$_is_tmp" 2>/dev/null \
           && chmod 0644 "$_is_tmp" 2>/dev/null \
           && mv -f "$_is_tmp" "$_is_dir/$SO_NAME" 2>/dev/null; then
            echo "$_is_dir/$SO_NAME"
            return 0
        fi
        rm -f "$_is_tmp" 2>/dev/null
    done
    return 1
}
resolve_libcrypto() {
    local so ver
    so=$(_rl_ldd_soname)
    if [ -n "$so" ]; then echo "$so"; return; fi
    # ldd silent: parse `nginx -V`'s OpenSSL version.
    ver=$(_rl_nginx_v | sed -n 's|.*[Oo]pen[Ss][Ss][Ll] \([0-9][0-9.]*\).*|\1|p' | head -1)
    case "$ver" in
        3.*)   echo "libcrypto.so.3";   return ;;
        1.1.*) echo "libcrypto.so.1.1"; return ;;
        1.0.*) echo "libcrypto.so.10";  return ;;
    esac
    # Still unknown (LibreSSL/BoringSSL/no version): newest system SONAME.
    for cand in libcrypto.so.3 libcrypto.so.1.1 libcrypto.so.10; do
        _rl_have_so "$cand" && { echo "$cand"; return; }
    done
    echo ""
}

# Guard: when sourced by the unit test, stop here (no install side effects).
[ -n "${PLACE_MODULE_TEST:-}" ] && return 0 2>/dev/null

if command -v ldd >/dev/null 2>&1; then
    NGINX_BIN=$(command -v nginx)
    NGINX_LIBCRYPTO=$(_rl_ldd_soname)
    if [ -z "$NGINX_LIBCRYPTO" ]; then
        NGINX_LIBCRYPTO=$(resolve_libcrypto)
        [ -n "$NGINX_LIBCRYPTO" ] && \
            echo "unmask-plugin-nginx: nginx -V/system probe -> $NGINX_LIBCRYPTO (ldd was silent, e.g. nginx.org static build)"
    fi
    case "$NGINX_LIBCRYPTO" in
        libcrypto.so.3)
            PLUGIN_DIR="$PLUGIN_BASE/openssl3"
            echo "unmask-plugin-nginx: host OpenSSL = 3.x ($NGINX_LIBCRYPTO), glibc=$GLIBC_VER"
            ;;
        libcrypto.so.1.1)
            PLUGIN_DIR="$PLUGIN_BASE/openssl11"
            echo "unmask-plugin-nginx: host OpenSSL = 1.1.x ($NGINX_LIBCRYPTO), glibc=$GLIBC_VER"
            ;;
        libcrypto.so.10|libcrypto.so.1.0)
            # Separate CentOS 6 (= glibc 2.12) and CentOS 7 (= glibc 2.17).
            if [ -n "$GLIBC_VER" ] && glibc_lt_214 "$GLIBC_VER"; then
                PLUGIN_DIR="$PLUGIN_BASE/glibc212"
                echo "unmask-plugin-nginx: host OpenSSL = 1.0.x ($NGINX_LIBCRYPTO) + glibc=$GLIBC_VER < 2.14 -> CentOS 6 build path"
            else
                PLUGIN_DIR="$PLUGIN_BASE/openssl10"
                echo "unmask-plugin-nginx: host OpenSSL = 1.0.x ($NGINX_LIBCRYPTO), glibc=$GLIBC_VER"
            fi
            ;;
        *)
            echo "WARNING: unrecognized libcrypto: $NGINX_LIBCRYPTO. Trying OpenSSL 3 path." >&2
            PLUGIN_DIR="$PLUGIN_BASE/openssl3"
            ;;
    esac
else
    echo "WARNING: ldd not found, skipping OpenSSL ABI detection.  Trying the OpenSSL 3 path." >&2
    PLUGIN_DIR="$PLUGIN_BASE/openssl3"
fi

[ -d "$PLUGIN_DIR" ] || {
    echo "ERROR: plugin dir $PLUGIN_DIR does not exist.  Please verify the package contents." >&2
    exit 0
}

# ---- 1. host nginx version ----
HOST_VER=$(nginx -v 2>&1 | sed -n 's|.*nginx/\([0-9.]*\).*|\1|p')
if [ -z "$HOST_VER" ]; then
    echo "ERROR: failed to parse 'nginx -v'.  Skipping module placement." >&2
    exit 0
fi
echo "unmask-plugin-nginx: host nginx ${HOST_VER}"

# ---- 2. pick the best matching .so ----
list_versions() {
    # nginx versions bundled, newest first.
    ls -1 "$PLUGIN_DIR"/ngx_http_unmask_module-*.so 2>/dev/null | \
        sed -n 's|.*/ngx_http_unmask_module-\(.*\)\.so$|\1|p' | \
        sort -V -r
}

PICKED=""
PICK_MODE=""
# (a) exact match
if [ -f "$PLUGIN_DIR/${SO_NAME%.so}-${HOST_VER}.so" ]; then
    PICKED="${HOST_VER}"
    PICK_MODE="exact"
fi
# (b) closest in the same minor branch (= 1.18.X)
if [ -z "$PICKED" ]; then
    HOST_MAJOR_MINOR=$(echo "$HOST_VER" | awk -F. '{print $1"."$2}')
    for v in $(list_versions); do
        v_mm=$(echo "$v" | awk -F. '{print $1"."$2}')
        if [ "$v_mm" = "$HOST_MAJOR_MINOR" ]; then
            PICKED="$v"
            PICK_MODE="minor-match"
            break
        fi
    done
fi

if [ -z "$PICKED" ]; then
    cat >&2 <<EOF
================================================================
ERROR: no module compatible with host nginx ${HOST_VER} is bundled.
================================================================

Bundled versions ($PLUGIN_DIR):
EOF
    for v in $(list_versions); do echo "  - $v" >&2; done
    cat >&2 <<EOF

Mitigations:
  1) Wait for the next unmask release (= adds a .so for nginx ${HOST_VER}).
  2) Build from source on another host:
       make build-module NGINX_VERSION=${HOST_VER}
       cp dist/ngx_http_unmask_module-linux-*.so /usr/lib/nginx/modules/
  3) Skip the plugin and run in forward-auth mode (= main package alone is enough).
================================================================
EOF
    # Re-run on a host nginx upgrade to an unbundled version leaves a now-
    # ABI-incompatible .so + load_module behind, which kills nginx on next
    # start.  Strip the wiring so nginx still comes up (degraded), not dead.
    disable_unmask_module "no bundled module for host nginx ${HOST_VER}"
    exit 0
fi

case "$PICK_MODE" in
    exact)
        echo "  exact match: ngx_http_unmask_module-${PICKED}.so" ;;
    minor-match)
        echo "  closest match: ngx_http_unmask_module-${PICKED}.so (= same minor branch / assumes patch ABI compatibility)" ;;
esac

# ---- 3. extract modules-path from `nginx -V` ----
MODULES_PATH=$(nginx -V 2>&1 | tr ' ' '\n' | sed -n 's|^--modules-path=||p' | head -1)
if [ -z "$MODULES_PATH" ]; then
    cat >&2 <<EOF
ERROR: nginx -V has no --modules-path, cannot place automatically.
  Place the chosen module by hand:
    cp $PLUGIN_DIR/${SO_NAME%.so}-${PICKED}.so /usr/lib/nginx/modules/$SO_NAME
EOF
    exit 0
fi

# ---- 4. install (with an immutable-/usr fallback) ----
SRC="$PLUGIN_DIR/${SO_NAME%.so}-${PICKED}.so"
DEST=$(install_so "$SRC" "$MODULES_PATH" "$FALLBACK_SO_DIR") || {
    echo "ERROR: could not write the module to $MODULES_PATH nor $FALLBACK_SO_DIR. Skipping placement." >&2
    exit 0
}
if [ "$DEST" = "$FALLBACK_SO_DIR/$SO_NAME" ]; then
    echo "  modules-path $MODULES_PATH is not writable (immutable /usr?) -> placed under $FALLBACK_SO_DIR"
    echo "  note: SELinux-enforcing hosts may need a local label before nginx can load from there:"
    echo "        semanage fcontext -a -t lib_t '$FALLBACK_SO_DIR(/.*)?' && restorecon -R $FALLBACK_SO_DIR"
else
    # Placed at the conventional path: drop a stale fallback copy from an
    # earlier read-only phase so exactly one .so exists on the host.
    rm -f "$FALLBACK_SO_DIR/$SO_NAME" 2>/dev/null
fi

# ---- 5. selinux ----
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$DEST" 2>/dev/null || true
fi

echo "  installed: $DEST"

# ---- 7. auto-place load_module ----
# Drop into the distro-conventional main-scope include dir (=
# /etc/nginx/modules-enabled/ or /usr/share/nginx/modules/).  Otherwise
# edit nginx.conf and add the line at the top (= outside http {}).  This
# is so it works on every distro out of the box.
NGINX_CONF=/etc/nginx/nginx.conf
# Tag the directive so it's recognizable as package-managed when it lands in the
# host nginx.conf (= the no-include-dir fallback below): a config-management tool
# or operator reading nginx.conf sees it's auto-added, not a hand edit.  Removal
# still matches the module name (grep -v), so the comment rides along and goes
# with it.  One line, so no begin/end block is needed.
LOAD_LINE="load_module \"$DEST\";  # unmask-plugin-nginx: auto-added, removed on uninstall"
LOAD_DROPPED=""

if [ -r "$NGINX_CONF" ]; then
    INCLUDE_DIR=$(awk '
        /^[[:space:]]*http[[:space:]]*{/ { exit }
        /^[[:space:]]*include[[:space:]]/ {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^[/]/) { print $i; exit }
            }
        }
    ' "$NGINX_CONF" | sed 's|/\*\.conf;$||; s|;$||' | head -1)
    if [ -n "$INCLUDE_DIR" ] && [ -d "$INCLUDE_DIR" ]; then
        DROP="$INCLUDE_DIR/50-mod-unmask.conf"
        # Idempotency across FOREIGN wiring, not just our own file.  An
        # operator may already load the module themselves -- a hand-added
        # line in nginx.conf (the docs used to show exactly that) or their
        # own conf in this include dir.  This script runs before EVERY nginx
        # start via the service drop-in, so unconditionally dropping ours
        # next to theirs makes nginx -t fail with "module is already
        # loaded", and the verify fail-safe below then strips the module --
        # a self-inflicted outage on a perfectly healthy setup.  Skip (and
        # remove a stale drop of ours) when any other load_module for this
        # module exists; overwriting OUR OWN previous drop stays fine (= the
        # normal re-pick path).
        FOREIGN=""
        if grep -q "load_module.*ngx_http_unmask_module" "$NGINX_CONF" 2>/dev/null; then
            FOREIGN="$NGINX_CONF"
        else
            for f in "$INCLUDE_DIR"/*.conf; do
                [ -f "$f" ] || continue
                [ "$f" = "$DROP" ] && continue
                if grep -q "load_module.*ngx_http_unmask_module" "$f" 2>/dev/null; then
                    FOREIGN="$f"
                    break
                fi
            done
        fi
        if [ -n "$FOREIGN" ]; then
            rm -f "$DROP" 2>/dev/null
            echo "  load_module already present in $FOREIGN (= operator-managed; idempotent skip)"
        else
            echo "$LOAD_LINE" > "$DROP"
            chmod 0644 "$DROP"
            # SELinux: a file created by this script in the include dir can land
            # with the wrong type; relabel it so nginx (httpd_t) can read it.
            command -v restorecon >/dev/null 2>&1 && restorecon -F "$DROP" 2>/dev/null || true
            echo "  load_module conf: $DROP"
        fi
        LOAD_DROPPED=1
    fi
fi

if [ -z "$LOAD_DROPPED" ] && [ -w "$NGINX_CONF" ]; then
    # No main-scope include dir found (= e.g. CentOS 6 nginx.org 1.18) ->
    # edit nginx.conf directly and idempotently add load_module at the
    # top.
    if ! grep -q "load_module.*ngx_http_unmask_module" "$NGINX_CONF"; then
        # Insert at the very top of nginx.conf (= keep existing lines,
        # add load_module as line 1).
        # Atomic edit: build the new file in a sibling tmp + rename(2) so a
        # SIGKILL / power loss between truncate and write doesn't leave
        # nginx.conf empty or half-written (= next `nginx -t` would die).
        tmp="$NGINX_CONF.tmp.$$"
        {
            echo "$LOAD_LINE"
            cat "$NGINX_CONF"
        } > "$tmp" && {
            chmod 0644 "$tmp"
            mv -f "$tmp" "$NGINX_CONF"
            echo "  load_module added to: $NGINX_CONF (= at the top of main scope)"
            LOAD_DROPPED=1
        } || rm -f "$tmp"
    elif grep -qF "load_module \"$DEST\"" "$NGINX_CONF"; then
        echo "  load_module already present in $NGINX_CONF (= idempotent skip)"
        LOAD_DROPPED=1
    else
        # A line exists but points at a different .so path — the module moved
        # between the modules path and the immutable-/usr fallback dir.
        # Replace it, or nginx keeps loading a stale copy that can be
        # ABI-incompatible after the next host-nginx upgrade.
        tmp="$NGINX_CONF.tmp.$$"
        {
            echo "$LOAD_LINE"
            grep -v 'load_module.*ngx_http_unmask_module' "$NGINX_CONF"
        } > "$tmp" && {
            chmod 0644 "$tmp"
            mv -f "$tmp" "$NGINX_CONF"
            echo "  load_module path updated in: $NGINX_CONF (-> $DEST)"
        } || rm -f "$tmp"
        LOAD_DROPPED=1
    fi
fi

if [ -z "$LOAD_DROPPED" ]; then
    echo ""
    echo "  WARNING: could not auto-place load_module.  Add this by hand:"
    echo "             at the top of $NGINX_CONF (= outside http {})"
    echo "               $LOAD_LINE"
fi

# Wire http.inc into http {} scope now that the native plugin .so is present.
# unmask-web-nginx also creates this symlink (gated on the .so), so doing it here
# too makes install order between the two packages irrelevant; http.inc carries
# the C-module directives + plugin-variable maps that only load with this .so.
if [ -e "$DEST" ]; then
    PINCDIR=/etc/nginx/conf.d
    if [ -d /etc/nginx/http.d ] && [ -r /etc/nginx/nginx.conf ] && awk '
        /^[[:space:]]*http[[:space:]]*\{/ { in_http=1 }
        in_http && /include[[:space:]]+\/etc\/nginx\/http\.d\// { found=1 }
        /^\}/ { in_http=0 }
        END { exit !found }' /etc/nginx/nginx.conf; then
        PINCDIR=/etc/nginx/http.d
    fi
    mkdir -p "$PINCDIR" /var/lib/unmask/nginx
    PSRC=/var/lib/unmask/nginx/http.inc
    PLINK=$PINCDIR/00-unmask.conf
    [ -e "$PSRC" ] || : > "$PSRC"
    if [ ! -e "$PLINK" ] || { [ -L "$PLINK" ] && [ "$(readlink "$PLINK")" != "$PSRC" ]; }; then
        ln -sf "$PSRC" "$PLINK"
        echo "  http.inc auto-load symlinked: $PLINK -> $PSRC"
    fi
fi

# Final gate: now that the .so + load_module + http.inc are wired, make sure the
# result actually loads.  If unmask broke `nginx -t` (bad render, missing map,
# ABI surprise), strip the wiring so nginx still starts; a non-unmask failure is
# left for the operator.
verify_or_disable

echo ""
echo "next steps (= on the nginx side):"
echo "  1. (web-nginx package handles 'include /var/lib/unmask/nginx/http.inc' via a symlink)"
echo "  2. Confirm 'nginx -t' passes, then reload."

exit 0
