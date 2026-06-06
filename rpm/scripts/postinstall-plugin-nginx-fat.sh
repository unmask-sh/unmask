#!/bin/sh
# postinstall for unmask-plugin-nginx (fat).
#
# Flow:
#   1. Get the host nginx version (= X.Y.Z) from `nginx -v`.
#   2. Look up the host nginx's libcrypto dependency to determine the
#      OpenSSL ABI (= 1.1 or 3).
#   3. Find /usr/share/unmask/plugin/{openssl11,openssl3}/ngx_http_unmask_module-X.Y.Z.so:
#      (a) exact match (= e.g. host 1.18.0 -> -1.18.0.so under the matching ABI dir)
#      (b) closest within the same minor branch (= host 1.18.4 -> -1.18.0.so, assuming patch ABI compatibility)
#      (c) none -> print "supported versions" and exit 0 (= don't treat as a failure)
#   4. Extract --modules-path= from `nginx -V`.
#   5. Copy the chosen .so to $modules_path/ngx_http_unmask_module.so.
#   6. restorecon if selinux is in use.

PLUGIN_BASE=/usr/share/unmask/plugin
SO_NAME=ngx_http_unmask_module.so

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

if command -v ldd >/dev/null 2>&1; then
    NGINX_BIN=$(command -v nginx)
    NGINX_LIBCRYPTO=$(ldd "$NGINX_BIN" 2>/dev/null | sed -n 's|.*\(libcrypto\.so\.[0-9.]*\).*|\1|p' | head -1)
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

[ -d "$MODULES_PATH" ] || mkdir -p "$MODULES_PATH"

# ---- 4. cp ----
SRC="$PLUGIN_DIR/${SO_NAME%.so}-${PICKED}.so"
DEST="$MODULES_PATH/$SO_NAME"
cp -f "$SRC" "$DEST"
chmod 0644 "$DEST"

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
LOAD_LINE="load_module \"$DEST\";"
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
        echo "$LOAD_LINE" > "$DROP"
        chmod 0644 "$DROP"
        echo "  load_module conf: $DROP"
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
        tmp=$(mktemp) && {
            echo "$LOAD_LINE" > "$tmp"
            cat "$NGINX_CONF" >> "$tmp"
            cat "$tmp" > "$NGINX_CONF"
            rm -f "$tmp"
            echo "  load_module added to: $NGINX_CONF (= at the top of main scope)"
            LOAD_DROPPED=1
        }
    else
        echo "  load_module already present in $NGINX_CONF (= idempotent skip)"
        LOAD_DROPPED=1
    fi
fi

if [ -z "$LOAD_DROPPED" ]; then
    echo ""
    echo "  WARNING: could not auto-place load_module.  Add this by hand:"
    echo "             at the top of $NGINX_CONF (= outside http {})"
    echo "               $LOAD_LINE"
fi

echo ""
echo "next steps (= on the nginx side):"
echo "  1. (web-nginx package handles 'include /etc/unmask/http.inc' via a symlink)"
echo "  2. Confirm 'nginx -t' passes, then reload."

exit 0
