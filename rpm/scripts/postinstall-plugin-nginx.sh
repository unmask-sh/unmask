#!/bin/sh
# postinstall for unmask-plugin-nginx.
#
# Copy from the staging path (/usr/share/unmask/plugin/ngx_http_unmask_module.so)
# to the location specified by the host nginx's `--modules-path=`.  Extracted
# from nginx -V output.  On failure, instruct the user to place it manually.

STAGING=/usr/share/unmask/plugin/ngx_http_unmask_module.so
SO_NAME=ngx_http_unmask_module.so

if ! command -v nginx >/dev/null 2>&1; then
    echo "WARNING: nginx command not found.  module staged at ${STAGING}." >&2
    echo "         Install nginx, then manually copy to the modules-path in your config." >&2
    exit 0
fi

# Extract --modules-path=<path> from nginx -V's configure arguments.
# Example:  --modules-path=/usr/lib64/nginx/modules
MODULES_PATH=$(nginx -V 2>&1 | tr ' ' '\n' | sed -n 's|^--modules-path=||p' | head -1)

if [ -z "$MODULES_PATH" ]; then
    # Old nginx (= below 1.9.11) lacks --modules-path = dynamic modules unsupported.
    # preinstall already validated the nginx version, so this branch is unexpected; defensive.
    echo "ERROR: --modules-path not found in nginx -V (= nginx without dynamic-module support)." >&2
    echo "       module staged at ${STAGING}.  Place manually or install a newer nginx." >&2
    exit 0
fi

echo "unmask-plugin-nginx: nginx's modules-path is ${MODULES_PATH}"

if [ ! -d "$MODULES_PATH" ]; then
    mkdir -p "$MODULES_PATH"
    echo "  created: $MODULES_PATH"
fi

DEST="$MODULES_PATH/$SO_NAME"
# Atomic install: write to a sibling tmp + rename(2) so a running nginx
# worker that still mmaps the old .so doesn't hit ETXTBSY mid-upgrade, and
# a SIGKILL during the copy can't leave a half-written .so on disk.
tmp_so="$DEST.tmp.$$"
cp -f "$STAGING" "$tmp_so"
chmod 0644 "$tmp_so"
mv -f "$tmp_so" "$DEST"

# On SELinux hosts, apply the right context so nginx can load the module.
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$DEST" 2>/dev/null || true
fi

echo "  installed: $DEST"

# ---------------------------------------------------------------------------
# Auto-install load_module — drop a load .conf into the dir the distro's
# nginx package includes at main scope.  Distro conventions:
#   - nginx official RPM (= rhel/centos):  /usr/share/nginx/modules/*.conf
#   - Debian/Ubuntu nginx package:         /etc/nginx/modules-enabled/*.conf
# Grep nginx.conf to find the include target (= fall back to writing into
# nginx.conf directly if needed).  The dropped .conf is treated as config —
# upgrade will not overwrite it.
# ---------------------------------------------------------------------------
NGINX_CONF=/etc/nginx/nginx.conf
LOAD_LINE="load_module \"$DEST\";"
LOAD_DROPPED=""

if [ -r "$NGINX_CONF" ]; then
    # Extract main-scope *.conf include dirs from nginx.conf's include lines
    # (= exclude includes inside http {}.  awk scans only up to the first http {).
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

if [ -z "$LOAD_DROPPED" ]; then
    # Could not auto-drop → instruct the user to add manually.
    echo ""
    echo "  WARNING: could not auto-place load_module (= no main-scope include dir found;"
    echo "           non-standard for this distro's nginx package).  Add manually:"
    echo "             At the top of $NGINX_CONF (= outside http {})"
    echo "               $LOAD_LINE"
fi

# NOTE: this thin plugin variant deliberately does NOT drop an include for the
# rendered JA4 maps.  The unmask-web-nginx package already symlinks the real
# rendered file (= /var/lib/unmask/nginx/http.inc) into http {} scope as
# /etc/nginx/conf.d/00-unmask.conf, so a second include here is redundant -- and
# the old /etc/unmask/nginx-rendered.conf path this block used was retired
# (= render-nginx now writes http.inc), so the include pointed at a file that is
# never produced and made `nginx -t` fail on every install.  Matches
# postinstall-plugin-nginx-fat.sh, which has no such block.

echo ""
echo "next steps:"
echo "  sudo dnf install unmask-web-nginx       (= installs the /unmask/* proxy + upstream)"
echo "  sudo nginx -t && sudo systemctl reload nginx"

exit 0
