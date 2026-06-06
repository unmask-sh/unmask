#!/bin/sh
# preremove for unmask-plugin-nginx.
# Removes the module file that postinstall copied.  Skipped on upgrade ($1=1)
# (= the new version overwrites the same path).

# Only on a genuine removal.  rpm: $1="0"; dpkg: $1="remove".  apk passes the
# package version string as $1, and nfpm wires this as apk's pre-deinstall hook
# (= uninstall-only by spec, upgrades use a separate pre-upgrade hook), so on
# Alpine this is always a removal -- detect it via /lib/apk (= same idiom as
# postremove.sh).  Without this, `apk del unmask-plugin-nginx` would leave the
# .so and the load_module .conf behind.
do_remove=0
if [ -d /lib/apk ]; then
    do_remove=1
else
    case "${1:-0}" in
        0|remove) do_remove=1 ;;
    esac
fi
[ "$do_remove" = 1 ] || exit 0

if ! command -v nginx >/dev/null 2>&1; then
    exit 0
fi

MODULES_PATH=$(nginx -V 2>&1 | tr ' ' '\n' | sed -n 's|^--modules-path=||p' | head -1)
if [ -z "$MODULES_PATH" ]; then
    exit 0
fi

DEST="$MODULES_PATH/ngx_http_unmask_module.so"
if [ -f "$DEST" ]; then
    rm -f "$DEST"
    echo "unmask-plugin-nginx: removed $DEST"
fi

# Remove the auto load_module .conf dropped by postinstall.  Several candidate
# paths depending on the distro.
for f in /usr/share/nginx/modules/50-mod-unmask.conf \
         /etc/nginx/modules-enabled/50-mod-unmask.conf \
         /etc/nginx/modules-available/50-mod-unmask.conf; do
    if [ -f "$f" ]; then
        rm -f "$f"
        echo "unmask-plugin-nginx: removed $f"
    fi
done

# Remove the auto-dropped include for rendered.conf as well.
if [ -f /etc/nginx/conf.d/10-unmask-rendered.conf ]; then
    rm -f /etc/nginx/conf.d/10-unmask-rendered.conf
    echo "unmask-plugin-nginx: removed /etc/nginx/conf.d/10-unmask-rendered.conf"
fi

echo "unmask-plugin-nginx: removal complete.  run 'nginx -t && systemctl reload nginx' to apply."

exit 0
