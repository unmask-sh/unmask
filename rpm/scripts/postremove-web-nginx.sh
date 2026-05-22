#!/bin/sh
# unmask-web-nginx postremove.  After the conf.d snippet is removed, prompt to reload nginx.
# We do NOT auto-reload (= the file may still exist via rpm/deb type=config|noreplace).

# Remove the symlinks the postinstall created (= prevents dangling links), but
# ONLY on a genuine uninstall — not on upgrade/reinstall.  rpm runs the OLD
# package's %postun *after* the new package's %post during an upgrade, so an
# unconditional rm here would delete the symlinks the new %post just created.
# rpm passes $1=0 on final removal ($1>=1 on upgrade); dpkg passes
# "remove"/"purge" on removal and "upgrade" on upgrade.
case "${1:-}" in
    0|remove|purge)
        for link in /etc/nginx/conf.d/00-unmask.conf \
                    /etc/nginx/conf.d/00-unmask-upstream.conf \
                    /etc/nginx/conf.d/00-unmask-rendered.conf; do
            if [ -L "$link" ]; then
                rm -f "$link"
            fi
        done
        ;;
esac

if command -v nginx >/dev/null 2>&1; then
    echo "unmask-web-nginx: snippet removed.  remember to:"
    echo "  sudo nginx -s reload"
fi

exit 0
