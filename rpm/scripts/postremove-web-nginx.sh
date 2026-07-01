#!/bin/sh
# unmask-web-nginx postremove.  After the conf.d snippet is removed, prompt to reload nginx.
# We do NOT auto-reload (= the file may still exist via rpm/deb type=config|noreplace).

# Remove the symlinks the postinstall created (= prevents dangling links), but
# ONLY on a genuine uninstall — not on upgrade/reinstall.  rpm runs the OLD
# package's %postun *after* the new package's %post during an upgrade, so an
# unconditional rm here would delete the symlinks the new %post just created.
# rpm passes $1=0 on final removal ($1>=1 on upgrade); dpkg passes
# "remove"/"purge" on removal and "upgrade" on upgrade.
# Decide whether this invocation is a real removal (= clean symlinks) or an
# upgrade / reinstall (= keep them so the new %post-created links are not
# nuked).  Argument conventions vary:
#   rpm:   $1 = "0" on final remove, "1..." on upgrade
#   dpkg:  $1 = "remove" / "purge" on remove, "upgrade" on upgrade
#   apk:   $1 = the package version string (= "0.1.0"); there is no built-in
#          upgrade distinction at this hook since apk has separate pre/post-
#          upgrade hooks, so post-deinstall here always means uninstall.
do_cleanup=0
if [ -d /lib/apk ]; then
    # apk hosts: post-deinstall is uninstall-only by spec.
    do_cleanup=1
else
    case "${1:-}" in
        0|remove|purge) do_cleanup=1 ;;
    esac
fi

if [ "$do_cleanup" = 1 ]; then
    rm -f /etc/nginx/conf.d/00-unmask-maphash.conf /etc/nginx/http.d/00-unmask-maphash.conf
    sed -i '/unmask-maphash/d' /etc/nginx/nginx.conf 2>/dev/null || true
    for link in /etc/nginx/conf.d/00-unmask.conf \
                /etc/nginx/conf.d/00-unmask-upstream.conf \
                /etc/nginx/conf.d/zz-unmask-fa-lbtrust.conf \
                /etc/nginx/conf.d/00-unmask-fa-lbtrust.conf \
                /etc/nginx/conf.d/00-unmask-rendered.conf \
                /etc/nginx/http.d/00-unmask.conf \
                /etc/nginx/http.d/00-unmask-upstream.conf \
                /etc/nginx/http.d/zz-unmask-fa-lbtrust.conf \
                /etc/nginx/http.d/00-unmask-fa-lbtrust.conf \
                /etc/nginx/http.d/00-unmask-rendered.conf; do
        if [ -L "$link" ]; then
            rm -f "$link"
        fi
    done
fi

if command -v nginx >/dev/null 2>&1; then
    echo "unmask-web-nginx: snippet removed.  remember to:"
    echo "  sudo nginx -s reload"
fi

exit 0
