#!/bin/sh
# unmask-web-apache postremove.
#
# On Debian-family the postinstall ran `a2enconf unmask-web`, which drops a
# symlink under /etc/apache2/conf-enabled/.  dpkg removes only the packaged
# conf-available file, so without an a2disconf here the dangling symlink
# survives the removal — harmless on apache >= 2.4.52 (IncludeOptional
# tolerates it) but it breaks `apachectl configtest` on older releases and is
# inconsistent with the nginx postremove, which does clean its symlinks.
#
# Cleanup runs ONLY on a genuine uninstall, mirroring postremove-web-nginx.sh:
#   rpm:   $1 = "0" on final remove, "1..." on upgrade
#   dpkg:  $1 = "remove" / "purge" on removal, "upgrade" on upgrade
#   apk:   post-deinstall only ever runs at uninstall (upgrades use the
#          dedicated pre/post-upgrade hooks)
do_cleanup=0
if [ -d /lib/apk ]; then
    do_cleanup=1
else
    case "${1:-}" in
        0|remove|purge) do_cleanup=1 ;;
    esac
fi

if [ "$do_cleanup" = 1 ]; then
    if command -v a2disconf >/dev/null 2>&1; then
        a2disconf unmask-web >/dev/null 2>&1 || true
    fi
    # Belt-and-suspenders for hosts where a2disconf is unavailable but the
    # postinstall (or an operator) linked the conf by hand.
    rm -f /etc/apache2/conf-enabled/unmask-web.conf
fi

if command -v apachectl >/dev/null 2>&1; then
    echo "unmask-web-apache: snippet removed.  remember to:"
    echo "  sudo apachectl graceful"
fi
exit 0
