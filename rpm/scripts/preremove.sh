#!/bin/sh
# Stop + disable the service, but ONLY on a genuine removal -- leave it running
# during an upgrade.  Argument conventions differ by packager:
#   rpm:  $1 = "0" on final remove, "1..." on upgrade
#   dpkg: $1 = "remove" on removal, "upgrade" on upgrade
#   apk:  $1 = the package version string.  nfpm wires this script as apk's
#         pre-deinstall hook, which by spec runs on uninstall only (= upgrades
#         use a separate pre-upgrade hook), so on Alpine this is always a real
#         removal.  Detect Alpine via /lib/apk (= same idiom as postremove.sh).
do_remove=0
if [ -d /lib/apk ]; then
    do_remove=1
else
    case "${1:-}" in
        0|remove) do_remove=1 ;;
    esac
fi

if [ "$do_remove" = 1 ]; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        systemctl disable --now unmask.service || true
    elif command -v rc-service >/dev/null 2>&1 || [ -x /sbin/openrc-run ]; then
        # OpenRC (= Alpine).  stop + rc-update del + delete the symlink.
        rc-service unmask stop 2>/dev/null || true
        rc-update del unmask default 2>/dev/null || true
        rm -f /etc/init.d/unmask
    fi
fi

exit 0
