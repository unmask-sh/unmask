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
        # dpkg keeps a removed package's configuration, and at the next
        # install calls the postinst as `configure <the version removed>` --
        # the way it calls an upgrade, which must not enable a unit the
        # operator may have disabled.  The mark says this disable was the
        # package's own, so that install enables the unit again
        # (postinstall.sh); without it the daemon ran after a remove and a
        # reinstall, and did not come back at the next boot.  In the unit's
        # drop-in directory: root's, kept by a remove, gone with a purge.
        # rpm needs none: its reinstall is a fresh install.
        if [ "${1:-}" = "remove" ] && [ -d /etc/systemd/system/unmask.service.d ]; then
            : > /etc/systemd/system/unmask.service.d/.disabled-by-remove 2>/dev/null || true
        fi
    elif command -v rc-service >/dev/null 2>&1 || [ -x /sbin/openrc-run ]; then
        # OpenRC (= Alpine).  stop + rc-update del + delete the symlink.
        rc-service unmask stop 2>/dev/null || true
        rc-update del unmask default 2>/dev/null || true
        rm -f /etc/init.d/unmask
    elif command -v chkconfig >/dev/null 2>&1 && [ -f /etc/rc.d/init.d/unmask ]; then
        # SysVinit (= RHEL 6 / CentOS 6).  stop + chkconfig --del + remove script.
        service unmask stop 2>/dev/null || /etc/rc.d/init.d/unmask stop 2>/dev/null || true
        chkconfig --del unmask 2>/dev/null || true
        rm -f /etc/rc.d/init.d/unmask
        # The log rotation postinstall put in place, while it still carries
        # the package's first line; an operator's own file stays.
        if grep -q '^# unmask: installed by the package' /etc/logrotate.d/unmask 2>/dev/null; then
            rm -f /etc/logrotate.d/unmask
        fi
    fi
fi

exit 0
