#!/bin/sh
# The user / data dir is removed only on purge.
# Distinguishes rpm full-remove ($1 = 0) from dpkg purge ($1 = "purge").

# Decide whether this is a real removal (apk passes the version string instead
# of "0"/"purge", so plain case-matching misses Alpine -- see the parallel
# logic in postremove-web-nginx.sh).
do_cleanup=0
if [ -d /lib/apk ]; then
    do_cleanup=1
else
    case "${1:-}" in
        0|purge) do_cleanup=1 ;;
    esac
fi

if [ "$do_cleanup" = 1 ]; then
    # Data is kept (= recovery scenarios).  User removal is left to the operator.
    # The systemd drop-in placed by postinst is removed (= on full remove only).
    rm -rf /etc/systemd/system/unmask-admin.service.d 2>/dev/null || true
    # OpenRC: postinstall symlinks /etc/init.d/unmask-admin -> the openrc init
    # script under /usr/share/unmask/init/.  apk's package manager won't touch
    # the symlink because it isn't owned by the package; clear it here so a
    # rerun of `apk add unmask` (or any later remove cycle) starts clean.
    if [ -L /etc/init.d/unmask-admin ]; then
        rm -f /etc/init.d/unmask-admin
    fi
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

exit 0
