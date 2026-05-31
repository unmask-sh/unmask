#!/bin/sh
# systemd-based: stop+disable only on full remove.  Leave alone during upgrade.
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    if [ "${1:-}" = "0" ] || [ "${1:-}" = "remove" ]; then
        systemctl disable --now unmask.service || true
    fi
elif command -v rc-service >/dev/null 2>&1 || [ -x /sbin/openrc-run ]; then
    # OpenRC (= Alpine).  On full remove: stop + rc-update del + delete symlink.
    if [ "${1:-}" = "0" ] || [ "${1:-}" = "remove" ]; then
        rc-service unmask stop 2>/dev/null || true
        rc-update del unmask default 2>/dev/null || true
        rm -f /etc/init.d/unmask
    fi
fi

exit 0
