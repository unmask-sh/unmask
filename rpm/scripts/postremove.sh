#!/bin/sh
# The user / data dir is removed only on purge.
# Distinguishes rpm full-remove ($1 = 0) from dpkg purge ($1 = "purge").

case "${1:-}" in
    0|purge)
        # Data is kept (= recovery scenarios).  User removal is left to the operator.
        # The systemd drop-in placed by postinst is removed (= on full remove only).
        rm -rf /etc/systemd/system/unmask-admin.service.d 2>/dev/null || true
        ;;
esac

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

exit 0
