#!/bin/sh
set -eu
if command -v systemctl >/dev/null 2>&1; then
    # 完全 remove のときだけ stop+disable. upgrade 時は据え置き.
    if [ "${1:-}" = "0" ] || [ "${1:-}" = "remove" ]; then
        systemctl disable --now unmask-aggregate.timer || true
        systemctl disable --now unmask-admin.service || true
    fi
fi
