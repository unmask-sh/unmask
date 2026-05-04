#!/bin/sh
# user / data dir は purge 時のみ削除する.
# rpm 完全 remove ($1 = 0) / dpkg purge ($1 = "purge") を区別.
set -eu

case "${1:-}" in
    0|purge)
        # data は残す方針 (= 復旧運用のため). user 削除は手動でやる.
        :
        ;;
esac

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi
