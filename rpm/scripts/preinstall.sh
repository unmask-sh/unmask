#!/bin/sh
# unmask system user / group を作成する (= service 起動用).
set -eu

if ! getent group unmask >/dev/null 2>&1; then
    groupadd --system unmask
fi
if ! getent passwd unmask >/dev/null 2>&1; then
    useradd --system \
            --gid unmask \
            --no-create-home \
            --home-dir /var/lib/unmask \
            --shell /sbin/nologin \
            --comment "unmask admin" \
            unmask
fi
