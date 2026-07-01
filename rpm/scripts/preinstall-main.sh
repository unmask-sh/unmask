#!/bin/sh
# preinstall for the unmask main package.
# Creates the user / group only.  nginx version checks are left to the plugin side.

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

exit 0
