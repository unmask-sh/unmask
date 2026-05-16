#!/bin/sh
# main-package preinstall for alpine (= busybox).
# Creates the user / group only.  alpine doesn't ship shadow-utils' groupadd/useradd,
# so we use busybox's addgroup/adduser (= preinstall-main-deb.sh does the equivalent for deb).
#
# Note: avoid `set -eu` + `if !` interaction aborts by skipping set -e and using
# variable-mediated tests (= same pattern as 2026-05-10 22:14 JST [B]; safe under
# apk-tools v3's sanitized-env hooks too).

grp_exists=0
getent group unmask >/dev/null 2>&1 && grp_exists=1
if [ "$grp_exists" = 0 ]; then
    addgroup -S unmask
fi

usr_exists=0
getent passwd unmask >/dev/null 2>&1 && usr_exists=1
if [ "$usr_exists" = 0 ]; then
    adduser -S -D -H \
            -G unmask \
            -h /var/lib/unmask \
            -s /sbin/nologin \
            -g "unmask admin" \
            unmask
fi

exit 0
