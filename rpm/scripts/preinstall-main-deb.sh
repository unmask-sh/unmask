#!/bin/sh
# deb-specific preinstall for the unmask main package.
# Uses the Debian-idiomatic `adduser --system` / `addgroup --system` (= avoids
# useradd / groupadd behavior drift on deb. Addresses the status=216/GROUP
# activating loop observed in an earlier e2e run).
#
# Note: avoid `set -eu` + `if !` interaction aborts on old dash / busybox sh
# (= same pattern as the 2026-05-10 22:14 JST [B] report) by skipping set -e and
# using variable-mediated tests.  preinst has no abort requirement (= group/user
# creation is idempotent).

grp_exists=0
getent group unmask >/dev/null 2>&1 && grp_exists=1
if [ "$grp_exists" = 0 ]; then
    addgroup --system unmask
fi

usr_exists=0
getent passwd unmask >/dev/null 2>&1 && usr_exists=1
if [ "$usr_exists" = 0 ]; then
    adduser --system \
            --ingroup unmask \
            --no-create-home \
            --home /var/lib/unmask \
            --shell /sbin/nologin \
            --gecos "unmask admin" \
            unmask
fi

exit 0
