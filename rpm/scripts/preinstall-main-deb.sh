#!/bin/sh
# deb-specific preinstall for the unmask main package.
# Uses the Debian-idiomatic `adduser --system` / `addgroup --system` (= avoids
# useradd / groupadd behavior drift on deb. Addresses the status=216/GROUP
# activating loop observed in an earlier e2e run).
#
# adduser is not part of a minimal Debian 13 / Ubuntu 24.04 system (a
# container, some cloud images).  There this script printed "addgroup: not
# found", exited 0, and left an install apt called successful whose daemon
# could not start for want of its user.  Without adduser the account is made
# with groupadd / useradd (passwd, which those systems do have), and an
# install that still ends up without the user stops here, where apt reports
# it, instead of going on to a postinstall that chowns to nobody.
#
# Note: avoid `set -eu` + `if !` interaction aborts on old dash / busybox sh
# (= same pattern as the 2026-05-10 22:14 JST [B] report) by skipping set -e and
# using variable-mediated tests.

have() { command -v "$1" >/dev/null 2>&1; }

grp_exists=0
getent group unmask >/dev/null 2>&1 && grp_exists=1
if [ "$grp_exists" = 0 ]; then
    if have addgroup; then
        addgroup --system unmask
    else
        groupadd --system unmask
    fi
fi

usr_exists=0
getent passwd unmask >/dev/null 2>&1 && usr_exists=1
if [ "$usr_exists" = 0 ]; then
    if have adduser; then
        adduser --system \
                --ingroup unmask \
                --no-create-home \
                --home /var/lib/unmask \
                --shell /sbin/nologin \
                --gecos "unmask admin" \
                unmask
    else
        useradd --system \
                --gid unmask \
                --no-create-home \
                --home-dir /var/lib/unmask \
                --shell /sbin/nologin \
                --comment "unmask admin" \
                unmask
    fi
fi

usr_exists=0
getent passwd unmask >/dev/null 2>&1 && usr_exists=1
if [ "$usr_exists" = 0 ]; then
    echo "unmask: the 'unmask' system user could not be created (tried adduser, then useradd)." >&2
    echo "        Install the adduser package and install unmask again." >&2
    exit 1
fi

exit 0
