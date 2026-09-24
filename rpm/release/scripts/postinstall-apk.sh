#!/bin/sh
# unmask-release postinstall (apk).
#
# Distribution uses a single path / single channel:
#   https://unmask.sh/dl/apk/main/{x86_64,aarch64}/APKINDEX.tar.gz
# apk-tools only reads `/etc/apk/repositories` (= a single file).  The zypper-style
# `/etc/apk/repositories.d/` does not apply.  Append the unmask line there.
#
# Note: do not use `set -e`.  This script has no abort requirement, and busybox
# ash's `if ! cmd` interaction can silently abort (= same pattern as 17:39 / 18:00
# [A]); printing a warning and continuing is the design that avoids blocking
# apk install.
#
# To prevent duplicate appends, branch on the result of `grep -Fxq` via a
# variable (= avoids `if !`).

REPO_FILE=/etc/apk/repositories
LINE="https://unmask.sh/dl/apk/main"

mkdir -p "$(dirname "$REPO_FILE")" 2>/dev/null || true
[ -e "$REPO_FILE" ] || : > "$REPO_FILE"

already=0
grep -Fxq "$LINE" "$REPO_FILE" 2>/dev/null && already=1
if [ "$already" = 0 ]; then
    echo "$LINE" >> "$REPO_FILE"
fi

# Pre-release channel.  Left OUT of this file on purpose: apk has no
# enabled=0, so a line here would be live, and an ordinary `apk upgrade` would
# start pulling pre-releases.  apk's equivalent of "only when asked" is a
# per-command flag, which needs no configuration at all and leaves no state to
# undo:
#
#   apk upgrade --repository https://unmask.sh/dl/testing/apk/main
#
# upgrade, not add: `apk add` on a package that is already installed changes
# nothing, which is every reporter's situation -- the earlier wording of this
# note installed nothing at all for them.  upgrade also moves the companion
# packages with it, which their exact-version pins require.
#
# The signing key is already installed by this package and is shared by both
# channels, so nothing further is needed.  The note goes in the file because
# that is where somebody looks when asked to try a build.
NOTE="# unmask pre-release builds are NOT enabled here -- to try one: apk upgrade --repository https://unmask.sh/dl/testing/apk/main"
# The note this package used to write.  Replace it rather than add beside it:
# the old command is the one that does nothing on an existing install.
OLD_NOTE="# unmask pre-release builds are NOT enabled here -- to try one: apk add --repository https://unmask.sh/dl/testing/apk/main unmask"
if grep -Fxq "$OLD_NOTE" "$REPO_FILE" 2>/dev/null; then
    grep -vFx "$OLD_NOTE" "$REPO_FILE" > "$REPO_FILE.unmask.$$" && cat "$REPO_FILE.unmask.$$" > "$REPO_FILE"
    rm -f "$REPO_FILE.unmask.$$"
fi
noted=0
grep -Fxq "$NOTE" "$REPO_FILE" 2>/dev/null && noted=1
if [ "$noted" = 0 ]; then
    echo "$NOTE" >> "$REPO_FILE"
fi

exit 0
