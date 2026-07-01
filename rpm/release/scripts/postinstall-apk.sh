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

exit 0
