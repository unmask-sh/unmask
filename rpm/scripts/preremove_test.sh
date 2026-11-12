#!/bin/bash
# Test for preremove.sh: what a removal leaves for the install after it.
#
# A deb that is removed (not purged) keeps its configuration, and dpkg calls
# the next install's postinst as `configure <the version removed>` -- exactly
# as it calls an upgrade.  postinstall.sh does not enable the unit on an
# upgrade (the operator may have disabled it), and preremove.sh disabled it
# at the removal: after a remove and a reinstall the daemon ran, and did not
# come back at the next boot.  So the removal leaves a mark in the unit's
# drop-in directory, which postinstall.sh reads (postinstall_test.sh has that
# half).  rpm leaves none: its reinstall is a fresh install.
#
# The script is run for real against a throwaway root, with a stand-in
# systemctl that records its calls.  No VM, no root.
#
# Run: bash rpm/scripts/preremove_test.sh
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
fails=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails+1)); }
check() { # <desc> <expected> <actual>
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected=\"$2\" got=\"$3\")"; fi
}

# run_case <drop-in dir there: 0|1> <args...>
run_case() {
    local dropin="$1"; shift
    T=$(mktemp -d)
    mkdir -p "$T/stub" "$T/tools" "$T/run/systemd/system" "$T/etc/systemd/system"
    [ "$dropin" = 1 ] && mkdir -p "$T/etc/systemd/system/unmask.service.d"
    : > "$T/calls.log"
    printf '#!/bin/sh\necho "systemctl $*" >> "%s/calls.log"\nexit 0\n' "$T" > "$T/stub/systemctl"
    chmod +x "$T/stub/systemctl"
    ln -s "$(command -v rm)" "$T/tools/rm"
    sed -e "s|/etc/systemd/system|$T/etc/systemd/system|g" \
        -e "s|/run/systemd/system|$T/run/systemd/system|g" \
        -e "s|/etc/rc.d/init.d|$T/etc/rc.d/init.d|g" \
        -e "s|/etc/init.d|$T/etc/init.d|g" \
        -e "s|/lib/apk|$T/lib/apk|g" \
        -e "s|/sbin/openrc-run|$T/sbin/openrc-run|g" \
        "$DIR/preremove.sh" > "$T/preremove.sh"
    PATH="$T/stub:$T/tools" /bin/sh "$T/preremove.sh" "$@" > "$T/out" 2>&1
    RC=$?
}
called() { grep -cE "$1" "$T/calls.log"; }
mark() { [ -e "$T/etc/systemd/system/unmask.service.d/.disabled-by-remove" ] && echo yes || echo no; }

run_case 1 remove
check "deb remove: exit 0" 0 "$RC"
check "deb remove: the unit is stopped and disabled" 1 "$(called '^systemctl disable --now unmask.service$')"
check "deb remove: the mark is left for the next install" yes "$(mark)"
rm -rf "$T"

run_case 1 upgrade 0.1.57-1
check "deb upgrade: the unit is left alone" 0 "$(called '^systemctl ')"
check "deb upgrade: no mark" no "$(mark)"
rm -rf "$T"

run_case 1 0
check "rpm erase: the unit is stopped and disabled" 1 "$(called '^systemctl disable --now unmask.service$')"
check "rpm erase: no mark (a reinstall is a fresh install there)" no "$(mark)"
rm -rf "$T"

run_case 1 1
check "rpm upgrade: the unit is left alone" 0 "$(called '^systemctl ')"
check "rpm upgrade: no mark" no "$(mark)"
rm -rf "$T"

run_case 0 remove
check "deb remove with no drop-in directory: exit 0" 0 "$RC"
check "deb remove with no drop-in directory: still disabled" 1 "$(called '^systemctl disable --now unmask.service$')"
check "deb remove with no drop-in directory: none is made for the mark" no "$([ -d "$T/etc/systemd/system/unmask.service.d" ] && echo yes || echo no)"
rm -rf "$T"

echo
if [ "$fails" -eq 0 ]; then echo "preremove_test: all passed"; else echo "preremove_test: $fails FAILED"; exit 1; fi
