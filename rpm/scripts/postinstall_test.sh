#!/bin/bash
# Test for postinstall.sh: how it (re)starts the daemon, and the schema notice.
#
# Two things an install cannot show you until it is too late to matter:
#
#   - The daemon must be started ONCE.  It applies pending migrations when it
#     starts, so the old "start, then restart to be sure" began a slow
#     migration, killed it part way and began it again.
#   - When the new daemon is going to leave a schema update for the operator,
#     the upgrade has to say so, and as the LAST thing it prints.
#
# The script is run for real, against a throwaway root: a copy with its
# absolute paths pointed into a temporary directory, and a PATH that holds
# nothing but recording stand-ins for the commands it calls.  No VM, no root.
#
# Run: bash rpm/scripts/postinstall_test.sh
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
fails=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails+1)); }
check() { # <desc> <expected> <actual>
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected=\"$2\" got=\"$3\")"; fi
}

# run_case <init: systemd|openrc|sysvinit> <apk: 0|1> <notice text> <args...>
# Leaves $T/calls.log (one "command args" line per call) and $T/out.
run_case() {
    local init="$1" apk="$2" notice="$3"; shift 3
    T=$(mktemp -d)
    mkdir -p "$T/stub" "$T/tools" "$T/etc/unmask" "$T/var/lib/unmask" "$T/usr/share/unmask/init" "$T/etc/init.d" "$T/bin"
    : > "$T/calls.log"
    : > "$T/usr/share/unmask/init/unmask.sysv"
    : > "$T/usr/share/unmask/init/unmask.openrc"
    : > "$T/etc/unmask/config.yml"           # an upgrade: the config is there
    # The commands the script may call, as stand-ins that record the call.
    local stubs="chown chmod getent hostname install runuser su"
    case "$init" in
        systemd)  stubs="$stubs systemctl"; mkdir -p "$T/run/systemd/system" "$T/etc/systemd/system" ;;
        openrc)   stubs="$stubs rc-service rc-update" ;;
        sysvinit) stubs="$stubs chkconfig service"; mkdir -p "$T/etc/rc.d/init.d" ;;
    esac
    [ "$apk" = 1 ] && mkdir -p "$T/lib/apk"
    local c
    for c in $stubs; do
        printf '#!/bin/sh\necho "%s $*" >> "%s/calls.log"\nexit 0\n' "$c" "$T" > "$T/stub/$c"
        chmod +x "$T/stub/$c"
    done
    # The unmask binary: records the call, and answers `migrate -notice`.
    cat > "$T/bin/unmask" <<STUB
#!/bin/sh
echo "unmask \$*" >> "$T/calls.log"
case "\$*" in
    "migrate -notice"*) [ -n "\${STUB_NOTICE:-}" ] && printf '%s\n' "\$STUB_NOTICE" ;;
esac
exit 0
STUB
    chmod +x "$T/bin/unmask"
    # What the script needs from the system, and nothing else: no real
    # systemctl / service may be reachable from here.
    for c in head od tr cat mkdir cp ln rm sed grep; do
        ln -s "$(command -v $c)" "$T/tools/$c"
    done
    sed -e "s|/usr/sbin/unmask|$T/bin/unmask|g" \
        -e "s|/usr/share/unmask|$T/usr/share/unmask|g" \
        -e "s|/etc/rc.d/init.d|$T/etc/rc.d/init.d|g" \
        -e "s|/etc/init.d|$T/etc/init.d|g" \
        -e "s|/etc/systemd/system|$T/etc/systemd/system|g" \
        -e "s|/etc/unmask|$T/etc/unmask|g" \
        -e "s|/var/lib/unmask|$T/var/lib/unmask|g" \
        -e "s|/run/systemd/system|$T/run/systemd/system|g" \
        -e "s|/lib/apk|$T/lib/apk|g" \
        -e "s|/sbin/openrc-run|$T/sbin/openrc-run|g" \
        "$DIR/postinstall.sh" > "$T/postinstall.sh"
    PATH="$T/stub:$T/tools" STUB_NOTICE="$notice" /bin/sh "$T/postinstall.sh" "$@" > "$T/out" 2>&1
}

# How many calls start or restart the daemon.
starts() {
    grep -cE '^(systemctl (restart|start|try-restart|enable --now) unmask|rc-service unmask (restart|start)|service unmask (restart|start|condrestart))' "$T/calls.log"
}
called() { grep -cE "$1" "$T/calls.log"; }

NOTICE='unmask: a database update is waiting and was NOT applied automatically:'

# --- the daemon is started once, on every init system and every kind of run --
run_case systemd 0 "" 1
check "systemd, rpm fresh install: started once" 1 "$(starts)"
check "systemd, rpm fresh install: enabled for boot" 1 "$(called '^systemctl enable unmask.service$')"
check "systemd, rpm fresh install: a restart, which also starts a stopped unit" 1 "$(called '^systemctl restart unmask.service$')"
rm -rf "$T"

run_case systemd 0 "" 2
check "systemd, rpm upgrade: started once" 1 "$(starts)"
check "systemd, rpm upgrade: not re-enabled (the operator may have disabled it)" 0 "$(called '^systemctl enable')"
rm -rf "$T"

run_case systemd 0 "" configure
check "systemd, deb fresh install: started once" 1 "$(starts)"
check "systemd, deb fresh install: enabled for boot" 1 "$(called '^systemctl enable unmask.service$')"
rm -rf "$T"

run_case systemd 0 "" configure 0.1.47-1
check "systemd, deb upgrade: started once" 1 "$(starts)"
check "systemd, deb upgrade: not re-enabled" 0 "$(called '^systemctl enable')"
rm -rf "$T"

run_case systemd 1 "" 0.1.48-r1
check "systemd on Alpine: started once" 1 "$(starts)"
check "systemd on Alpine: enabled (apk cannot tell an install from an upgrade)" 1 "$(called '^systemctl enable unmask.service$')"
rm -rf "$T"

run_case openrc 1 "" 0.1.48-r1
check "OpenRC, apk: started once" 1 "$(starts)"
check "OpenRC, apk: a restart, not a start (a start leaves the old binary running on an upgrade)" 1 "$(called '^rc-service unmask restart$')"
check "OpenRC, apk: added to the default runlevel" 1 "$(called '^rc-update add unmask default$')"
rm -rf "$T"

run_case sysvinit 0 "" 1
check "SysVinit, rpm fresh install: started once" 1 "$(starts)"
check "SysVinit, rpm fresh install: registered for boot" 1 "$(called '^chkconfig unmask on$')"
rm -rf "$T"

run_case sysvinit 0 "" 2
check "SysVinit, rpm upgrade: started once" 1 "$(starts)"
check "SysVinit, rpm upgrade: a restart (brings up a daemon a prior remove stopped)" 1 "$(called '^service unmask restart$')"
[ -f "$T/etc/rc.d/init.d/unmask" ] && pass "SysVinit: the init script is installed" || fail "SysVinit: the init script is installed"
rm -rf "$T"

# --- the schema notice ------------------------------------------------------
run_case systemd 0 "$NOTICE" 2
check "the notice is asked for once" 1 "$(called '^unmask migrate -notice ')"
check "the notice is the last thing printed" "$NOTICE" "$(grep -v '^$' "$T/out" | tail -1)"
# Worked out BEFORE the restart: after it, this would compete with the
# starting daemon for the database.
n_notice=$(grep -n '^unmask migrate -notice' "$T/calls.log" | head -1 | cut -d: -f1)
n_start=$(grep -n '^systemctl restart unmask' "$T/calls.log" | head -1 | cut -d: -f1)
if [ -n "$n_notice" ] && [ -n "$n_start" ] && [ "$n_notice" -lt "$n_start" ]; then
    pass "the notice is worked out before the daemon is restarted"
else
    fail "the notice is worked out before the daemon is restarted (notice at call $n_notice, restart at call $n_start)"
fi
rm -rf "$T"

run_case systemd 0 "" 2
check "nothing waiting: nothing about it is printed" 0 "$(grep -c 'database update' "$T/out")"
check "nothing waiting: the run still ends on the usual last line" 1 "$(tail -3 "$T/out" | grep -c 'systemctl reload nginx')"
rm -rf "$T"

run_case sysvinit 0 "$NOTICE" 2
check "SysVinit: the notice is the last thing printed" "$NOTICE" "$(grep -v '^$' "$T/out" | tail -1)"
rm -rf "$T"

echo
if [ "$fails" -gt 0 ]; then
    echo "postinstall_test: $fails FAILED"
    exit 1
fi
echo "postinstall_test: all passed"
