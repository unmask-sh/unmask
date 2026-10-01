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
    # systemctl also answers --version, as the systemd of STUB_SYSTEMD_VER.
    if [ "$init" = systemd ]; then
        cat > "$T/stub/systemctl" <<STUB
#!/bin/sh
echo "systemctl \$*" >> "$T/calls.log"
if [ "\$1" = "--version" ] && [ -n "\${STUB_SYSTEMD_VER:-}" ]; then
    printf 'systemd %s (%s-1.el9)\n+PAM +AUDIT +SELINUX\n' "\$STUB_SYSTEMD_VER" "\$STUB_SYSTEMD_VER"
fi
# What systemd would find when it re-reads the unit, and when it restarts it.
case "\$1" in daemon-reload|restart)
    if [ -f "$T/etc/systemd/system/unmask.service.d/20-log-handover.conf" ]; then echo "\$1 handover=yes" >> "$T/order.log"
    else echo "\$1 handover=no" >> "$T/order.log"; fi ;;
esac
exit 0
STUB
        chmod +x "$T/stub/systemctl"
    fi
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
    if [ -n "${PRE_DROPIN:-}" ]; then
        mkdir -p "$T/etc/systemd/system/unmask.service.d"
        printf '[Service]\nFileDescriptorStoreMax=1\n' > "$T/etc/systemd/system/unmask.service.d/20-log-handover.conf"
    fi
    PATH="$T/stub:$T/tools" STUB_NOTICE="$notice" STUB_SYSTEMD_VER="${STUB_SYSTEMD_VER:-}" \
        /bin/sh "$T/postinstall.sh" "$@" > "$T/out" 2>&1
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

# --- nginx's access-log socket over a restart (the handover drop-in) --------
# The drop-in keeps the socket in systemd's store over a restart.  A systemd
# older than 236 cannot drop a stale socket from the store (FDSTOREREMOVE), so
# there it is not written -- and one left by an earlier run is taken away: a
# stale socket would hold nginx's workers unread.  It must be in place before
# systemd re-reads the unit and before the daemon is restarted, or the start
# that follows the install would not have it.
HO=etc/systemd/system/unmask.service.d/20-log-handover.conf
order() { tr '\n' ' ' < "$T/order.log" 2>/dev/null | sed 's/ $//'; }

STUB_SYSTEMD_VER=252 run_case systemd 0 "" 2
check "systemd 252: the handover drop-in is written" yes "$([ -f "$T/$HO" ] && echo yes || echo no)"
check "systemd 252: it lets the daemon store the socket" 2 "$(grep -cxE 'NotifyAccess=exec|FileDescriptorStoreMax=1' "$T/$HO" 2>/dev/null)"
# Before every start: a binary without the daemon's marker is not handed the
# kept socket.  The command must end in an `exec` of systemd-notify (so that
# it is the unit's control process, the one NotifyAccess=exec listens to), be
# allowed to fail (-), and name the socket as the daemon stores it.
check "systemd 252: a binary without the handover is not handed the socket" 1 "$(grep -cxE "ExecStartPre=-/bin/sh -c 'grep -q UNMASK_LOG_HANDOVER [^ ]*/unmask \|\| exec systemd-notify FDSTOREREMOVE=1 FDNAME=nginxlog'" "$T/$HO" 2>/dev/null)"
# (This run's root moves the binary; the script itself names the one the unit starts.)
check "the check reads the binary the unit starts" 1 "$(grep -c "grep -q UNMASK_LOG_HANDOVER /usr/sbin/unmask || exec systemd-notify" "$DIR/postinstall.sh")"
check "the unit starts that binary" 1 "$(grep -cx 'ExecStart=/usr/sbin/unmask serve' "$DIR/../unmask.service")"
check "systemd 252: it keeps the directory the socket is bound in" 1 "$(grep -cx 'RuntimeDirectoryPreserve=restart' "$T/$HO" 2>/dev/null)"
check "systemd 252: it tells the daemon so" 1 "$(grep -cx 'Environment=UNMASK_LOG_HANDOVER=1' "$T/$HO" 2>/dev/null)"
check "systemd 252: in place when the unit is re-read, and when the daemon is restarted" "daemon-reload handover=yes restart handover=yes" "$(order)"
check "systemd 252: still started once" 1 "$(starts)"
rm -rf "$T"

STUB_SYSTEMD_VER=236 run_case systemd 0 "" configure 0.1.48-1
check "systemd 236 (the first with FDSTOREREMOVE), deb upgrade: the drop-in is written" yes "$([ -f "$T/$HO" ] && echo yes || echo no)"
rm -rf "$T"

STUB_SYSTEMD_VER=235 run_case systemd 0 "" 2
check "systemd 235: one short of it, no drop-in" no "$([ -f "$T/$HO" ] && echo yes || echo no)"
rm -rf "$T"

STUB_SYSTEMD_VER=219 run_case systemd 0 "" 2
check "systemd 219 (CentOS 7): no handover drop-in" no "$([ -f "$T/$HO" ] && echo yes || echo no)"
check "systemd 219: the unit is re-read and the daemon restarted without it" "daemon-reload handover=no restart handover=no" "$(order)"
rm -rf "$T"

# A drop-in from an earlier run, on a systemd that turns out too old for it
# (or whose version cannot be read): taken away before the unit is re-read.
PRE_DROPIN=1 STUB_SYSTEMD_VER=219 run_case systemd 0 "" 2
check "a drop-in left on a systemd too old for it is removed" no "$([ -f "$T/$HO" ] && echo yes || echo no)"
check "... before the unit is re-read" "daemon-reload handover=no restart handover=no" "$(order)"
rm -rf "$T"

PRE_DROPIN=1 STUB_SYSTEMD_VER= run_case systemd 0 "" 2
check "a systemd whose version cannot be read: no drop-in" no "$([ -f "$T/$HO" ] && echo yes || echo no)"
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
