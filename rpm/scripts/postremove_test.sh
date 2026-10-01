#!/bin/bash
# Test for postremove.sh: the log-socket handover drop-in across a downgrade.
#
# postinstall.sh writes unmask.service.d/20-log-handover.conf, which has
# systemd keep nginx's access-log socket over a restart of the daemon
# (admin/internal/nginxlog/handover.go).  A daemon from before that knows
# nothing of it: handed the kept socket, it holds the descriptor without ever
# reading it and binds a new one beside it, and nginx's workers stay connected
# to the kept one.  So when a version without the handover takes this one's
# place, postremove takes the drop-in away and has systemd re-read the unit
# -- which empties the store -- and, if the store held a socket before that,
# stops the daemon that may have been handed it and starts it again.  An
# upgrade keeps it all.
#
# The script is run for real against a throwaway root, with a stand-in
# systemctl that records its calls and keeps the unit's store count.  No VM,
# no root.
#
# Run: bash rpm/scripts/postremove_test.sh
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
fails=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails+1)); }
check() { # <desc> <expected> <actual>
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected=\"$2\" got=\"$3\")"; fi
}

# run_case <incoming binary handles the handover: 0|1> <daemon state> <kept> <store> <args...>
#   daemon state: what `systemctl is-active` says (active / activating / inactive)
#   kept: sockets in the store when the script starts (0 = the newer daemon let
#         its socket go on the way out; 1 = it is still there)
#   store: how a kept socket behaves --
#     reload   systemd lets go of it when it re-reads the unit without the drop-in
#     stop     it outlasts the re-read and goes with a stop
#     never    it outlasts both (the wait must give up)
#   SYSTEMD=0 in the environment: systemd is not running (a chroot, an image build)
#   NOBIN=1 in the environment: no binary on disk (the package was removed)
run_case() {
    local handles="$1" state="$2" had="$3" store="$4"; shift 4
    T=$(mktemp -d)
    D="$T/etc/systemd/system/unmask.service.d/20-log-handover.conf"
    mkdir -p "$T/stub" "$T/tools" "$T/etc/systemd/system/unmask.service.d" "$T/usr/sbin"
    [ "${SYSTEMD:-1}" = 1 ] && mkdir -p "$T/run/systemd/system"
    : > "$T/calls.log"
    echo "$had" > "$T/store"
    printf '[Service]\nSupplementaryGroups=nginx\n' > "$T/etc/systemd/system/unmask.service.d/10-group.conf"
    printf '[Service]\nFileDescriptorStoreMax=1\nEnvironment=UNMASK_LOG_HANDOVER=1\n' > "$D"
    # The binary on disk is the incoming version's (none after a removal).
    if [ "${NOBIN:-0}" = 1 ]; then
        :
    elif [ "$handles" = 1 ]; then
        printf 'ELF ... os.Getenv("UNMASK_LOG_HANDOVER") ...' > "$T/usr/sbin/unmask"
    else
        printf 'ELF ... an unmask from before the handover ...' > "$T/usr/sbin/unmask"
    fi
    cat > "$T/stub/systemctl" <<STUB
#!/bin/sh
case "\$*" in
    daemon-reload)
        # What systemd sees when it re-reads the unit: with the drop-in gone it
        # may store nothing, and lets go of what it held.
        if [ -f "$D" ]; then echo "systemctl daemon-reload dropin=present" >> "$T/calls.log"
        else echo "systemctl daemon-reload dropin=absent" >> "$T/calls.log"; [ "$store" = reload ] && echo 0 > "$T/store"; fi
        exit 0 ;;
esac
echo "systemctl \$*" >> "$T/calls.log"
case "\$*" in
    "is-active unmask.service")
        # After a stop the daemon is no longer what it was: the script must
        # have asked before it stopped it.
        if [ -e "$T/stopped" ]; then echo inactive; exit 3; fi
        echo "$state"; [ "$state" = active ] && exit 0 || exit 3 ;;
    "show -p NFileDescriptorStore --value unmask.service") cat "$T/store" ;;
    "stop unmask.service") : > "$T/stopped"; [ "$store" = never ] || echo 0 > "$T/store" ;;
esac
exit 0
STUB
    printf '#!/bin/sh\necho "sleep $*" >> "%s/calls.log"\n' "$T" > "$T/stub/sleep"
    chmod +x "$T/stub/systemctl" "$T/stub/sleep"
    for c in rm grep cat; do
        ln -s "$(command -v $c)" "$T/tools/$c"
    done
    sed -e "s|/etc/systemd/system|$T/etc/systemd/system|g" \
        -e "s|/usr/sbin/unmask|$T/usr/sbin/unmask|g" \
        -e "s|/run/systemd/system|$T/run/systemd/system|g" \
        -e "s|/lib/apk|$T/lib/apk|g" \
        -e "s|/etc/init.d|$T/etc/init.d|g" \
        "$DIR/postremove.sh" > "$T/postremove.sh"
    PATH="$T/stub:$T/tools" /bin/sh "$T/postremove.sh" "$@" > "$T/out" 2>&1
}
dropin() { [ -f "$T/etc/systemd/system/unmask.service.d/20-log-handover.conf" ] && echo kept || echo removed; }
called() { grep -cE "$1" "$T/calls.log"; }
# Everything asked of systemd about the daemon and the unit, in order.
steps() { grep -oE '^systemctl (stop|start|restart|try-restart) unmask.service$|^systemctl daemon-reload dropin=[a-z]+' "$T/calls.log" | sed -e 's/^systemctl //' -e 's/ unmask.service$//' -e 's/daemon-reload dropin=/reread:/' | tr '\n' ' ' | sed 's/ $//'; }
# The stops and starts alone: "" when the daemon was left alone.
cycle() { grep -oE '^systemctl (stop|start|restart|try-restart) unmask.service$' "$T/calls.log" | awk '{print $2}' | tr '\n' ' ' | sed 's/ $//'; }

# --- an upgrade keeps everything ---------------------------------------------
run_case 1 active 1 reload 1
check "rpm upgrade to a version with the handover: the drop-in is kept" kept "$(dropin)"
check "rpm upgrade: the daemon is left alone" "" "$(cycle)"
check "rpm upgrade: the store is not even asked about" 0 "$(called 'NFileDescriptorStore')"
rm -rf "$T"

run_case 1 active 1 reload upgrade 0.1.50-1
check "deb upgrade to a version with the handover: the drop-in is kept" kept "$(dropin)"
rm -rf "$T"

# --- a downgrade after the newer daemon let its socket go (nothing kept) -----
run_case 0 active 0 reload 1
check "rpm downgrade, nothing kept: the drop-in is removed" removed "$(dropin)"
check "rpm downgrade, nothing kept: the unit is re-read once the drop-in is gone, and the daemon left alone" "reread:absent reread:absent" "$(steps)"
check "rpm downgrade, nothing kept: the group drop-in stays" yes "$([ -f "$T/etc/systemd/system/unmask.service.d/10-group.conf" ] && echo yes || echo no)"
rm -rf "$T"

# --- a downgrade with a socket still kept ------------------------------------
# rpm: the newer daemon had no way out (a crash, a kill), and the older one,
# started by its package just before, was handed the socket and holds it.  The
# re-read empties the store, but only ending that process frees the socket.
# deb: this runs before the older package's restart, with the newer daemon up.
run_case 0 active 1 reload 1
check "rpm downgrade, a socket kept: the drop-in is removed" removed "$(dropin)"
check "rpm downgrade, a socket kept: re-read without the drop-in, then stopped outright and started" "reread:absent stop start reread:absent" "$(steps)"
check "rpm downgrade, a socket kept: no waiting once the store is empty" 0 "$(called '^sleep')"
rm -rf "$T"

run_case 0 active 1 reload upgrade 0.1.48-1
check "deb downgrade, a socket kept: the drop-in is removed" removed "$(dropin)"
check "deb downgrade, a socket kept: re-read, stopped outright, started" "reread:absent stop start reread:absent" "$(steps)"
rm -rf "$T"

run_case 0 activating 1 reload 1
check "a socket kept, daemon between restarts: stopped and started again" "stop start" "$(cycle)"
rm -rf "$T"

run_case 0 inactive 1 reload 1
check "a socket kept, daemon stopped: not started behind the operator's back" "stop" "$(cycle)"
rm -rf "$T"

# --- a store that outlasts the re-read ---------------------------------------
run_case 0 active 1 stop 1
check "store outlasts the re-read: the stop ends it (a restart would keep it)" "stop start" "$(cycle)"
check "store outlasts the re-read: no waiting once the stop ended it" 0 "$(called '^sleep')"
rm -rf "$T"

run_case 0 active 1 never 1
check "store that never goes: the wait gives up after 50 tries" 50 "$(called '^sleep 0.1$')"
check "store that never goes: the daemon is started again all the same" "stop start" "$(cycle)"
rm -rf "$T"

# --- systemd not running (a chroot, an image build) --------------------------
SYSTEMD=0 run_case 0 active 1 reload 1
check "no systemd running: the drop-in is removed all the same" removed "$(dropin)"
check "no systemd running: nothing is stopped or started" "" "$(cycle)"
rm -rf "$T"

# --- removal -----------------------------------------------------------------
# The package's files are gone by now, the binary with them.
NOBIN=1 run_case 0 inactive 0 reload remove
check "deb remove: nothing is stopped or started from here" "" "$(cycle)"
check "deb remove: the drop-ins stay for the purge, or for the next install to rewrite" kept "$(dropin)"
check "deb remove: the store is not asked about" 0 "$(called 'NFileDescriptorStore')"
rm -rf "$T"

NOBIN=1 run_case 0 inactive 0 reload purge
check "deb purge: the whole drop-in directory goes" no "$([ -d "$T/etc/systemd/system/unmask.service.d" ] && echo yes || echo no)"
check "deb purge: no stop and start from here" "" "$(cycle)"
rm -rf "$T"

run_case 0 active 1 reload 0
check "rpm erase: the whole drop-in directory goes" no "$([ -d "$T/etc/systemd/system/unmask.service.d" ] && echo yes || echo no)"
check "rpm erase: no stop and start from here (preremove stopped it)" "" "$(cycle)"
rm -rf "$T"

# --- the marker is the one the daemon carries --------------------------------
# postremove tells an old binary from a new one by a string the new one
# contains; postinstall sets the variable of that name.  All three must agree.
GO="$DIR/../../admin/internal/nginxlog/handover.go"
if [ -f "$GO" ]; then
    marker=$(sed -n 's/^[[:space:]]*HandoverEnv = "\([A-Z_]*\)"$/\1/p' "$GO")
    check "the daemon's marker is found in its source" UNMASK_LOG_HANDOVER "$marker"
    check "postremove.sh looks for that marker" 1 "$(grep -c "grep -q $marker /usr/sbin/unmask" "$DIR/postremove.sh")"
    check "postinstall.sh sets the variable of that name" 1 "$(grep -c "Environment=$marker=1" "$DIR/postinstall.sh")"
fi

echo
if [ "$fails" -gt 0 ]; then
    echo "postremove_test: $fails failure(s)"
    exit 1
fi
echo "postremove_test: all passed"
