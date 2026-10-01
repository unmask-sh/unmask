#!/bin/sh
# The user / data dir is removed only on purge.
# Distinguishes rpm full-remove ($1 = 0) from dpkg purge ($1 = "purge").

# Decide whether this is a real removal (apk passes the version string instead
# of "0"/"purge", so plain case-matching misses Alpine -- see the parallel
# logic in postremove-web-nginx.sh).
do_cleanup=0
if [ -d /lib/apk ]; then
    do_cleanup=1
else
    case "${1:-}" in
        0|purge) do_cleanup=1 ;;
    esac
fi

if [ "$do_cleanup" = 1 ]; then
    # Data is kept (= recovery scenarios).  User removal is left to the operator.
    # The systemd drop-in placed by postinst is removed (= on full remove only).
    rm -rf /etc/systemd/system/unmask.service.d 2>/dev/null || true
    # OpenRC: postinstall symlinks /etc/init.d/unmask -> the openrc init
    # script under /usr/share/unmask/init/.  apk's package manager won't touch
    # the symlink because it isn't owned by the package; clear it here so a
    # rerun of `apk add unmask` (or any later remove cycle) starts clean.
    if [ -L /etc/init.d/unmask ]; then
        rm -f /etc/init.d/unmask
    fi
fi

# A version without the log-socket handover (admin/internal/nginxlog/
# handover.go) taking this one's place -- a downgrade -- must not keep the
# drop-in that turns it on.  systemd would hand that daemon the socket it
# kept; the daemon would ignore it and bind its own; and nginx's workers would
# stay connected to the kept one, with nobody reading.  (The newer daemon lets
# its socket go when it sees the older binary in its place, on its way out;
# this is for when it had no way out -- a crash, a kill.)
#
# On a deb downgrade this runs before the older package's restart, on an rpm
# one after it: there the older daemon may already be running, with the kept
# socket handed to it -- a descriptor it never looks at, and holds open.  So
# what the store held BEFORE the unit is re-read decides.  Nothing kept: the
# drop-in goes and the daemon is left alone.  Something kept: the re-read
# empties the store (the unit may store nothing without the drop-in), and a
# stop -- not a restart, which would keep a store that outlasted the re-read
# -- ends the process that may hold the socket; it is started again if it was
# running.
HANDOVER_DROPIN=/etc/systemd/system/unmask.service.d/20-log-handover.conf
if [ "$do_cleanup" = 0 ] && [ -f "$HANDOVER_DROPIN" ] && [ -f /usr/sbin/unmask ] &&
   ! grep -q UNMASK_LOG_HANDOVER /usr/sbin/unmask 2>/dev/null; then
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        kept() { systemctl show -p NFileDescriptorStore --value unmask.service 2>/dev/null; }
        HAD=$(kept)
        rm -f "$HANDOVER_DROPIN"
        systemctl daemon-reload || true
        if [ "$HAD" != 0 ] || [ "$(kept)" != 0 ]; then
            WAS=$(systemctl is-active unmask.service 2>/dev/null)
            systemctl stop unmask.service || true
            i=0
            while [ "$(kept)" != 0 ] && [ "$i" -lt 50 ]; do
                sleep 0.1
                i=$((i + 1))
            done
            case "$WAS" in
            active|activating|reloading) systemctl start unmask.service || true ;;
            esac
        fi
    else
        rm -f "$HANDOVER_DROPIN"
    fi
fi

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || true
fi

exit 0
