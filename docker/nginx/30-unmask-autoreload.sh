#!/bin/sh
# Auto-reload for the unmask nginx image.
#
# The admin container renders the nginx includes into the shared /etc/unmask
# volume whenever settings change; on a host the operator then reloads
# nginx, but a container cannot be signalled from another container.  So
# this watches the rendered files and reloads nginx itself when their
# content changes -- after `nginx -t`, so a broken render is logged and
# skipped while the running config stays up.
#
# Executed (not sourced) by the stock entrypoint before nginx starts; it
# forks the watcher into the background and returns immediately.  Polling
# rather than inotify: the official image has no inotify tools, and a
# checksum of ~200KB every few seconds is nothing.
#
# UNMASK_AUTORELOAD=0 turns it off.
case "${UNMASK_AUTORELOAD:-1}" in 0|false|no|off) exit 0 ;; esac

WATCH="/etc/unmask/http.inc /etc/unmask/upstream.conf /etc/unmask/server.inc /etc/unmask/protect.inc /etc/unmask/forward-auth-lbtrust.conf /etc/unmask/community-bans-ip.map /etc/unmask/community-bans-ja4.map /etc/unmask/community-bans-ipja4.map"
INTERVAL="${UNMASK_AUTORELOAD_INTERVAL:-3}"

sig() {
    # Content signature over the files that exist; a missing file simply
    # contributes nothing, so a first render appearing later is a change.
    for f in $WATCH; do [ -f "$f" ] && cat "$f"; done | md5sum | cut -d' ' -f1
}

(
    last=$(sig)
    # Let nginx come up before the first comparison could ever fire.
    sleep 5
    echo "unmask-autoreload: watching the rendered includes in /etc/unmask (every ${INTERVAL}s; UNMASK_AUTORELOAD=0 disables)"
    while :; do
        sleep "$INTERVAL"
        cur=$(sig)
        [ "$cur" = "$last" ] && continue
        last=$cur
        # Give a multi-file render a moment to finish before testing it.
        sleep 1
        cur=$(sig); last=$cur
        if nginx -t >/dev/null 2>&1; then
            if nginx -s reload 2>/dev/null; then
                echo "unmask-autoreload: includes changed, nginx reloaded"
            else
                echo "unmask-autoreload: includes changed but the reload signal failed (is nginx up yet?)" >&2
            fi
        else
            echo "unmask-autoreload: includes changed but nginx -t fails; keeping the running config:" >&2
            nginx -t 2>&1 | tail -3 >&2
        fi
    done
) &
