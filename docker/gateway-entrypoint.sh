#!/bin/bash
# unmask gateway entrypoint: the daemon and nginx in one container.
#
#   1. unmask-daemon.sh (= the daemon's own entrypoint): first-boot config
#      skeleton, ownership of the volumes, migrate, render-nginx, then
#      `unmask serve` -- started in the background.
#   2. Wait until the daemon answers /unmask/healthz (the rendered includes
#      exist by then, which nginx's gateway script also waits for).
#   3. nginx through the stock entrypoint, so /docker-entrypoint.d/ runs as in
#      the official image (our gateway.envsh and the autoreload watcher among
#      them), in the background as well.
#   4. Supervise.  nginx gone = the container is over: stop the daemon and
#      exit with nginx's status, and let the restart policy bring the whole
#      thing back.  The daemon gone = restart it after a short pause; nginx
#      keeps serving meanwhile (fail-open: the module lets traffic through
#      while the daemon is unreachable), so a daemon crash costs no outage.
#   SIGTERM (docker stop): nginx quits gracefully, the daemon is terminated,
#   both are waited for.
#
# The daemon-only variables keep their names; the image sets the loopback
# defaults (UNMASK_DAEMON_ADDR, UNMASK_GATEWAY_ADDR) and UNMASK_GATEWAY=1.
set -u
CFG=/etc/unmask/config.yml
DAEMON=/usr/local/bin/unmask-daemon.sh
DPID=""; NPID=""; STOPPING=""

log() { printf 'unmask-gateway: %s\n' "$*"; }

start_daemon() {
    "$DAEMON" serve -config "$CFG" &
    DPID=$!
}

wait_daemon() {
    # up to 90s: a first boot migrates and renders before it listens
    for i in $(seq 1 90); do
        if curl -fsS -o /dev/null --max-time 2 "http://127.0.0.1:9477/unmask/healthz" 2>/dev/null; then return 0; fi
        kill -0 "$DPID" 2>/dev/null || { log "the daemon exited before it came up"; return 1; }
        sleep 1
    done
    log "the daemon did not answer /unmask/healthz within 90s"
    return 1
}

stop_all() {
    STOPPING=1
    [ -n "$NPID" ] && kill -0 "$NPID" 2>/dev/null && nginx -s quit 2>/dev/null
    [ -n "$DPID" ] && kill -TERM "$DPID" 2>/dev/null
    wait 2>/dev/null
    exit 0
}
trap stop_all TERM INT

start_daemon
wait_daemon || { kill -TERM "$DPID" 2>/dev/null; wait; exit 1; }

# the stock entrypoint runs /docker-entrypoint.d/* and then exec's nginx,
# so $NPID is nginx's master process
/docker-entrypoint.sh nginx -g 'daemon off;' &
NPID=$!

backoff=2
while :; do
    wait -n 2>/dev/null
    [ -n "$STOPPING" ] && exit 0
    if ! kill -0 "$NPID" 2>/dev/null; then
        wait "$NPID"; rc=$?
        log "nginx exited ($rc); stopping the daemon and the container"
        kill -TERM "$DPID" 2>/dev/null; wait "$DPID" 2>/dev/null
        exit "$rc"
    fi
    if ! kill -0 "$DPID" 2>/dev/null; then
        wait "$DPID"; rc=$?
        log "the daemon exited ($rc); nginx keeps serving (fail-open), restarting the daemon in ${backoff}s"
        sleep "$backoff"
        [ "$backoff" -lt 30 ] && backoff=$((backoff * 2))
        start_daemon
        if wait_daemon; then backoff=2; fi
    fi
done
