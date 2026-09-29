# Stopping and starting the daemon's container from a scenario.
#
# The scenarios that restart the daemon used to send docker's output to
# /dev/null and then wait for healthz.  When the start itself failed -- docker
# could not bring the container up -- the daemon never ran, the wait ran out,
# and the only thing on record was "did not come back" a minute later.  These
# keep what docker said, and try a start that docker refused once more: that
# is the stack's trouble, not what the scenario is there to test.  A container
# that was started and then went away is not retried -- that is the daemon's
# doing, and the scenario is right to fail on it.
#
# Sourced after assert.sh (log).

# stack_stop <compose file>
stack_stop() {
    local out t0=$SECONDS
    if ! out=$(docker compose -f "$1" stop unmask 2>&1); then
        log "docker compose stop unmask failed: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-300)"
        return 1
    fi
    [ $((SECONDS - t0)) -lt 8 ] || log "docker compose stop unmask took $((SECONDS - t0))s (the daemon did not leave on SIGTERM?)"
    return 0
}

# stack_start <compose file>: 0 when docker started the container.
stack_start() {
    local out i
    for i in 1 2 3; do
        if out=$(docker compose -f "$1" start unmask 2>&1); then
            return 0
        fi
        log "docker compose start unmask failed (attempt $i of 3): $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-300)"
        sleep 2
    done
    return 1
}

# stack_restart <compose file>: stop, then start.
stack_restart() {
    stack_stop "$1"
    stack_start "$1"
}
