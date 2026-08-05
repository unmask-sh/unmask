#!/bin/bash
# 55: what unmask costs per request, measured against stock nginx.
#
# Three targets, all served by the SAME nginx binary from the same image, over
# the same TLS, differing only in what is loaded:
#
#   stock    :8446  module not loaded, no unmask config       <- the baseline
#   bare     :8445  module loaded, vhost includes no server.inc
#   unmask   :8443  module loaded, vhost includes server.inc
#
# stock vs bare is what the module costs by being present.  bare vs unmask is
# what the decision logic costs.  Splitting them matters: they have different
# causes and different fixes, and a single "unmask is Nx slower" number hides
# which one moved.
#
# What this catches: a change that moves an expensive variable into a map KEY on
# a path every request touches.  nginx builds a key eagerly -- every variable in
# it, on every request -- and resolves only the matched entry's value, so "key"
# and "value" are not interchangeable and no functional test can tell them
# apart.  Two have shipped or nearly shipped: $final_challenge in the Web Bot
# Auth gate key (measured 56k -> 3.9k req/s on a location without protect.inc),
# and $is_search_bot in the hard-deny key (46k -> 3.4k).
#
# LIMITS OF THIS TEST, stated because a perf test that oversells itself is worse
# than none: both regressions above cost ~13x on a config where the expensive
# variable pulls the JA4 fingerprint, and near nothing on one where it does not.
# This fixture is the latter for the deny axis -- re-introducing that regression
# was measured here and moved the ratio by ~0.1x, well inside noise.  So this is
# a guard against gross regressions of ANY shape, and the deterministic guard
# for the specific one is TestServerScopeGatesDoNotBuildTheChainEagerly, which
# reads the map keys directly.
#
# The threshold is a ratio, never a rate: absolute throughput depends on the
# machine and on what else is running, so an absolute bound is a flaky test
# wearing a benchmark costume.  All three are measured in the same run, seconds
# apart, from a container that is not the one serving them.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
if ! command -v docker >/dev/null 2>&1 || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q bench 2>/dev/null)" ]; then
    log_skip "55-request-overhead needs the docker e2e stack (bench container) — skipped"
    exit 0
fi

REQS=${PERF_REQS:-3000}
CONC=${PERF_CONC:-4}
ROUNDS=${PERF_ROUNDS:-3}
# Healthy is ~1.9x here.  3.0 leaves room for a noisy runner while still
# catching the two regressions this exists for (both measured >4x on this
# fixture, ~13x on one where the expensive variable pulls the fingerprint).
MAX_RATIO=${PERF_MAX_RATIO:-3.0}

# ab from its own container, over the compose network: no host port mapping in
# the path, and the load generator is not stealing CPU from the server.
# -k so connections are reused and the TLS handshake is not what gets measured.
rps() { # <host:port> -> requests/sec
    local target=$1 out
    out=$(docker compose -f "$COMPOSE" exec -T bench \
        ab -q -n "$REQS" -c "$CONC" -k "https://${target}/__unmask_perf" 2>/dev/null) || return 1
    echo "$out" | awk '/Requests per second/ {print $4; found=1} END{exit !found}'
}

# Interleaved: all three targets inside each round, not three rounds of one and
# then three of the next.  Sequential blocks bias whichever target is measured
# last -- a box that gets busier during the run makes the first target look fast
# and the last look slow, and "last" here is the one under test.  Measured with
# the sequential form: the module-only leg, which does no extra work at all,
# came out at 1.34x.
declare -A best=()
for ((r = 1; r <= ROUNDS; r++)); do
    line="round $r:"
    for t in "stock:stock-nginx:8446" "bare:nginx:8445" "unmask:nginx:8443"; do
        name=${t%%:*}
        target=${t#*:}
        v=$(rps "$target") || { log_fail "could not measure $name ($target)"; exit 1; }
        awk -v x="$v" 'BEGIN{exit !(x > 0)}' \
            || { log_fail "$name measured $v req/s; the measurement itself is broken"; exit 1; }
        # Best-of rather than mean: the fastest round is the one least disturbed
        # by something else on the box, and noise here only ever costs time.
        cur=${best[$name]:-0}
        awk -v a="$v" -v b="$cur" 'BEGIN{exit !(a > b)}' && best[$name]=$v
        line="$line $name=$v"
    done
    log "$line"
done

stock=${best[stock]:-0}
bare=${best[bare]:-0}
unmask=${best[unmask]:-0}
# A measurement that did not happen must not be able to pass.  An earlier
# version of this scenario compared two sentinels, got a ratio of 1.00 and
# reported the healthiest-looking result there is.
for v in "$stock" "$bare" "$unmask"; do
    awk -v x="$v" 'BEGIN{exit !(x > 0)}' \
        || { log_fail "a target measured 0 req/s; the measurement itself is broken"; exit 1; }
done

mod_ratio=$(awk -v s="$stock" -v b="$bare" 'BEGIN{printf "%.2f", s/b}')
dec_ratio=$(awk -v b="$bare" -v u="$unmask" 'BEGIN{printf "%.2f", b/u}')
tot_ratio=$(awk -v s="$stock" -v u="$unmask" 'BEGIN{printf "%.2f", s/u}')

# log_note rather than log: these three are the point of the scenario, and a
# suite of 55 scrolls them off the screen long before it finishes.  run.sh
# reprints collected notes in the summary block.
log_note "$(printf 'stock nginx    %10s req/s          (module not loaded)' "$stock")"
log_note "$(printf '  + module     %10s req/s  %5sx  (module loaded, no server.inc)' "$bare" "$mod_ratio")"
log_note "$(printf '  + server.inc %10s req/s  %5sx  (full decision path)' "$unmask" "$dec_ratio")"
log_note "$(printf '  = unmask vs stock nginx: %sx   (limit %sx, %s req x %s rounds, c=%s)' \
    "$tot_ratio" "$MAX_RATIO" "$REQS" "$ROUNDS" "$CONC")"

if awk -v r="$tot_ratio" -v m="$MAX_RATIO" 'BEGIN{exit !(r > m)}'; then
    log_fail "unmask costs ${tot_ratio}x stock nginx per request (limit ${MAX_RATIO}x).
  module alone ${mod_ratio}x, decision logic ${dec_ratio}x -- the larger one is where to look.
  A common cause is a variable moved into a map KEY: nginx builds keys eagerly,
  so a fingerprint or rescue variable in a key is paid by every request to the
  vhost, while the same variable reached through a map VALUE is paid only on
  the branch that needs it."
    exit 1
fi
log_pass "per-request cost ${tot_ratio}x stock nginx (module ${mod_ratio}x, decision ${dec_ratio}x)"
