#!/bin/bash
# 46: forward-auth rate-limit -- the daemon's Go RateLimiter is the enforcer.
#
# Native mode rate-limits in nginx (limit_req zones rendered into http.inc).
# Forward-auth (stock nginx + apache) has NO limit_req, so AuthCheck's in-daemon
# sliding-window limiter (h.RateLimiter.Hit) is what enforces the zones -- and it
# was e2e-dark.  admin.yml defines a DENY zone on /deny-test/ (5 r/min, burst 2);
# bursting the same IP through a forward-auth front must drive the over-cap
# requests to a hard DENY (403) -- proving the daemon limiter trips on the
# forward-auth path (fa-nginx auth_request -> 403 -> branded /unmask/_ban;
# apache lua -> /unmask/_ban).  A browser UA is used so the UA axis passes and
# rate-limit is the only thing that can produce a 4xx.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

fails=0

# burst <front-url> <ip> -> prints one HTTP status per line (40 concurrent).
burst() {
    seq 1 40 | xargs -P 40 -I{} curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $2" \
        -o /dev/null -w '%{http_code}\n' --max-time 8 "$1/deny-test/?x={}" 2>/dev/null
}

# Each front gets its own IP so its deny bucket is independent.
check_front() {
    local name="$1" url="$2" ip="$3"
    if ! curl -sk -o /dev/null --max-time 5 "${url}/unmask/healthz"; then
        log "${name} not reachable -- skipping"
        return 0
    fi
    # control: a single browser request to a normal path is NOT denied.  The
    # deny signal differs per front: fa-nginx returns 403 directly (error_page
    # 403 -> @unmask_blocked); apache redirects 302 -> /unmask/_ban (apache-unmask
    # .lua).  Count both (and 429) as "denied".
    local c
    c=$(curl -sk -o /dev/null -w '%{http_code}' --max-time 6 -A "$UA_BROWSER" \
        -H "X-Forwarded-For: $ip" "${url}/")
    case "$c" in
        403|302|429) log_fail "${name}: a single normal request was already denied ($c, unexpected pre-trip)"; fails=$((fails+1));;
    esac
    # burst the deny zone with the same IP -> over-cap requests hard-denied.
    local denied
    denied=$(burst "$url" "$ip" | grep -cE '^(403|302|429)$')
    log "${name}: deny-zone burst -> deny count (403/302/429) = ${denied}/40"
    if [ "${denied:-0}" -ge 1 ]; then
        log_pass "${name}: daemon RateLimiter trips the deny zone on the forward-auth path"
    else
        log_fail "${name}: deny-zone burst produced no deny -- the daemon limiter is not enforcing in forward-auth"
        fails=$((fails+1))
    fi
}

check_front "forward-auth nginx" "$FA_NGINX_URL" "198.51.100.46"
check_front "forward-auth apache" "$APACHE_URL" "198.51.100.47"

[ "$fails" -eq 0 ] && exit 0
exit 1
