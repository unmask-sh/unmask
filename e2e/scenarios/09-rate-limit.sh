#!/bin/bash
# 09: rapid-fire requests trigger the nginx limit_req zone.
#
# Demo nginx: `limit_req zone=unmask_rate burst=10 nodelay` + `error_page 429 = @unmask_rate_challenge`.
# Sending many more requests than burst from a single IP should produce either:
#   - 4xx status (= direct 429 / 403 challenge rewrite), or
#   - 200 status with a challenge HTML body (= @unmask_rate_challenge in
#     server.inc rewrites to /unmask/_rl<orig URI> which serves the challenge
#     page — admin returns 200 + HTML).
#
# Either signal is acceptable; we just need to confirm the zone is wired.
# Use --parallel-immediate so requests fire concurrently and overflow the burst.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

N=50
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# Fire N requests in parallel via xargs.  Sequential curl runs are slow enough
# (TLS handshake per request) that the rate-limit refill can keep up; parallel
# bursts overflow the burst=10 queue reliably.
seq 1 "$N" | xargs -I{} -P "$N" sh -c '
    curl -sk -A "'"$UA_BROWSER"'" \
        -o "'"$tmpdir"'/body.$1" \
        -w "%{http_code}\n" \
        --max-time 5 "'"${BASE_URL}"'/?rl=$1" 2>/dev/null
' _ {} > "$tmpdir/codes"

ok=0
denied=0
challenge_body=0
other=0
i=0
while read -r code; do
    i=$((i+1))
    case "$code" in
        200)
            # 200 may either be a normal pass OR the rate-limit challenge page.
            if grep -qiE 'challenge|<!doctype html>|window\.UNMASK' "$tmpdir/body.$i" 2>/dev/null; then
                challenge_body=$((challenge_body+1))
            else
                ok=$((ok+1))
            fi
            ;;
        403|429)     denied=$((denied+1)) ;;
        *)           other=$((other+1)) ;;
    esac
done < "$tmpdir/codes"

log "ok=$ok denied=$denied challenge_body=$challenge_body other=$other (N=$N)"

if [ $((denied + challenge_body)) -ge 1 ]; then
    log_pass "rate limit fired at least once (denied=$denied challenge_body=$challenge_body)"
    exit 0
fi

log_fail "rate limit never fired (= no 4xx / challenge body in $N requests)"
log "→ check nginx limit_req zone (unmask_rate) and burst setting"
exit 1
