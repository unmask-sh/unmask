#!/bin/bash
# 16: multi-site — the visitor's Host header becomes the event's site.
#
# unmask derives `site` from the normalized request Host (= the vhost the
# visitor reached), so one unmask instance fronting many vhosts splits
# cleanly in the dashboard with zero per-site config.  This scenario drives
# /api/check with distinct Host headers and confirms each event landed under
# the expected site value.
#
# Verified properties:
#   - X-Original-Host -> site (= the auth_request proxy forwards the vhost)
#   - Host is lowercased and the :port is stripped
#   - X-Unmask-Site overrides the derived value (= proxies that map vhosts
#     to a custom site id)
#
# Ghost-site classification (defined mode) is covered by the Go unit test
# TestGhostSites; it needs `sites.mode: defined` which the shared e2e config
# does not set, so it is not exercised here.
#
# Verification reads the events back via `unmask events`, which needs
# `docker compose exec` into the admin container.  When that is unavailable
# (= the suite is pointed at a remote BASE_URL) the scenario skips cleanly.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

ADMIN_URL=${ADMIN_URL:-http://127.0.0.1:19477}
COMPOSE="$DIR/docker/docker-compose.yml"

# Skip gracefully when the docker e2e stack is not the target (= no admin
# container to exec the events CLI into).
if ! command -v docker >/dev/null 2>&1 || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q admin 2>/dev/null)" ]; then
    log_skip "16-multi-site needs the docker e2e stack (admin container) — skipped"
    exit 0
fi

# fire(IP, Host, extra-header...) — one /api/check hit with a chosen vhost.
fire() {
    local ip="$1" host="$2"; shift 2
    curl -sk -o /dev/null \
        -A "$UA_BROWSER" \
        -H "X-Original-URI: /public" \
        -H "X-Original-IP: $ip" \
        -H "X-Original-Host: $host" \
        "$@" \
        "${ADMIN_URL}/unmask/api/check"
}

# Distinct IPs (RFC 5737 documentation space) so no ban / rate-limit state
# bleeds between the four requests.
fire 198.51.100.61 shop.example.com
fire 198.51.100.62 blog.example.com
fire 198.51.100.63 API.Example.com:8443
fire 198.51.100.64 anything.invalid -H "X-Unmask-Site: customsite"

# Read the event table back, polling until all four sites appear.  The events
# CLI never self-exits (it tails), so each read is a `timeout`-bounded snapshot
# of `--since 0` (= every event).  The old single fixed `timeout 4` read was
# flaky for two compounding reasons: InsertAsync's 1s event flush can lag, and
# `docker compose exec` startup alone eats ~3-4s under load -- so the 4s window
# often expired before the CLI emitted a line, and `|| true` handed back an
# empty dump (all four assertions then failed at once).  Measured: a 3s timeout
# yields 0 lines, 5s yields the full dump.  So: use an 8s read window AND retry
# the whole read until the expected sites are present (or a ~30s deadline).  The
# checks below still run on the last dump, so a genuine miss is reported with it.
want_sites="shop.example.com blog.example.com api.example.com customsite"
dump=""
deadline=$(( $(date +%s) + 30 ))
while :; do
    dump=$(timeout 8 docker compose -f "$COMPOSE" exec -T admin \
        unmask events -config /etc/unmask/admin.yml --since 0 --poll-ms 100 \
        2>/dev/null || true)
    miss=0
    for s in $want_sites; do
        printf '%s' "$dump" | grep -qF "site=$s" || { miss=1; break; }
    done
    { [ "$miss" -eq 0 ] || [ "$(date +%s)" -ge "$deadline" ]; } && break
    sleep 1
done

fails=0
check_site() {
    local desc="$1" needle="$2"
    if echo "$dump" | grep -qF "site=$needle"; then
        log_pass "$desc → site=$needle recorded"
    else
        log_fail "$desc: no event with site=$needle\n--- events dump ---\n$dump"
        fails=$((fails+1))
    fi
}

check_site "Host shop.example.com"          "shop.example.com"
check_site "Host blog.example.com"          "blog.example.com"
check_site "Host API.Example.com:8443 (lowercased, port stripped)" "api.example.com"
check_site "X-Unmask-Site override"         "customsite"

# The bogus Host must NOT have leaked in as its own site (= the override won).
if echo "$dump" | grep -qF "site=anything.invalid"; then
    log_fail "X-Unmask-Site override did not win: site=anything.invalid leaked"
    fails=$((fails+1))
else
    log_pass "X-Unmask-Site override wins over the raw Host header"
fi

exit "$fails"
