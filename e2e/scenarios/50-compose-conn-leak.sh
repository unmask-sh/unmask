#!/bin/bash
# 50: a composed redirect must not strand the client connection.
#
# Regression guard for the 0.1.5 connection leak (= the 2026-07-15 fleet
# outage).  The compose-mode ACCESS handler called ngx_http_internal_redirect()
# without the paired ngx_http_finalize_request(r, NGX_DONE) that hands back
# the request reference the redirect takes (= nginx's own X-Accel-Redirect
# idiom).  CONTENT-phase callers recover that reference through their phase
# checker; the ACCESS phase checker maps NGX_DONE to "handled" WITHOUT
# finalizing, so every composed challenge / rate-limit redirect left
# r->main->count one too high.  The response still went out, but the
# connection never re-entered keepalive: the next request on it sat unread
# forever, and the orphans accumulated until worker_connections ran out and
# nginx stopped answering entirely.
#
# Detection = the outage's own signature, observable over plain HTTP: send TWO
# challenged requests over ONE keep-alive connection.
#   fixed -> both are answered, request 2 reuses the connection
#   leaky -> request 1 answers, request 2 gets no response, curl exits 28
#
# /login/ is the captcha-mode protected path (= admin.yml, scenario 20), so a
# browser UA is challenged deterministically; in compose mode that challenge
# IS the ACCESS-phase internal redirect that leaked.  The rate-limit redirect
# (= /unmask/_rl) goes through the same helper (ngx_unmask_access_redirect),
# so one probe covers both redirect sites.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

body1=$(mktemp); body2=$(mktemp); codes=$(mktemp)
trap 'rm -f "$body1" "$body2" "$codes"' EXIT

# One curl invocation, two URLs -> one TLS connection, two HTTP/1.1 requests.
# -o pairs with URLs positionally.  --max-time caps the whole invocation so a
# stranded request 2 fails fast instead of hanging the suite.
curl -sk --http1.1 --max-time 10 \
    -A "$UA_BROWSER" -H 'X-Forwarded-For: 203.0.113.60' \
    -w '%{http_code} %{num_connects}\n' \
    -o "$body1" -o "$body2" \
    "${BASE_URL}/login/" "${BASE_URL}/login/" > "$codes"
rc=$?

if [ "$rc" = "28" ]; then
    log_fail "request 2 got no response on the kept-alive connection (curl exit 28) = the 0.1.5 leak signature (composed redirect stranded the connection)"
    log "→ an ACCESS-phase ngx_http_internal_redirect must be paired with ngx_http_finalize_request(r, NGX_DONE) — see ngx_unmask_access_redirect()"
    exit 1
fi
if [ "$rc" != "0" ]; then
    log_fail "curl exited $rc (wanted a clean two-request keepalive probe)"
    exit 1
fi

code1=$(awk 'NR==1 {print $1}' "$codes")
code2=$(awk 'NR==2 {print $1}' "$codes")
conn2=$(awk 'NR==2 {print $2}' "$codes")
log "request1=$code1 request2=$code2 new_connections_for_request2=$conn2"

# Both requests must be answered with the challenge (403 + challenge HTML,
# the scenario-20 baseline for /login/).
assert_eq 403 "$code1" "request 1: composed challenge answered"
if grep -qF 'probe=' "$body1"; then
    log_pass "request 1: challenge HTML body"
else
    log_fail "request 1: body is not the challenge page"
fi
assert_eq 403 "$code2" "request 2 on the same connection: answered too"

# ...and request 2 must actually have REUSED the connection; a fresh socket
# (num_connects=1) means keepalive never happened and this probe proved
# nothing about the leak.
assert_eq 0 "$conn2" "request 2 reused the keep-alive connection"

exit 0
