#!/bin/bash
# 17: non-GET requests routed to the challenge endpoint get a JSON 403, not
# a 405 "Method Not Allowed".
#
# Regression for the pre-v0.1 405 leak: the `/unmask/_rl/` and
# `/unmask/challenge/` routes were registered as `GET` only, so a POST
# routed through `error_page 429 = @unmask_rate_challenge` (which rewrites
# `POST /api/foo` to `POST /unmask/_rl/api/foo`) hit Go's ServeMux auto-405
# with `Allow: GET, HEAD` and an opaque `Method Not Allowed` body.  Real
# XHR / fetch clients were stuck because nothing in the response told them
# they had been challenged.
#
# New behaviour: any method is accepted on the challenge endpoints.  The
# handler inspects Sec-Fetch-Dest / Accept and picks the format:
#
#   - browser navigation (= Sec-Fetch-Dest: document / Accept: text/html)
#     -> HTML challenge (= same as before for human visitors)
#   - XHR / fetch (= Sec-Fetch-Dest: empty, Sec-Fetch-Mode: cors, etc.)
#     -> JSON 403 with `{error, challenge_url, retry_after, reason}`
#
# Test plan:
#   (a) POST directly to /unmask/_rl/api/foo as a fetch client -> 403 + JSON
#   (b) Same path as a browser navigation -> 403 + text/html (= unchanged)
#   (c) Status MUST NOT be 405 in either case (= guards against re-introducing
#       the method gate)

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

# (a) POST as fetch / XHR (= Sec-Fetch-Dest: empty).
code_api=$(curl -sk -o "$tmpdir/api.body" -w '%{http_code}' \
    -X POST \
    -H 'Sec-Fetch-Dest: empty' \
    -H 'Sec-Fetch-Mode: cors' \
    -H 'Accept: application/json' \
    -H 'Content-Type: application/json' \
    -A "$UA_BROWSER" \
    -d '{"probe":1}' \
    "${BASE_URL}/unmask/_rl/api/foo")

if [ "$code_api" = "405" ]; then
    log_fail "API client POST returned 405 (= GET-only route regression)"
    exit 1
fi
if [ "$code_api" != "403" ]; then
    log_fail "API client POST: expected 403, got $code_api"
    cat "$tmpdir/api.body" | head -c 200 >&2; echo >&2
    exit 1
fi

# Body must be JSON with the documented shape.
if ! grep -q '"error":"challenge_required"' "$tmpdir/api.body"; then
    log_fail "API client body missing error=challenge_required"
    head -c 400 "$tmpdir/api.body" >&2; echo >&2
    exit 1
fi
if ! grep -q '"challenge_url":"/unmask/challenge/' "$tmpdir/api.body"; then
    log_fail "API client body missing challenge_url pointing at /unmask/challenge/"
    head -c 400 "$tmpdir/api.body" >&2; echo >&2
    exit 1
fi
if ! grep -q '"retry_after":600' "$tmpdir/api.body"; then
    log_fail "API client body missing retry_after"
    head -c 400 "$tmpdir/api.body" >&2; echo >&2
    exit 1
fi
# orig_path round-trip: /unmask/_rl/api/foo -> _orig=%2Fapi%2Ffoo
if ! grep -q '_orig=%2Fapi%2Ffoo' "$tmpdir/api.body"; then
    log_fail "API client body missing _orig query reflecting the original path"
    head -c 400 "$tmpdir/api.body" >&2; echo >&2
    exit 1
fi
log_pass "(a) API fetch -> 403 JSON with challenge_required + challenge_url + orig"

# (b) Browser navigation (= Sec-Fetch-Dest: document) keeps HTML challenge.
code_html=$(curl -sk -o "$tmpdir/html.body" -w '%{http_code}' \
    -X GET \
    -H 'Sec-Fetch-Dest: document' \
    -H 'Sec-Fetch-Mode: navigate' \
    -H 'Accept: text/html,application/xhtml+xml' \
    -A "$UA_BROWSER" \
    "${BASE_URL}/unmask/_rl/api/foo")

if [ "$code_html" = "405" ]; then
    log_fail "Browser GET returned 405 (= regression)"
    exit 1
fi
if [ "$code_html" != "403" ]; then
    log_fail "Browser GET: expected 403, got $code_html"
    exit 1
fi
# HTML body shape — challenge.html embeds window.UNMASK.
if ! grep -qE 'window\.UNMASK|<!doctype html>' "$tmpdir/html.body"; then
    log_fail "Browser GET body does not look like challenge HTML"
    head -c 400 "$tmpdir/html.body" >&2; echo >&2
    exit 1
fi
log_pass "(b) Browser navigation -> 403 HTML challenge (unchanged path)"

# (c) Method gate guard: try a handful of methods on /unmask/challenge/.
# All must avoid 405; the API ones must come back JSON, the HTML ones HTML.
for m in PUT DELETE PATCH; do
    code=$(curl -sk -o "$tmpdir/$m.body" -w '%{http_code}' \
        -X "$m" \
        -H 'Sec-Fetch-Dest: empty' \
        -H 'Accept: application/json' \
        -A "$UA_BROWSER" \
        "${BASE_URL}/unmask/challenge/")
    if [ "$code" = "405" ]; then
        log_fail "$m /unmask/challenge/ returned 405 (= method gate regression)"
        exit 1
    fi
    if [ "$code" != "403" ]; then
        log_fail "$m /unmask/challenge/ expected 403, got $code"
        exit 1
    fi
done
log_pass "(c) PUT / DELETE / PATCH all return 403 (not 405)"

log_pass "scenario 17 OK"
exit 0
