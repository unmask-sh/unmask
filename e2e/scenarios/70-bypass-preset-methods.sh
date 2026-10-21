#!/bin/bash
# 70: the bypass-path presets for fetched files pass GET / HEAD / OPTIONS only.
#
# The default-on presets (robots.txt, a favicon, /static/, /.well-known/,
# health checks, browser metadata) passed every method.  A POST to one went
# through unjudged, and on a site that hands every path it has no file for to
# one script (a PHP front controller: try_files ... /index.php) the body reached
# that script's request parser: the exemption decided for /robots.txt held
# after the internal redirect.  A POST there is now judged like any other
# request; an operator's own bypass path still passes every method.
#   1. native: GET / HEAD / OPTIONS on /robots.txt pass unjudged (the curl UA
#      is challenged on any other path)
#   2. native: a multipart POST to /robots.txt, /.well-known/x, /healthz and
#      /static/x is challenged (403, the challenge's JSON)
#   3. native: the same POST with a pass cookie goes through
#   4. native: an operator's bypass path (^/e2e-bypass-only/) passes a POST
#   5. forward-auth nginx (the shipped server.inc sends X-Original-Method):
#      GET on /robots.txt passes, a POST is challenged
#   6. forward-auth Apache (the shipped lua): the same
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

IP=203.0.113.170
IP_PASS=203.0.113.171
IP_FA=203.0.113.172
IP_AP=203.0.113.173

up=$(mktemp)
body=$(mktemp)
# Clean up AND keep assert.sh's exit guard: a bare `trap ... EXIT` here would
# replace _e2e_exit_guard, and a FAIL with no explicit `exit 1` would report
# the scenario as passed.
cleanup() { rc=$?; rm -f "$up" "$body"; [ "$rc" -eq 0 ] && [ "${_E2E_FAILS:-0}" -gt 0 ] && exit 1; exit "$rc"; }
trap cleanup EXIT
printf 'e2e upload\n' > "$up"

# post <base-url> <ip> <cookie> <path> -> HTTP status of a multipart POST shaped
# like a PHP upload (a session cookie, an upload-progress field, a file); the
# body lands in $body.
post() {
    curl -sk -o "$body" -w '%{http_code}' -A "$UA_CURL" -H "X-Forwarded-For: $2" \
        -H "Cookie: $3" -F 'PHP_SESSION_UPLOAD_PROGRESS=e2e' -F "file=@$up;filename=a.txt" \
        "$1$4"
}

# Baseline: the curl UA is challenged off the presets.
assert_eq 403 "$(curl -sk -o /dev/null -w '%{http_code}' -A "$UA_CURL" -H "X-Forwarded-For: $IP" "${BASE_URL}/")" \
    "native: the curl UA is challenged on / (baseline)"

# 1. Fetches pass.
assert_eq 200 "$(curl -sk -o /dev/null -w '%{http_code}' -A "$UA_CURL" -H "X-Forwarded-For: $IP" "${BASE_URL}/robots.txt")" \
    "native: GET /robots.txt passes (bypass preset)"
assert_eq 200 "$(curl -sk -I -o /dev/null -w '%{http_code}' -A "$UA_CURL" -H "X-Forwarded-For: $IP" "${BASE_URL}/robots.txt")" \
    "native: HEAD /robots.txt passes"
assert_eq 200 "$(curl -sk -X OPTIONS -o /dev/null -w '%{http_code}' -A "$UA_CURL" -H "X-Forwarded-For: $IP" "${BASE_URL}/robots.txt")" \
    "native: OPTIONS /robots.txt passes (a CORS preflight)"

# 2. A POST is judged.
for p in /robots.txt /.well-known/x /healthz /static/x; do
    assert_eq 403 "$(post "$BASE_URL" "$IP" "PHPSESSID=e2e70" "$p")" "native: a multipart POST to $p is judged (403)"
    assert_in '"challenge_required"' "$(cat "$body")" "native: ... answered with the challenge's JSON, not the backend"
done

# 3. With a pass cookie the POST goes through, as anywhere else.
ch=$(curl -sk -A "$UA_CURL" -H "X-Forwarded-For: $IP_PASS" "${BASE_URL}/unmask/challenge/")
seed=$(printf '%s' "$ch" | grep -oE '__POW_SEED__\*/"[0-9a-f]+' | grep -oE '[0-9a-f]{40}' | head -1)
issued=$(printf '%s' "$ch" | grep -oE '__ISSUED_AT__\*/[0-9]+' | grep -oE '[0-9]{6,}' | head -1)
diff=$(printf '%s' "$ch" | grep -oE '__POW_DIFFICULTY__\*/[0-9]+' | grep -oE '[0-9]+$' | head -1)
bv=""
if [ -n "$seed" ] && [ -n "$issued" ]; then
    bv=$(python3 "$DIR/lib/powsolve.py" "$seed" "$issued" "${diff:-18}")
fi
if [ -n "$bv" ]; then
    assert_eq 200 "$(post "$BASE_URL" "$IP_PASS" "PHPSESSID=e2e70; _bv=$bv" /robots.txt)" \
        "native: the POST with a pass cookie goes through (200)"
else
    log_fail "native: no PoW pass to post with"
fi

# 4. An operator's bypass path passes every method.
assert_eq 200 "$(post "$BASE_URL" "$IP" "PHPSESSID=e2e70" /e2e-bypass-only/upload)" \
    "native: a POST to the operator's bypass path passes (200)"

# 5-6. Forward-auth: the method rides X-Original-Method from the shipped
#      server.inc and lua.  Neither container runs in socket mode.
if [ "${UNMASK_E2E_SOCKET:-}" = "1" ]; then
    log_skip "forward-auth checks: the forward-auth containers are not part of socket mode"
    exit 0
fi

# fa-nginx: a passed GET reaches the static root, which has no robots.txt (404);
# a judged POST is rewritten to the challenge route (403, the JSON).
assert_eq 404 "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA_CURL" -H "X-Forwarded-For: $IP_FA" "${FA_NGINX_URL}/robots.txt")" \
    "forward-auth nginx: GET /robots.txt passes the gate (404 from the static root)"
assert_eq 403 "$(post "$FA_NGINX_URL" "$IP_FA" "PHPSESSID=e2e70" /robots.txt)" \
    "forward-auth nginx: a multipart POST to /robots.txt is judged (403)"
assert_in '"challenge_required"' "$(cat "$body")" "forward-auth nginx: ... the challenge's JSON"

# Apache: a judged request is redirected to the challenge page (302).
hdr=$(curl -s -o /dev/null -D - -A "$UA_CURL" -H "X-Forwarded-For: $IP_AP" "${APACHE_URL}/robots.txt" | tr -d '\r')
if printf '%s' "$hdr" | grep -qi '^location: .*/unmask/challenge/'; then
    log_fail "forward-auth Apache: GET /robots.txt was challenged; the preset must pass it"
else
    log_pass "forward-auth Apache: GET /robots.txt passes the gate"
fi
hdr=$(curl -s -o /dev/null -D - -A "$UA_CURL" -H "X-Forwarded-For: $IP_AP" -H "Cookie: PHPSESSID=e2e70" \
    -F 'PHP_SESSION_UPLOAD_PROGRESS=e2e' -F "file=@$up;filename=a.txt" "${APACHE_URL}/robots.txt" | tr -d '\r')
if printf '%s' "$hdr" | grep -qi '^location: .*/unmask/challenge/'; then
    log_pass "forward-auth Apache: a multipart POST to /robots.txt is judged (redirected to the challenge)"
else
    log_fail "forward-auth Apache: a multipart POST to /robots.txt was not judged: $(printf '%s' "$hdr" | head -1)"
fi
