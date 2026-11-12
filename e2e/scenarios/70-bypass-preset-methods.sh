#!/bin/bash
# 70: the bypass-path presets for fetched files pass GET / HEAD / OPTIONS only.
#
# The default-on presets (robots.txt, a favicon, /static/, /.well-known/,
# health checks, browser metadata) passed every method.  A POST to one went
# through unjudged, and on a site that hands every path it has no file for to
# one script (a PHP front controller: try_files ... /index.php) the body reached
# that script's request parser: the exemption decided for /robots.txt held
# after the internal redirect.  A POST there is now judged like any other
# request; an operator's own bypass path still passes every method, unless the
# row is set to GET / HEAD / OPTIONS only.
#   1. native: GET / HEAD / OPTIONS on /robots.txt pass unjudged (the curl UA
#      is challenged on any other path)
#   2. native: a multipart POST to /robots.txt, /.well-known/x, /healthz and
#      /static/x is challenged (403, the challenge's JSON)
#   3. native: the same POST with a pass cookie goes through
#   4. native: an operator's bypass path (^/e2e-bypass-only/) passes a POST
#   5. native: an operator's row set to GET / HEAD / OPTIONS only
#      (^/e2e-fetch-only/) passes the fetch and judges the POST; the same row
#      for one site (^/e2e-shop-fetch-only/, shop.example.com) does so on that
#      site and is no bypass on another
#   6. native: the sitemaps a sitemap index names and llms.txt pass a GET and
#      judge a POST, like the rest of the preset
#   7. forward-auth nginx (the shipped server.inc sends X-Original-Method):
#      GET on /robots.txt passes, a POST is challenged; the same for the
#      operator's fetched-only row
#   8. forward-auth Apache (the shipped lua): the same
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

IP=203.0.113.170
IP_PASS=203.0.113.171
IP_FA=203.0.113.172
IP_AP=203.0.113.173
# The steps added after the first four judge more requests than one address's
# rate budget covers on top of them, so each has an address of its own.
IP_ROW=203.0.113.174
IP_SITE=203.0.113.175
IP_MAP=203.0.113.176

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

# 5. An operator's row set to GET / HEAD / OPTIONS only.
for m in GET HEAD OPTIONS; do
    assert_eq 200 "$(curl -sk -X "$m" -o /dev/null -w '%{http_code}' -A "$UA_CURL" -H "X-Forwarded-For: $IP_ROW" "${BASE_URL}/e2e-fetch-only/feed")" \
        "native: $m on the operator's fetched-only path passes"
done
assert_eq 403 "$(post "$BASE_URL" "$IP_ROW" "PHPSESSID=e2e70" /e2e-fetch-only/feed)" \
    "native: a multipart POST to the operator's fetched-only path is judged (403)"
assert_in '"challenge_required"' "$(cat "$body")" "native: ... answered with the challenge's JSON, not the backend"

# The same row for one site: on that site as above, on another no bypass.
# The site names resolve to the stack the way scenario 21 reaches them.
E2E_PORT=$(echo "$BASE_URL" | sed -nE 's|^https?://[^:/]+:([0-9]+).*|\1|p')
E2E_PORT=${E2E_PORT:-8443}
site_code() { # <host> <method> <path> -> status, the request sent to <host>
    curl -sk -X "$2" -o /dev/null -w '%{http_code}' -A "$UA_CURL" -H "X-Forwarded-For: $IP_SITE" \
        --resolve "$1:${E2E_PORT}:127.0.0.1" "https://$1:${E2E_PORT}$3"
}
assert_eq 200 "$(site_code shop.example.com GET /e2e-shop-fetch-only/feed)" \
    "native: GET on the site's fetched-only path passes on that site"
assert_eq 403 "$(site_code shop.example.com POST /e2e-shop-fetch-only/feed)" \
    "native: a POST to the site's fetched-only path is judged on that site (403)"
assert_eq 403 "$(site_code blog.example.com GET /e2e-shop-fetch-only/feed)" \
    "native: the site's fetched-only path is no bypass on another site (403)"

# 6. The sitemaps a sitemap index names, and llms.txt, ride the preset.
for p in /sitemap-2026.xml /wp-sitemap-posts-post-1.xml /sitemap.xml.gz /llms.txt /llms-full.txt; do
    assert_eq 200 "$(curl -sk -o /dev/null -w '%{http_code}' -A "$UA_CURL" -H "X-Forwarded-For: $IP_MAP" "${BASE_URL}$p")" \
        "native: GET $p passes (bypass preset)"
    assert_eq 403 "$(post "$BASE_URL" "$IP_MAP" "PHPSESSID=e2e70" "$p")" "native: a multipart POST to $p is judged (403)"
done
assert_eq 403 "$(curl -sk -o /dev/null -w '%{http_code}' -A "$UA_CURL" -H "X-Forwarded-For: $IP_MAP" "${BASE_URL}/blog/sitemap.xml")" \
    "native: a sitemap below the top level is not in the preset (403)"
# The preset bounds the name on either side of "sitemap" (an unbounded pattern
# let one long path hold a worker); a name past the bound is no sitemap.
long=$(printf 'a%.0s' $(seq 1 65))
assert_eq 403 "$(curl -sk -o /dev/null -w '%{http_code}' -A "$UA_CURL" -H "X-Forwarded-For: $IP_MAP" "${BASE_URL}/${long}sitemap.xml")" \
    "native: a name longer than the preset's bound is not in the preset (403)"

# 7-8. Forward-auth: the method rides X-Original-Method from the shipped
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
assert_eq 404 "$(curl -s -o /dev/null -w '%{http_code}' -A "$UA_CURL" -H "X-Forwarded-For: $IP_FA" "${FA_NGINX_URL}/e2e-fetch-only/feed")" \
    "forward-auth nginx: GET on the operator's fetched-only path passes the gate (404 from the static root)"
assert_eq 403 "$(post "$FA_NGINX_URL" "$IP_FA" "PHPSESSID=e2e70" /e2e-fetch-only/feed)" \
    "forward-auth nginx: a multipart POST to the operator's fetched-only path is judged (403)"

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
