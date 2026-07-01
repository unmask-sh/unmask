#!/bin/bash
# 02: browser UA + honeypot path (= /wp-login.php) triggers the 403 challenge.
#
# Challenge fires when:  $is_known_browser=1 AND ($ja4_verdict bot_* OR $serve_bot_challenge=1)
# /wp-login.php is registered in honeypot.map, so $serve_bot_challenge=1.
# The UA is Mozilla/5.0...Chrome, so $is_known_browser=1.
# Expected response: challenge HTML (= 403 Forbidden + body).

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

# Capture the status code while saving the body to a separate file
body_tmp=$(mktemp)
trap 'rm -f "$body_tmp"' EXIT

code=$(curl -sk -A "$UA_BROWSER" -o "$body_tmp" -w '%{http_code}' "${BASE_URL}/wp-login.php")
assert_eq 403 "$code" "GET /wp-login.php (= browser UA + honeypot) returns 403" || exit 1

# Verify the challenge HTML was returned (= identifiers are the embedded JS post-__JA4_HIT__ replace and the __SUBFILTER_PROBE__ trace)
assert_in 'probe=' "$(cat "$body_tmp")" "challenge HTML body contains probe marker"
