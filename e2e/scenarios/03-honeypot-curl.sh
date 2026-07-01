#!/bin/bash
# 03: a curl UA hitting /wp-login.php is challenged the same as a browser UA.
#
# Honeypot paths fire for every UA (= $serve_bot_challenge=1 in the
# final_challenge map regardless of $is_known_browser).  curl in particular
# is also in the UA-filter blacklist (= upstream rescue "http-library"
# preset → $is_challenge_target=1), so we'd reach the same 403 even without
# the honeypot trip.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

code=$(http_get /wp-login.php -A "$UA_CURL")
assert_eq 403 "$code" "GET /wp-login.php (= curl UA + honeypot) returns 403"
