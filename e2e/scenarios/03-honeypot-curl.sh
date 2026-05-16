#!/bin/bash
# 03: a curl UA hitting /wp-login.php passes through (= no challenge).
#
# By design, UAs that don't claim to be a known browser (= curl/python-requests/etc)
# never receive a challenge.  Even honeypot paths return 200 (= rate-limit is the
# blocking mechanism for those flows).  This achieves "let honest bots through silently,
# only challenge fake-browser UAs".

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

code=$(http_get /wp-login.php -A "$UA_CURL")
assert_eq 200 "$code" "GET /wp-login.php (= curl UA, honeypot but unknown-browser) returns 200"
