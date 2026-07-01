#!/bin/bash
# 01: a regular UA hitting / should return 200 and pass through (= no challenge).

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"

code=$(http_get / -A "$UA_BROWSER")
assert_eq 200 "$code" "GET / (= browser UA, no honeypot) returns 200"
