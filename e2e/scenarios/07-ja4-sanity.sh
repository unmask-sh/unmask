#!/bin/bash
# 07: native plugin extracts JA4 from the TLS ClientHello.
#
# The demo nginx returns a debug body containing `ja4=<fingerprint>` for `/`.
# A real JA4 looks like `t13d1517h2_8daaf6152771_b0da82dd1658` (= 36 chars).
# Empty / placeholder JA4 means the plugin failed to parse the ClientHello.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

body=$(curl -sk -A "$UA_BROWSER" "${BASE_URL}/")
ja4_line=$(echo "$body" | grep -E '^ja4=' | head -1 | tr -d '\r')
ja4="${ja4_line#ja4=}"

if [ -z "$ja4" ]; then
    log_fail "no ja4 line in body:\n$body"
    exit 1
fi
log "ja4 line: $ja4_line"

# Format: t<ver>d<count>h<count>_<cipher_hash>_<ext_hash>
# Use a loose regex to tolerate variant prefixes (t12, t13, etc).
if echo "$ja4" | grep -qE '^t1[0-9][a-z][0-9]+[a-z][0-9]+_[a-f0-9]+_[a-f0-9]+$'; then
    log_pass "ja4 matches expected shape (= $ja4)"
else
    log_fail "ja4 does not match expected shape: $ja4"
    exit 1
fi
