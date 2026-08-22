#!/bin/bash
# 24: the served challenge assets must be the current seed-bound build, never a
# stale pre-seed-bound (djb2) copy.
#
# The web1-jp loop shipped a 2026-05-25 djb2 challenge.html/js that the
# seed-bound plugin rejected, looping every visitor.  This scenario fails loudly
# the moment a stale / incompatible asset is served: it checks that the page
# carries a real seed, inlines its JS, and contains no djb2 PoW.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

CLIENT_IP=198.51.100.70

ch=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" "${BASE_URL}/unmask/challenge/")

# (a) the page carries a filled-in (non-empty) pow_seed -> a seed-bound build.
seed=$(printf '%s' "$ch" | grep -oE '__POW_SEED__\*/"[0-9a-f]+' | grep -oE '[0-9a-f]{16,}' | head -1)
if [ -z "$seed" ]; then
    log_fail "challenge page has no filled-in pow_seed (stale or pre-seed-bound asset?)"
    exit 1
fi
log "pow_seed present: ${seed:0:12}..."

# (b) the JS is inlined -- no external <script src> a client could fail to fetch
#     (the external-fetch failure mode the inline fix removed).
ext=$(printf '%s' "$ch" | grep -coE '<script[^>]+src=[^>]*challenge\.js')
assert_eq 0 "$ext" "challenge page inlines challenge.js (no external <script src=>)"

# (c) the served challenge uses the SHA-256 seed-bound PoW, never the old djb2.
djb2=$(printf '%s' "$ch" | grep -ciE 'djb2|0x1505')
assert_eq 0 "$djb2" "served challenge has no djb2 (= no pre-seed-bound PoW algorithm)"
assert_in 'pow_seed' "$ch" "served challenge references pow_seed (= seed-bound PoW)"

# (d) the /unmask/static/challenge.js route (used by any non-inlined consumer)
#     must likewise be the seed-bound build.
js=$(curl -sk -A "$UA_BROWSER" "${BASE_URL}/unmask/static/challenge.js")
assert_in 'pow_seed' "$js" "/unmask/static/challenge.js reads window.UNMASK.pow_seed (seed-bound)"
djb2js=$(printf '%s' "$js" | grep -ciE 'djb2|0x1505')
assert_eq 0 "$djb2js" "/unmask/static/challenge.js has no djb2 (= no pre-seed-bound PoW)"
