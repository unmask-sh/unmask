#!/bin/bash
# 24: the served challenge assets must be the current seed-bound build, never a
# stale pre-seed-bound (djb2) copy, and the page and its script must be of one
# build.
#
# The web1-jp loop shipped a 2026-05-25 djb2 challenge.html/js that the
# seed-bound plugin rejected, looping every visitor.  This scenario fails loudly
# the moment a stale / incompatible asset is served: it checks that the page
# carries a real seed and contains no djb2 PoW, and that the script it runs is
# this daemon's own.
#
# The script is a file beside the page, under a name that is the hash of its
# content: the page can only load the script it was written with,
# and a client that runs nothing is sent the page alone.  A browser that cannot
# load the file asks for the page with the script inside (the _bvi cookie), and
# gets it -- the way out of the loop the script was once always in the page for.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

CLIENT_IP=198.51.100.70
# No trap of its own: assert.sh's EXIT trap is what turns an earlier failed
# assertion into a failed scenario.
TMP=$(mktemp -d)

ch=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" "${BASE_URL}/unmask/challenge/")

# (a) the page carries a filled-in (non-empty) pow_seed -> a seed-bound build.
seed=$(printf '%s' "$ch" | grep -oE '__POW_SEED__\*/"[0-9a-f]+' | grep -oE '[0-9a-f]{16,}' | head -1)
if [ -z "$seed" ]; then
    log_fail "challenge page has no filled-in pow_seed (stale or pre-seed-bound asset?)"
    rm -rf "$TMP"
    exit 1
fi
log "pow_seed present: ${seed:0:12}..."

# (b) the page names the script's file by its hash, and carries no copy of the
#     script beside the name.
name=$(printf '%s' "$ch" | grep -oE '<script[^>]+id="unmask-js"[^>]+src="/unmask/static/challenge\.[0-9a-f]{16}\.js"' \
    | grep -oE 'challenge\.[0-9a-f]{16}\.js' | head -1)
if [ -z "$name" ]; then
    log_fail "challenge page does not name the script's file (<script id=\"unmask-js\" src=\"/unmask/static/challenge.<hash>.js\">)"
    rm -rf "$TMP"
    exit 1
fi
log_pass "challenge page names the script's file: $name"
assert_not_in '_bv_set_ok' "$ch" "the page that names the file does not carry the script as well"
assert_in '/*__JS_INLINE__*/0' "$ch" "the page tells its own script that the challenge script is a file"
plain=$(printf '%s' "$ch" | grep -coE '<script[^>]+src="/unmask/static/challenge\.js')
assert_eq 0 "$plain" "the page does not name the plain /unmask/static/challenge.js"

# (c) the file is this build's script: named after its content, seed-bound, no
#     djb2, kept by the browser, and compressed by the daemon when asked.
code=$(curl -sk -A "$UA_BROWSER" -D "$TMP/h" -o "$TMP/js" -w '%{http_code}' "${BASE_URL}/unmask/static/$name")
assert_eq 200 "$code" "/unmask/static/$name is served"
sum=$(sha256sum "$TMP/js" | cut -c1-16)
assert_eq "challenge.$sum.js" "$name" "the file's name is the hash of its content"
assert_in 'max-age=31536000, immutable' "$(grep -i '^cache-control:' "$TMP/h")" "the file is one a browser keeps"
assert_in 'javascript' "$(grep -i '^content-type:' "$TMP/h")" "the file is served as a script"
js=$(cat "$TMP/js")
assert_in 'pow_seed' "$js" "the script reads window.UNMASK.pow_seed (seed-bound)"
djb2=$(printf '%s' "$ch$js" | grep -ciE 'djb2|0x1505')
assert_eq 0 "$djb2" "neither the page nor its script has djb2 (= no pre-seed-bound PoW)"
curl -sk -A "$UA_BROWSER" -H 'Accept-Encoding: gzip' -D "$TMP/hz" -o "$TMP/js.gz" "${BASE_URL}/unmask/static/$name"
assert_in 'gzip' "$(grep -i '^content-encoding:' "$TMP/hz")" "the file is compressed for a client that takes gzip"
if gzip -dc "$TMP/js.gz" 2>/dev/null | cmp -s - "$TMP/js"; then
    log_pass "the compressed file is the same script"
else
    log_fail "the compressed file does not decompress to the script"
fi

# (d) a name this build does not have -- another build's script, asked of this
#     node -- is not here, and the miss is not one to keep.
code=$(curl -sk -A "$UA_BROWSER" -D "$TMP/h404" -o /dev/null -w '%{http_code}' "${BASE_URL}/unmask/static/challenge.0123456789abcdef.js")
assert_eq 404 "$code" "another build's script name answers 404"
assert_in 'no-store' "$(grep -i '^cache-control:' "$TMP/h404")" "the 404 is not cached"

# (e) the way back: a browser that could not load the file asks for the page
#     with the script inside, and the page then names no file.
ch2=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" -H 'Cookie: _bvi=1' "${BASE_URL}/unmask/challenge/")
assert_in '_bv_set_ok' "$ch2" "asked with the _bvi cookie, the page carries the script"
assert_in '/*__JS_INLINE__*/1' "$ch2" "that page tells its own script the challenge script is inside"
named=$(printf '%s' "$ch2" | grep -coE '<script[^>]+src="/unmask/static/challenge')
assert_eq 0 "$named" "the page with the script inside names no file"

# (f) the plain name (a copy of the page from before the hashed one names it)
#     must likewise be the seed-bound build.
js=$(curl -sk -A "$UA_BROWSER" "${BASE_URL}/unmask/static/challenge.js")
assert_in 'pow_seed' "$js" "/unmask/static/challenge.js reads window.UNMASK.pow_seed (seed-bound)"
djb2js=$(printf '%s' "$js" | grep -ciE 'djb2|0x1505')
assert_eq 0 "$djb2js" "/unmask/static/challenge.js has no djb2 (= no pre-seed-bound PoW)"
rm -rf "$TMP"
