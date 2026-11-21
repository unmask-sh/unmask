#!/bin/bash
# 76: the challenge page reaches a client that reads gzip compressed, through
# an nginx whose own gzip is off -- as it is in the gateway image, in a stock
# nginx.conf, and for any request that arrived through a load balancer where
# nobody wrote gzip_proxied.
#
# The daemon compresses the page before nginx sees it, and nginx passes an
# answer that already carries a Content-Encoding as it is.  The page a rate
# limit answers with is a 429, a status nginx's gzip never compresses: it is
# compressed the same way.  A client that did not ask for gzip is sent the
# page as it always was.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

CLIENT_IP=198.51.100.176
# No trap of its own: assert.sh's EXIT trap is what turns an earlier failed
# assertion into a failed scenario.
TMP=$(mktemp -d)

# ask <name> <path> [curl args...]: headers in $TMP/<name>.h, body in
# $TMP/<name>.body, prints the status.
ask() {
    local name="$1" path="$2"; shift 2
    curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" "$@" \
        -D "$TMP/$name.h" -o "$TMP/$name.body" -w '%{http_code}' "${BASE_URL}${path}"
}
hdr() { grep -i "^$2:" "$TMP/$1.h" | tr -d '\r' | cut -d' ' -f2- | head -1; }

# (a) not asked for: the page as it is.
code=$(ask plain /unmask/challenge/)
assert_eq 403 "$code" "the challenge page, asked for without Accept-Encoding, answers 403"
assert_eq "" "$(hdr plain content-encoding)" "and carries no Content-Encoding"
assert_in 'id="unmask-js"' "$(cat "$TMP/plain.body")" "and is the page itself"
plain_size=$(wc -c < "$TMP/plain.body")

# (b) asked for, as a browser asks: compressed by the daemon, passed by nginx.
code=$(ask gz /unmask/challenge/ -H 'Accept-Encoding: gzip, deflate, br, zstd')
assert_eq 403 "$code" "the challenge page, asked for with Accept-Encoding: gzip, answers 403"
assert_eq gzip "$(hdr gz content-encoding)" "and is gzip"
assert_in 'Accept-Encoding' "$(hdr gz vary)" "and says the answer varies with Accept-Encoding"
assert_in 'no-store' "$(hdr gz cache-control)" "and is still not to be stored"
if gzip -dc "$TMP/gz.body" > "$TMP/gz.html" 2>"$TMP/gz.err"; then
    log_pass "the body is a whole gzip stream"
else
    log_fail "the body does not decode: $(head -c 200 "$TMP/gz.err")"
fi
assert_in 'id="unmask-js"' "$(cat "$TMP/gz.html")" "what decodes is the page that names the script's file"
assert_in '</html>' "$(tail -c 200 "$TMP/gz.html")" "to its last tag"
gz_size=$(wc -c < "$TMP/gz.body"); html_size=$(wc -c < "$TMP/gz.html")
# The two pages differ in what is drawn for each serve, never in length by
# more than a few bytes.
d=$((html_size - plain_size)); [ "$d" -lt 0 ] && d=$((-d))
if [ "$d" -le 64 ]; then
    log_pass "the decoded page is the size of the page as it is ($html_size and $plain_size bytes)"
else
    log_fail "the decoded page is $html_size bytes and the page as it is $plain_size"
fi
if [ $((gz_size * 100)) -le $((html_size * 45)) ]; then
    log_pass "$gz_size bytes on the wire for a page of $html_size"
else
    log_fail "$gz_size bytes on the wire for a page of $html_size: not what compressing is for"
fi
cl=$(hdr gz content-length)
if [ -n "$cl" ]; then
    assert_eq "$gz_size" "$cl" "Content-Length is the size of what was sent"
fi

# (c) a client that refuses gzip is not sent it.
code=$(ask refused /unmask/challenge/ -H 'Accept-Encoding: gzip;q=0, identity')
assert_eq "" "$(hdr refused content-encoding)" "Accept-Encoding: gzip;q=0 is answered with the page as it is"

# (d) the page of a rate limit: a 429, compressed the same way.
code=$(ask rl /unmask/_rl/docs/ -H 'Accept-Encoding: gzip')
assert_eq 429 "$code" "the page of a rate limit answers 429"
assert_eq gzip "$(hdr rl content-encoding)" "and is gzip too (nginx's own gzip never compresses a 429)"
if gzip -dc "$TMP/rl.body" > "$TMP/rl.html" 2>/dev/null; then
    assert_in '</html>' "$(tail -c 200 "$TMP/rl.html")" "and decodes to a whole page"
else
    log_fail "the 429 body does not decode"
fi

# (e) the script's file is compressed by the daemon as before, and still once.
name=$(grep -oE 'challenge\.[0-9a-f]{16}\.js' "$TMP/gz.html" | head -1)
code=$(ask js "/unmask/static/$name" -H 'Accept-Encoding: gzip')
assert_eq 200 "$code" "the script's file is served"
assert_eq gzip "$(hdr js content-encoding)" "compressed"
if gzip -dc "$TMP/js.body" 2>/dev/null | grep -q 'pow_seed'; then
    log_pass "and decodes to the script"
else
    log_fail "the script's file does not decode to the script"
fi

rm -rf "$TMP"
