#!/bin/bash
# 18: bypass-path Extra rules use natural path-anchored regex (= `^/foo/`).
#
# Background: pre-v0.1 the bypass map was keyed on `"$host:$request_uri"` and
# the template prefixed `~^[^:]*:` -- combining a Pattern that started with
# `^/foo/` produced `~^[^:]*:^/foo/`, a regex with two start anchors that
# never matched.  Presets shipped with `^` form were silently inactive.
#
# Fix: render bypass-path patterns into `map $request_uri ...` directives so
# the `^` is interpreted as the start of the path, no concatenation, no
# anchor stripping.  This scenario proves the fixed rendering works end to
# end.
#
# Fixture (= e2e admin.yml):
#   bypass_paths.extra: [ "^/e2e-bypass-only/" ]   (= scope to this scenario)
#   bypass_paths.disabled_presets: [ all preset IDs ]  (= deterministic)
#
# Expectations:
#   (a) /e2e-bypass-only/...   -> bypass takes effect (= fc=0, upstream echo)
#   (b) /foo/e2e-bypass-only/  -> anchor blocks mid-URI match (= fc=1)
#   (c) /not-bypassed/         -> challenge engages for the same UA (= fc=1)
# The echo location prints `fc=<final_challenge>` so we can assert exactly.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT

fails=0

# IP isolation: dedicated XFF so honeypot bans from prior scenarios don't
# pre-empt the bypass-path matcher with a banned-IP challenge.
CLIENT_IP=198.51.100.180

# (a) Inside the bypass path -- expect fc=0 + echo body.
curl -sk -A "$UA_CURL" -H "X-Forwarded-For: $CLIENT_IP" \
    -o "$tmpdir/a.body" -w '%{http_code}' \
    "${BASE_URL}/e2e-bypass-only/foo" > "$tmpdir/a.code"
code_a=$(cat "$tmpdir/a.code")
body_a=$(cat "$tmpdir/a.body")
if [ "$code_a" != "200" ]; then
    log_fail "(a) /e2e-bypass-only/foo: expected 200, got $code_a"
    fails=$((fails+1))
elif ! echo "$body_a" | grep -qE 'fc=0'; then
    log_fail "(a) /e2e-bypass-only/foo: bypass not honored (= fc != 0)"
    echo "$body_a" >&2
    fails=$((fails+1))
else
    log_pass "(a) /e2e-bypass-only/foo bypassed (= fc=0)"
fi

# (b) Same substring mid-URI -- must NOT bypass (= anchor enforced).
curl -sk -A "$UA_CURL" -H "X-Forwarded-For: $CLIENT_IP" \
    -o "$tmpdir/b.body" -w '%{http_code}' \
    "${BASE_URL}/foo/e2e-bypass-only/bar" > "$tmpdir/b.code"
code_b=$(cat "$tmpdir/b.code")
body_b=$(cat "$tmpdir/b.body")
# The echo body either reports fc=1 (= still got to @echo via try_files) or
# we see a 403 challenge directly; either way fc must NOT be 0 inside the
# echo and the response shape must not look bypassed.
if echo "$body_b" | grep -qE 'fc=0'; then
    log_fail "(b) /foo/e2e-bypass-only/bar leaked bypass (= ^ anchor not enforced)"
    echo "$body_b" >&2
    fails=$((fails+1))
else
    log_pass "(b) /foo/e2e-bypass-only/bar did NOT bypass (status=$code_b)"
fi

# (c) Unrelated path -- with curl UA the request is normally challenged.
# Confirms the bypass entry doesn't accidentally let everything through.
curl -sk -A "$UA_CURL" -H "X-Forwarded-For: $CLIENT_IP" \
    -o "$tmpdir/c.body" -w '%{http_code}' \
    "${BASE_URL}/not-bypassed/" > "$tmpdir/c.code"
code_c=$(cat "$tmpdir/c.code")
body_c=$(cat "$tmpdir/c.body")
if echo "$body_c" | grep -qE 'fc=0'; then
    log_fail "(c) /not-bypassed/: unexpectedly bypassed (= fc=0)"
    echo "$body_c" >&2
    fails=$((fails+1))
else
    log_pass "(c) /not-bypassed/ not bypassed (status=$code_c)"
fi

exit "$fails"
