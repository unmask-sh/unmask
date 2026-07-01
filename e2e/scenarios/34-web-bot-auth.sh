#!/bin/bash
# 34: Web Bot Auth (RFC 9421) end-to-end in native mode.
#
# A signed agent's request detours through server.inc's /_unmask/_signed_route
# (gated on "signed AND would-be-challenged"), the admin daemon verifies the
# ed25519 signature against the operator's JWK directory (served by the fake
# operator vhost https://nginx:9444/ inside the compose network, fixtures in
# e2e/docker/wba/), and a verified agent skips the challenge while everything
# else degrades to the normal flow.  Covers:
#   - unsigned baseline still challenges
#   - a signature on a NON-challenged request causes no detour (= the
#     dlvr.it regression shape: feed fetchers must never see 404/500)
#   - a garbage signature degrades to the normal challenge (not 404/500)
#   - a valid signature passes through to the proxied content
#   - replaying the same nonce is rejected (anti-replay)
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

WBA="$DIR/docker/wba"
SIGN_ARGS=(-seed "$WBA/signer-ed25519.seed" -kid "$(cat "$WBA/signer.kid")"
           -authority localhost -agent "https://nginx:9444/")

# sign [extra wbasign flags...] -> emits 3 "Header: value" lines on stdout.
sign() { go run "$DIR/lib/wbasign.go" "${SIGN_ARGS[@]}" "$@"; }

# code <ip> <path> [curl args...] -> HTTP status as a challenge-target UA.
code() {
    local ip="$1" path="$2"; shift 2
    curl -sk -A "$UA_CURL" -H "X-Forwarded-For: $ip" "$@" \
        -o /dev/null -w '%{http_code}' "${BASE_URL}${path}"
}

# 1. Baseline: a challenge-target UA without a signature is challenged.
assert_eq 403 "$(code 203.0.113.41 /wba-test)" "unsigned challenge-target UA is challenged (403)"

# 2. A signature on a request that would NOT be challenged (browser UA) takes
#    the normal fast path untouched — no signed-route detour, no 404/500.
#    This is the dlvr.it regression shape (signed feed fetcher on a bypass).
garbage=(-H 'Signature-Input: sig1=("@authority");created=1;keyid="nosuch";tag="web-bot-auth"'
         -H 'Signature: sig1=:bm90aGluZw==:'
         -H 'Signature-Agent: sig1="https://nginx:9444/"')
st=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: 203.0.113.42" "${garbage[@]}" \
    -o /dev/null -w '%{http_code}' "${BASE_URL}/")
assert_eq 200 "$st" "signature on a non-challenged request causes no detour (200)"

# 3. A garbage signature on a challenged request degrades to the normal
#    challenge — the daemon rejects, nginx falls back; never 404/500.
assert_eq 403 "$(code 203.0.113.43 /wba-test "${garbage[@]}")" \
    "garbage signature degrades to the normal challenge (403, not 404/500)"

# 4. A valid signature passes: gate -> auth_request -> daemon verifies against
#    the operator directory -> pass -> re-entry skips the challenge -> the
#    proxied content answers.  ONE request for status + body: each signature
#    carries a single-use nonce, so a second curl with the same headers would
#    be a replay (= case 5's subject) and get challenged.
mapfile -t SIG < <(sign)
tmp=$(mktemp)
st=$(curl -sk -A "$UA_CURL" -H "X-Forwarded-For: 203.0.113.44" \
    -H "${SIG[0]}" -H "${SIG[1]}" -H "${SIG[2]}" \
    -o "$tmp" -w '%{http_code}' "${BASE_URL}/wba-test")
body=$(head -1 "$tmp"); rm -f "$tmp"
assert_eq 200 "$st" "valid signature skips the challenge (200)"
assert_eq "[unmask e2e]" "$body" "verified agent reaches the proxied content"

# 5. Anti-replay: the exact same signature (same nonce) is rejected on reuse.
#    (Case 4's body fetch already consumed a fresh signature once; here we pin
#    a nonce, use it, then use it AGAIN and expect the challenge.)
mapfile -t PIN < <(sign -nonce e2e-replay-nonce-34)
st=$(code 203.0.113.45 /wba-test -H "${PIN[0]}" -H "${PIN[1]}" -H "${PIN[2]}")
assert_eq 200 "$st" "pinned-nonce signature passes on first use (200)"
st=$(code 203.0.113.45 /wba-test -H "${PIN[0]}" -H "${PIN[1]}" -H "${PIN[2]}")
assert_eq 403 "$st" "replaying the same nonce is rejected (403)"

# 6. A fresh signature still passes after the replay rejection.
mapfile -t SIG2 < <(sign)
assert_eq 200 "$(code 203.0.113.46 /wba-test -H "${SIG2[0]}" -H "${SIG2[1]}" -H "${SIG2[2]}")" \
    "fresh nonce passes again after a replay rejection (200)"
