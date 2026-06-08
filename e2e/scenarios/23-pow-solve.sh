#!/bin/bash
# 23: solve the seed-bound SHA-256 PoW (= challenge.js's exact algorithm) and
# pass the challenge with the resulting _bv.
#
# Guards against a challenge.js <-> plugin seed-binding desync.  The tool1-jp
# production loop was a stale challenge.js that solved a seedless/djb2 PoW the
# seed-bound plugin rejected, looping every visitor -- and the curl-based e2e
# never exercised the PoW (only the CAPTCHA _bv in 04 and tamper in 08), so it
# escaped to production.  This scenario re-runs the verifier's exact algorithm
# end-to-end: the daemon issues the seed, we solve it, the native plugin must
# recompute the same seed and accept the cookie.
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

CLIENT_IP=198.51.100.66

# 1. Fetch the challenge page (browser UA, no _bv) and read the server-supplied
#    PoW seed / issued-at / difficulty out of window.UNMASK.
ch=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" "${BASE_URL}/unmask/challenge/")
seed=$(printf '%s' "$ch" | grep -oE '__POW_SEED__\*/"[0-9a-f]+' | grep -oE '[0-9a-f]{40}' | head -1)
issued=$(printf '%s' "$ch" | grep -oE '__ISSUED_AT__\*/[0-9]+' | grep -oE '[0-9]{6,}' | head -1)
diff=$(printf '%s' "$ch" | grep -oE '__POW_DIFFICULTY__\*/[0-9]+' | grep -oE '[0-9]+$' | head -1)
if [ -z "$seed" ] || [ -z "$issued" ]; then
    log_fail "challenge page missing pow_seed/issued_at (stale or pre-seed-bound asset?): seed='$seed' issued='$issued'"
    exit 1
fi
log "challenge: seed=${seed:0:12}... issued=$issued diff=${diff:-18}"

# 2. Brute-force the nonce: the first n where sha256("<seed>:<n>") has
#    >= difficulty leading zero bits -- byte-for-byte the loop in challenge.js
#    and the verifier in cookies.go verifyPowSHA256 / the C plugin.
bv=$(python3 - "$seed" "$issued" "${diff:-18}" <<'PY'
import hashlib, string, sys
seed, issued, diff = sys.argv[1], sys.argv[2], int(sys.argv[3])
DIG = string.digits + string.ascii_lowercase
n = 0
while True:
    h = hashlib.sha256(f"{seed}:{n}".encode()).digest()
    bits = 0
    for byte in h:
        if byte == 0:
            bits += 8
            continue
        while not (byte & 0x80):
            bits += 1
            byte <<= 1
        break
    if bits >= diff:
        m, b36 = n, ""
        while m:
            b36 = DIG[m % 36] + b36
            m //= 36
        print(f"{issued}.pow2.{b36 or '0'}.0")
        break
    n += 1
PY
)
[ -n "$bv" ] || { log_fail "PoW solve produced no _bv"; exit 1; }
log "solved _bv=$bv"

# 3. Request a challenged path with the solved _bv.  The native plugin must
#    recompute the same seed (BV secret + this IP + host + issued) and accept
#    the PoW -> 200.  A seed desync (the production bug) would re-challenge -> 403.
code=$(curl -sk -A "$UA_BROWSER" -H "X-Forwarded-For: $CLIENT_IP" -H "Cookie: _bv=$bv" \
    -o /dev/null -w '%{http_code}' "${BASE_URL}/wp-login.php")
assert_eq 200 "$code" "GET /wp-login.php with a solved seed-bound PoW _bv returns 200"
