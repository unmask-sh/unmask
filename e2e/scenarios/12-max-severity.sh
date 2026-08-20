#!/bin/bash
# 12: auth_check decision pipeline (= max-severity composition).
#
# Verifies that when multiple axes vote, the strongest severity wins and
# its chMode flows to the response header.  Hits the admin's /unmask/api/check
# directly (= bypasses nginx so we control X-Original-IP and X-Client-JA4
# exactly).
#
# Admin.yml fixture (e2e/docker/admin/admin.yml):
#   nginx.geo.rules = [JP: pow_only, CN: deny]
#   nginx.ja4_verdicts.extra = [t13e2e0bot01_xxx_yyy → action=bot]
#   nginx.trusted_lb_extra.cidrs = [0.0.0.0/0]  (= honor X-Client-JA4 from anywhere)
# Compose env: UNMASK_TEST_GEO_OVERRIDE=192.0.2.81:JP,192.0.2.82:CN,192.0.2.83:US
#
# Cases:
#   A) US visitor (= no geo rule, default=skip), benign JA4 → pass
#   B) JP visitor + benign JA4 → pow_only (= geo rule only)
#   C) US visitor + bot JA4 → pow_then_captcha (= ja4 only; the fixture rule
#      has no explicit action, so the chain inherits the operating default)
#   D) JP visitor + bot JA4 → pow_then_captcha (= max(geo:pow_only, ja4))
#   E) CN visitor + bot JA4 → deny (= geo deny > ja4 captcha)

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

ADMIN_URL=${ADMIN_URL:-http://127.0.0.1:19477}

JA4_OK="t13ok000000000_xxx_yyy"        # not in any rule -> verdict=ok
JA4_BOT="t13e2e0bot01_xxx_yyy"          # matches admin.yml extra rule -> action=bot

# check sends /unmask/api/check with the given IP/JA4 and prints status|action|chmode|reason
check() {
    local ip="$1"; local ja4="$2"
    local hdrfile; hdrfile=$(mktemp)
    local code
    code=$(curl -sk -o /dev/null -D "$hdrfile" -w '%{http_code}' \
        -A "$UA_BROWSER" \
        -H "X-Original-URI: /restricted" \
        -H "X-Original-IP: $ip" \
        -H "X-Client-JA4: $ja4" \
        "${ADMIN_URL}/unmask/api/check")
    local action chmode reason
    action=$(grep -i '^X-Unmask-Action:' "$hdrfile" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
    chmode=$(grep -i '^X-Unmask-Chmode:' "$hdrfile" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
    reason=$(grep -i '^X-Unmask-Reason:' "$hdrfile" | head -1 | tr -d '\r' | sed 's/^[^:]*: *//')
    rm -f "$hdrfile"
    echo "$code|$action|$chmode|$reason"
}

fails=0

# A) US + benign JA4 -> pass
res=$(check "192.0.2.83" "$JA4_OK")
log "A: US+ok        = $res"
assert_eq 200 "${res%%|*}"             "A: US+ok → 200" || fails=$((fails+1))
[[ "$res" == *"|pass|"* ]] || { log_fail "A: action != pass: $res"; fails=$((fails+1)); }

# B) JP + benign JA4 -> challenge / chMode=pow_only (geo only)
res=$(check "192.0.2.81" "$JA4_OK")
log "B: JP+ok        = $res"
assert_eq 401 "${res%%|*}"             "B: JP+ok → 401 (geo:pow_only)" || fails=$((fails+1))
[[ "$res" == *"|challenge|pow_only|"* ]] || { log_fail "B: expected challenge|pow_only, got $res"; fails=$((fails+1)); }
[[ "$res" == *"geo:JP:pow_only"* ]]      || { log_fail "B: reason missing geo:JP:pow_only, got $res"; fails=$((fails+1)); }

# C) US + bot JA4 -> challenge / chMode=pow_then_captcha (ja4 only, inherited
#    from the operating default -- the fixture rule pins no action)
res=$(check "192.0.2.83" "$JA4_BOT")
log "C: US+bot       = $res"
assert_eq 401 "${res%%|*}"             "C: US+bot → 401 (ja4: inherited pow_then_captcha)" || fails=$((fails+1))
[[ "$res" == *"|challenge|pow_then_captcha|"* ]] || { log_fail "C: expected challenge|pow_then_captcha, got $res"; fails=$((fails+1)); }
[[ "$res" == *"ja4:e2e-fixture-bot"* ]]      || { log_fail "C: reason missing ja4:e2e-fixture-bot, got $res"; fails=$((fails+1)); }

# D) JP + bot JA4 -> max(pow_only, pow_then_captcha) = pow_then_captcha
res=$(check "192.0.2.81" "$JA4_BOT")
log "D: JP+bot       = $res"
assert_eq 401 "${res%%|*}"             "D: JP+bot → 401 (max -> pow_then_captcha)" || fails=$((fails+1))
[[ "$res" == *"|challenge|pow_then_captcha|"* ]] || { log_fail "D: expected challenge|pow_then_captcha, got $res"; fails=$((fails+1)); }
[[ "$res" == *"ja4:e2e-fixture-bot"* ]]      || { log_fail "D: reason missing ja4:e2e-fixture-bot, got $res"; fails=$((fails+1)); }
[[ "$res" == *"suppressed:"* && "$res" == *"geo:JP:pow_only"* ]] \
    || { log_fail "D: reason missing suppressed:geo:JP:pow_only, got $res"; fails=$((fails+1)); }

# E) CN + bot JA4 -> max(deny, captcha_only) = deny
res=$(check "192.0.2.82" "$JA4_BOT")
log "E: CN+bot       = $res"
assert_eq 403 "${res%%|*}"             "E: CN+bot → 403 (geo:CN:deny wins over ja4)" || fails=$((fails+1))
[[ "$res" == *"|block|"* ]]           || { log_fail "E: action != block, got $res"; fails=$((fails+1)); }
[[ "$res" == *"geo:CN:deny"* ]]       || { log_fail "E: reason missing geo:CN:deny, got $res"; fails=$((fails+1)); }
[[ "$res" == *"suppressed:"* && "$res" == *"ja4:"* ]] \
    || { log_fail "E: reason missing suppressed:ja4:..., got $res"; fails=$((fails+1)); }

if [ "$fails" -eq 0 ]; then
    log_pass "max-severity composition: A-E all match expected outcomes"
    exit 0
fi
log_fail "max-severity composition failed in $fails check(s)"
exit 1
