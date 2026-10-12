#!/bin/bash
# 67: custom rules on the nginx-module path: a real nginx loads a render that
# carries rules, and each rule answers the way it is set.
#
# A rule is rendered into nginx's own configuration -- a map (or a geo block)
# per condition line, a map that ANDs the lines, a first-match chain into
# $unmask_cr_id, the hard-deny composite, and a limit_req zone per throttling
# rule.  The Go tests read that text; this is the one place nginx itself loads
# it and answers requests with it.
#
# The rules, top to bottom (first match wins):
#   cre2edeny    path ^/cr-e2e/deny/   AND ua e2e-cr-deny                 -> deny
#   cre2ecap     path ^/cr-e2e/captcha/ AND ua e2e-cr-captcha AND host    -> CAPTCHA
#   cre2efirst   path ^/cr-e2e/order/                                     -> PoW
#   cre2esecond  path ^/cr-e2e/order/                                     -> deny (never: the first wins)
#   cre2erate    ip 198.51.100.170 AND path ^/cr-e2e/rate/  -> judgement unchanged, 2/min, over it deny
#   cre2eoff     disabled, path ^/cr-e2e/off/                             -> deny (never: not rendered)
#
# Flow: add the rules to config.yml, restart the daemon (its start renders
# http.inc / protect.inc into the shared volume), reload nginx -- no new
# [emerg] -- then ask.  Afterwards the original config goes back the same way.
#
# Needs the docker e2e stack (it restarts the daemon and reloads nginx).
set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=../lib/env.sh
. "$DIR/lib/env.sh"
# shellcheck source=../lib/assert.sh
. "$DIR/lib/assert.sh"
# shellcheck source=../lib/stack.sh
. "$DIR/lib/stack.sh"

COMPOSE="${COMPOSE:-$DIR/docker/docker-compose.yml}"
if ! command -v docker >/dev/null 2>&1 || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q unmask 2>/dev/null)" ] || \
   [ -z "$(docker compose -f "$COMPOSE" ps -q nginx 2>/dev/null)" ]; then
    log_skip "67-custom-rules-native needs the docker e2e stack (unmask + nginx containers) — skipped"
    exit 0
fi
if ! command -v python3 >/dev/null 2>&1; then
    log_skip "67-custom-rules-native needs python3 to edit the fixture — skipped"
    exit 0
fi

# RFC 5737 addresses of this scenario's own.
IP=198.51.100.168
IP_RATE=198.51.100.170
IP_RATE_OTHER=198.51.100.171
CFG=/etc/unmask/config.yml
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

healthz() {
    curl -sk -o /dev/null -w '%{http_code}' --max-time 3 "${BASE_URL}/unmask/healthz"
}
wait_healthz_200() {
    local i
    for i in $(seq 1 60); do
        [ "$(healthz)" = 200 ] && return 0
        sleep 1
    done
    return 1
}
# get <path> <client ip> [ua]: prints the status; the body is left in $WORK/body.
get() {
    curl -sk -A "${3:-$UA_BROWSER}" -H "X-Forwarded-For: $2" -o "$WORK/body" \
        -w '%{http_code}' --max-time 10 "${BASE_URL}$1"
}
# switch_config <file>: install it as the daemon's config, restart the daemon
# (its start re-renders the includes), reload nginx so it reads the render.
switch_config() {
    local c
    c=$(docker compose -f "$COMPOSE" ps -q unmask)
    docker cp "$1" "$c:$CFG" >/dev/null 2>&1 || { log "docker cp into the unmask container failed"; return 1; }
    stack_restart "$COMPOSE" || return 1
    wait_healthz_200 || { log "daemon did not come back (healthz $(healthz))"; return 1; }
    docker compose -f "$COMPOSE" exec -T nginx /usr/sbin/nginx -c /etc/nginx/nginx.conf -s reload >/dev/null 2>&1 \
        || { log "nginx -s reload failed"; return 1; }
    sleep 1
}
nginx_emerg_count() {
    docker compose -f "$COMPOSE" exec -T nginx sh -c 'grep -c "\[emerg\]" /var/log/nginx/error.log 2>/dev/null || true' | tr -d '\r'
}

C=$(docker compose -f "$COMPOSE" ps -q unmask)
docker cp "$C:$CFG" "$WORK/orig.yml" >/dev/null 2>&1 || { log_fail "could not read the daemon's config.yml"; exit 1; }
python3 - "$WORK/orig.yml" "$WORK/rules.yml" <<'PY'
import sys
rules = '''  custom_rules:
    - id: cre2edeny
      enabled: true
      conditions:
        - kind: path
          values: ["^/cr-e2e/deny/"]
        - kind: ua
          values: ["e2e-cr-deny"]
      action: deny
    - id: cre2ecap
      enabled: true
      conditions:
        - kind: path
          values: ["^/cr-e2e/captcha/"]
        - kind: ua
          values: ["e2e-cr-captcha"]
        - kind: host
          values: ["localhost"]
      action: captcha_only
    - id: cre2efirst
      enabled: true
      conditions:
        - kind: path
          values: ["^/cr-e2e/order/"]
      action: pow_only
    - id: cre2esecond
      enabled: true
      conditions:
        - kind: path
          values: ["^/cr-e2e/order/"]
      action: deny
    - id: cre2erate
      enabled: true
      conditions:
        - kind: ip
          values: ["198.51.100.170"]
        - kind: path
          values: ["^/cr-e2e/rate/"]
      action: monitor
      rate_per_min: 2
      rate_action: deny
    - id: cre2eoff
      enabled: false
      conditions:
        - kind: path
          values: ["^/cr-e2e/off/"]
      action: deny
'''
src = open(sys.argv[1]).read().splitlines(keepends=True)
out, done = [], False
for line in src:
    out.append(line)
    if not done and line.rstrip("\n") == "nginx:":
        out.append(rules)
        done = True
assert done, "the nginx: block was not found in the fixture"
open(sys.argv[2], "w").write("".join(out))
PY

fails=0
emerg_before=$(nginx_emerg_count)
if ! switch_config "$WORK/rules.yml"; then
    log_fail "could not switch the stack to the custom rules"
    exit 1
fi
# A render nginx refused would leave the old configuration running and every
# check below reading the previous behaviour; name it when it happens.
emerg_after=$(nginx_emerg_count)
assert_eq "$emerg_before" "$emerg_after" "custom rules: nginx reloaded into the render (no new [emerg] in its error log)" || fails=$((fails+1))
inc=$(docker compose -f "$COMPOSE" exec -T nginx sh -c 'grep -c "\"cre2e[a-z]*\";" /etc/unmask/http.inc; grep -c "crrate_" /etc/unmask/protect.inc' 2>/dev/null | tr -d '\r' | tr '\n' ' ')
case "$inc" in
    "0 "*|*" 0 ") log_fail "custom rules: not in the render (rule ids in http.inc, zone in protect.inc: $inc)"; fails=$((fails+1)) ;;
    *) log_pass "custom rules: rendered (rule ids in http.inc, the throttle zone in protect.inc)" ;;
esac
if docker compose -f "$COMPOSE" exec -T nginx sh -c 'grep -q cre2eoff /etc/unmask/http.inc' 2>/dev/null; then
    log_fail "custom rules: the disabled rule was rendered"
    fails=$((fails+1))
fi

# deny: both lines hold -> the blocked answer, named for the rule.  A request
# that is not a page navigation (Sec-Fetch-Dest: empty, as fetch() sends) gets
# it as JSON, which carries the reason the event was recorded under.
code=$(get /cr-e2e/deny/x "$IP" "$UA_BROWSER e2e-cr-deny")
assert_eq 403 "$code" "deny rule: path + UA -> 403" || fails=$((fails+1))
if grep -q '__CHMODE__' "$WORK/body"; then
    log_fail "deny rule: a challenge page came back instead of the blocked page"
    fails=$((fails+1))
fi
code=$(curl -sk -A "$UA_BROWSER e2e-cr-deny" -H "X-Forwarded-For: $IP" -H 'Sec-Fetch-Dest: empty' \
    -o "$WORK/body" -w '%{http_code}' --max-time 10 "${BASE_URL}/cr-e2e/deny/x")
if [ "$code" = 403 ] && grep -q '"error":"blocked"' "$WORK/body" && grep -q '"reason":"custom_rule"' "$WORK/body"; then
    log_pass "deny rule: the blocked answer, recorded as custom_rule"
else
    log_fail "deny rule: want the blocked JSON with reason custom_rule, got: $(head -c 300 "$WORK/body")"
    fails=$((fails+1))
fi
# AND: the path alone is not the rule.
code=$(get /cr-e2e/deny/x "$IP")
assert_eq 200 "$code" "deny rule: the path without the UA line passes (lines are ANDed)" || fails=$((fails+1))

# CAPTCHA: three lines (path, UA, host) -> the challenge page in CAPTCHA mode,
# its force reason the rule's.
code=$(get /cr-e2e/captcha/x "$IP" "$UA_BROWSER e2e-cr-captcha")
assert_eq 403 "$code" "CAPTCHA rule: path + UA + host -> challenged (403)" || fails=$((fails+1))
if grep -q '/\*__CHMODE__\*/"captcha_only"' "$WORK/body" && grep -q '/\*__CAPTCHA_FORCE__\*/"custom_rule"' "$WORK/body"; then
    log_pass "CAPTCHA rule: the page is in CAPTCHA mode, forced by custom_rule"
else
    log_fail "CAPTCHA rule: want captcha_only forced by custom_rule, got $(grep -oE '/\*__CHMODE__\*/"[a-z_]*"|/\*__CAPTCHA_FORCE__\*/"[a-z_]*"' "$WORK/body" | tr '\n' ' ')"
    fails=$((fails+1))
fi

# First match: two rules on the same path, PoW above deny -> PoW.
code=$(get /cr-e2e/order/x "$IP")
assert_eq 403 "$code" "order: the first rule (PoW) answers, not the deny below it" || fails=$((fails+1))
if grep -q '/\*__CHMODE__\*/"pow_only"' "$WORK/body"; then
    log_pass "order: the challenge is the first rule's PoW"
else
    log_fail "order: want a pow_only challenge from the first rule, got: $(head -c 300 "$WORK/body")"
    fails=$((fails+1))
fi

# Disabled: not rendered, so not answered.
code=$(get /cr-e2e/off/x "$IP")
assert_eq 200 "$code" "disabled rule: no answer of its own (200)" || fails=$((fails+1))

# Throttle: the rule changes no judgement (a known browser passes), counts the
# address while it matches, and over 2/min (burst 2) answers its own deny with
# the rate answer's status.
codes=""
for _ in 1 2 3 4 5 6; do
    codes="$codes $(get /cr-e2e/rate/x "$IP_RATE")"
done
codes=${codes# }
first=${codes%% *}
assert_eq 200 "$first" "throttle rule: the first request passes (the rule changes no judgement)" || fails=$((fails+1))
case " $codes " in
    *" 429 "*) log_pass "throttle rule: over the limit -> 429 ($codes)" ;;
    *) log_fail "throttle rule: never limited in 6 requests at 2/min ($codes)"; fails=$((fails+1)) ;;
esac
# The last answer is over the limit: the rule's deny, not a challenge page.
if grep -q '__CHMODE__' "$WORK/body"; then
    log_fail "throttle rule: over the limit the rule says deny, but a challenge page came back"
    fails=$((fails+1))
fi
# The ip line: another address on the same path is not this rule's.
other=""
for _ in 1 2 3 4 5 6; do other="$other $(get /cr-e2e/rate/x "$IP_RATE_OTHER")"; done
case " $other " in
    *" 429 "*) log_fail "throttle rule: an address the ip line does not list was limited ($other)"; fails=$((fails+1)) ;;
    *) log_pass "throttle rule: another address on the same path is not counted ($other)" ;;
esac

if ! switch_config "$WORK/orig.yml"; then
    log_fail "could not switch the stack back to its own config"
    exit 1
fi
code=$(get /cr-e2e/deny/x "$IP" "$UA_BROWSER e2e-cr-deny")
assert_eq 200 "$code" "rules gone again: the deny rule's request passes" || fails=$((fails+1))

[ "$fails" -eq 0 ]
