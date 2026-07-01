#!/bin/sh
# unmask auth helper for Apache mod_authnz_external (= for environments without mod_lua).
#
# Flow:
#   Apache forks this script on every user request, exporting environment
#   variables (= USER, HTTP_HOST etc.).  The script curls unmask /api/check
#   and returns exit 0 (= pass) / 1 (= challenge or block).
#
# Apache config (= excerpt):
#   AddExternalAuth         unmask /usr/share/unmask/snippets/apache-unmask-auth.sh
#   SetExternalAuthMethod   unmask environment
#   <Location />
#     AuthType               Basic
#     AuthName               "unmask"
#     AuthBasicProvider      external
#     AuthExternal           unmask
#     Require                valid-user
#   </Location>
#
# Limitations:
#   - mod_authnz_external is not in RHEL stock (= must install from EPEL)
#   - one fork per request → throughput drops (mod_lua is ~10x faster)
#   - cannot auto-redirect to the challenge HTML (= can only return 401)
#
# Recommended: use apache-unmask.lua + mod_lua in most cases.

set -eu

UNMASK_API="${UNMASK_API:-http://127.0.0.1:9477/unmask/api/check}"

URI="${REDIRECT_URL:-${REQUEST_URI:-/}}"
IP="${REMOTE_ADDR:-}"
UA="${HTTP_USER_AGENT:-}"
HOST="${HTTP_HOST:-}"
COOKIE="${HTTP_COOKIE:-}"
# Client JA4 (forward-auth mode). Apache exports request headers as HTTP_*
# env vars, so X-Client-JA4 -> HTTP_X_CLIENT_JA4. Carries a value only when a
# JA4-aware front layer (LB / CDN) set it. The daemon honors it ONLY when the
# real connecting peer (CONN_PEER below) is a trusted LB, so a client reaching
# Apache directly cannot spoof a JA4. CONN_PEER comes from the RewriteRule in
# apache-forward-auth.conf ([E=UNMASK_CONN_PEER:%{CONN_REMOTE_ADDR}]), exported
# to this script as UNMASK_CONN_PEER.
JA4="${HTTP_X_CLIENT_JA4:-}"
CONN_PEER="${UNMASK_CONN_PEER:-}"

# Pass /unmask/* / /_unmask/* to prevent self-loops.
case "$URI" in
    /unmask/*|/_unmask/*) exit 0 ;;
esac

RESP=$(curl -sS -o /dev/null -w "%{http_code}|%header{x-unmask-action}|%header{x-unmask-reason}\n" \
    -H "X-Original-URI: $URI" \
    -H "X-Original-IP: $IP" \
    -H "X-Original-UA: $UA" \
    -H "X-Original-Host: $HOST" \
    -H "X-Client-JA4: $JA4" \
    -H "X-Unmask-Conn-Peer: $CONN_PEER" \
    -H "Cookie: $COOKIE" \
    --max-time 2 \
    "$UNMASK_API" 2>/dev/null) || RESP="000||"

STATUS=$(echo "$RESP" | cut -d'|' -f1)
ACTION=$(echo "$RESP" | cut -d'|' -f2)

# pass: 200 OR action=pass
if [ "$STATUS" = "200" ] || [ "$ACTION" = "pass" ]; then
    exit 0
fi

# 401/403 / challenge / block → all deny.
# Apache's mod_authnz_external can only return results as an exit code, so
# we can't distinguish challenge from block.  We exit with 401 and let
# Apache redirect to /unmask/challenge/ via ErrorDocument 401.
exit 1
