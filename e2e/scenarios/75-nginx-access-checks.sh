#!/bin/bash
# 75: nginx's own access checks on a protected location -- satisfy any with
# allow / deny / auth_basic, and auth_request -- neither carry a client past
# the gate nor are skipped for one the gate lets through.
#
# The plugin's ACCESS handler runs before the location's allow/deny,
# auth_basic and auth_request (nginx runs a phase's handlers in the reverse
# of their registration, and a dynamic module registers after the built-in
# ones).  It sends a client the gate stops to the challenge by an internal
# redirect and returns NGX_DONE, which nginx's access phase passes on without
# consulting `satisfy`.  Had it returned 403 instead, `satisfy any` would
# have let a matching allow or a good password through around it -- the
# question an outside review of the module asked, and that only a real nginx
# answers.  Once the gate lets a client through, the handler declines and the
# location's own checks decide, as written.
#
# Locations (e2e/docker/nginx/nginx.conf): /ac-any/ (satisfy any, allow
# 198.51.100.75, deny all, auth_basic), /ac-basic/ (auth_basic), /ac-deny/
# (deny all), /ac-authreq/ (auth_request answering yes to X-E2E-Auth: yes).
# Password: e2e / e2e-pass.  The gate stops curl (a challenge target) and lets
# an ordinary browser UA through, as in scenarios 01 and 03.

set -u
DIR="$(cd "$(dirname "$0")/.." && pwd)"
. "$DIR/lib/env.sh"
. "$DIR/lib/assert.sh"

# One address per group of requests: the rate limit counts per address
# (30 a minute + a burst of 10 in this stack), and a group that ran into it
# would read a rate answer as an access check's.
ALLOWED=198.51.100.75     # the allow line of /ac-any/
STOPPED=198.51.100.76     # no allow line: the gate-stopped requests
ANY=198.51.100.77         # no allow line: /ac-any/ for a passed client
BASIC=198.51.100.78       # /ac-basic/ and /ac-deny/
AUTHREQ=198.51.100.79     # /ac-authreq/
GOOD=(-u e2e:e2e-pass)
body=$(mktemp)
trap 'rm -f "$body"' EXIT

# get <ip> <ua> <path> [curl args...] -> the status; the body lands in $body.
get() {
    local ip="$1" ua="$2" path="$3"; shift 3
    curl -sk -o "$body" -w '%{http_code}' -A "$ua" -H "X-Forwarded-For: $ip" \
        "$@" "${BASE_URL}${path}"
}
is_challenge() { grep -qE 'window\.UNMASK|/unmask/(api|static|challenge)/' "$body"; }
is_echo()      { grep -q '^\[unmask e2e\]' "$body"; }

# challenged <msg> <ip> <path> [curl args...]: the gate's challenge, not the
# location's answer -- above all not the echo a passed check would give.
challenged() {
    local msg="$1" ip="$2" path="$3"; shift 3
    local code
    code=$(get "$ip" "$UA_CURL" "$path" "$@")
    if [ "$code" = 403 ] && is_challenge; then
        log_pass "$msg -> the challenge"
    else
        log_fail "$msg -> $code, not the challenge: $(head -c 160 "$body" | tr '\n' ' ')"
    fi
}

# answered <want> <msg> <ip> <path> [curl args...]: what the location's own
# checks give a client the gate let through.
answered() {
    local want="$1" msg="$2" ip="$3" path="$4"; shift 4
    local code
    code=$(get "$ip" "$UA_BROWSER" "$path" "$@")
    if [ "$code" != "$want" ]; then
        log_fail "$msg -> $code, want $want: $(head -c 160 "$body" | tr '\n' ' ')"
    elif is_challenge; then
        log_fail "$msg -> $code, but the body is the challenge page"
    elif [ "$want" = 200 ] && ! is_echo; then
        log_fail "$msg -> 200 without the location's content: $(head -c 160 "$body" | tr '\n' ' ')"
    else
        log_pass "$msg -> $code"
    fi
}

# --- the gate stops the client: no access check carries it past ----------
challenged "satisfy any, the allow matches"            "$ALLOWED" /ac-any/x
challenged "satisfy any, the allow matches + password" "$ALLOWED" /ac-any/x "${GOOD[@]}"
challenged "satisfy any, a good password"              "$STOPPED" /ac-any/x "${GOOD[@]}"
challenged "auth_basic, a good password"               "$STOPPED" /ac-basic/x "${GOOD[@]}"
challenged "auth_request, the backend says yes"        "$STOPPED" /ac-authreq/x -H 'X-E2E-Auth: yes'
code=$(get "$STOPPED" "$UA_CURL" /ac-deny/x)
assert_eq 403 "$code" "deny all, gate-stopped -> 403 (the challenge or the deny, never the content)"

# --- the gate lets the client through: the checks decide as written -------
answered 200 "satisfy any, the allow matches"       "$ALLOWED" /ac-any/x
answered 401 "satisfy any, no allow, no password"   "$ANY"     /ac-any/x
answered 401 "satisfy any, no allow, bad password"  "$ANY"     /ac-any/x -u e2e:wrong
answered 200 "satisfy any, no allow, good password" "$ANY"     /ac-any/x "${GOOD[@]}"
answered 401 "auth_basic, no password"              "$BASIC"   /ac-basic/x
answered 200 "auth_basic, good password"            "$BASIC"   /ac-basic/x "${GOOD[@]}"
answered 403 "deny all"                             "$BASIC"   /ac-deny/x
answered 403 "auth_request, the backend says no"    "$AUTHREQ" /ac-authreq/x
answered 200 "auth_request, the backend says yes"   "$AUTHREQ" /ac-authreq/x -H 'X-E2E-Auth: yes'

[ "${_E2E_FAILS:-0}" -eq 0 ]
