#!/bin/bash
# Gateway UI smoke against a running compose stack: complete the setup
# wizard, log in, paste a certificate into settings > Gateway, and check that
# :443 serves it within the autoreload interval.  Needs the admin daemon on
# ADMIN_URL (see admin-port-override.yml) and the gateway on GATEWAY.
#
#   ADMIN_URL=http://127.0.0.1:19477/unmask GATEWAY=127.0.0.1:443 e2e/docker/gateway-ui-smoke.sh
set -u
ADMIN_URL=${ADMIN_URL:-http://127.0.0.1:19477/unmask}
GATEWAY=${GATEWAY:-127.0.0.1:443}
SERVER_NAME=${SERVER_NAME:-localhost}
ADMIN_CONTAINER=${ADMIN_CONTAINER:-unmask-admin}
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
J=$W/jar
C="curl -sS -b $J -c $J"
fails=0
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; fails=$((fails+1)); }
# The CSRF token is the unmask_admin_csrf cookie (the forms carry it too).
csrf() { awk '$6=="unmask_admin_csrf"{v=$7} END{print v}' "$J"; }
h2() { $C "$ADMIN_URL/admin/setup/" | grep -oE '<h2[^>]*>[^<]*' | head -1 | sed 's/<[^>]*>//'; }

# 1. The wizard: token (minted by the entrypoint, printed to the logs), DB
#    (the skeleton config's sqlite), admin user, install.
TOK=$(docker exec "$ADMIN_CONTAINER" sh -c 'cat /var/lib/unmask/.setup-token 2>/dev/null || cat /etc/unmask/.setup-token')
[ -n "$TOK" ] && pass "setup token minted" || fail "no setup token in the admin container"
loc=$($C -o /dev/null -w '%{redirect_url}' --data-urlencode "token=$TOK" "$ADMIN_URL/admin/setup/token")
case "$loc" in *err=*) fail "token step: $loc" ;; *) pass "token step accepted" ;; esac
loc=$($C -o /dev/null -w '%{redirect_url}' --data-urlencode "driver=sqlite" --data-urlencode "sqlite_path=/var/lib/unmask/unmask.sqlite" "$ADMIN_URL/admin/setup/db")
case "$loc" in *err=*) fail "db step: $loc" ;; *) pass "db step accepted" ;; esac
PW='Gateway-Smoke-2026!'
loc=$($C -o /dev/null -w '%{redirect_url}' --data-urlencode "username=admin" --data-urlencode "password=$PW" --data-urlencode "password_confirm=$PW" "$ADMIN_URL/admin/setup/user")
case "$loc" in *err=*) fail "user step: $loc" ;; *) pass "user step accepted" ;; esac
step=$(h2)
loc=$($C -o /dev/null -w '%{http_code} %{redirect_url}' -X POST "$ADMIN_URL/admin/setup/install")
case "$loc" in *err=*) fail "install step: $loc (after user step the wizard showed: $step)" ;; *) pass "install step: $loc" ;; esac
# Setup ends in a re-exec of the daemon; wait for it to answer again.
for i in $(seq 1 30); do [ "$(curl -s -o /dev/null -w '%{http_code}' "$ADMIN_URL/healthz")" = 200 ] && break; sleep 1; done
loc=$($C -o /dev/null -w '%{redirect_url}' --data-urlencode "username=admin" --data-urlencode "password=$PW" "$ADMIN_URL/admin/login")
case "$loc" in */admin/setup/*) fail "login still redirects to the wizard ($loc) -- setup did not complete" ;; *) pass "login: $loc" ;; esac

# 2. The Gateway tab renders for a gateway install, and a pasted pair lands
#    on :443.  Self-signed, with a subject nothing else uses.
page=$($C "$ADMIN_URL/admin/settings/gateway/")
echo "$page" | grep -q 'name="cert_cert_pem"' && pass "gateway tab renders the paste form" || fail "gateway tab has no paste form"
openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 90 -keyout $W/k.pem -out $W/c.pem -subj "/CN=$SERVER_NAME/O=Pasted Via UI" 2>/dev/null
t=$(csrf)
loc=$($C -o /dev/null -w '%{redirect_url}' --data-urlencode "_csrf=$t" --data-urlencode "tls=here" --data-urlencode "hostnames_mode=custom" --data-urlencode "hostnames=$SERVER_NAME" --data-urlencode "cert_id=" --data-urlencode "cert_domains=" --data-urlencode "cert_mode=upload" --data-urlencode "cert_cert_path=" --data-urlencode "cert_key_path=" --data-urlencode "cert_cert_pem@$W/c.pem" --data-urlencode "cert_chain_pem=" --data-urlencode "cert_key_pem@$W/k.pem" "$ADMIN_URL/admin/settings/save?section=gateway")
case "$loc" in *saved=1*) pass "paste saved" ;; *) fail "paste save: $loc" ;; esac
mode=$(docker exec "$ADMIN_CONTAINER" stat -c '%a' /etc/unmask/gateway.key 2>/dev/null)
[ "$mode" = "600" ] && pass "stored key is 0600" || fail "stored key mode: '$mode'"
served() { echo | timeout 5 openssl s_client -connect "$GATEWAY" -servername "$SERVER_NAME" 2>/dev/null | openssl x509 -noout -subject 2>/dev/null; }
for i in $(seq 1 20); do served | grep -q 'Pasted Via UI' && break; sleep 2; done
served | grep -q 'Pasted Via UI' && pass "gateway serves the pasted certificate (after ${i}x2s)" || fail "gateway still serves: $(served)"
page=$($C "$ADMIN_URL/admin/settings/gateway/")
keyline=$(sed -n '2p' $W/k.pem)
echo "$page" | grep -qF "$keyline" && fail "the tab echoes the private key" || pass "the tab does not echo the key"
echo "$page" | grep -q 'Pasted Via UI' && pass "the tab shows the served certificate" || fail "the tab does not show the served certificate"

# 3. A pair that does not match is refused, and :443 keeps the good one.
openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:P-256 -days 90 -keyout $W/k2.pem -out $W/c2.pem -subj "/CN=$SERVER_NAME/O=Mismatch" 2>/dev/null
t=$(csrf)
loc=$($C -o /dev/null -w '%{redirect_url}' --data-urlencode "_csrf=$t" --data-urlencode "tls=here" --data-urlencode "hostnames_mode=custom" --data-urlencode "hostnames=$SERVER_NAME" --data-urlencode "cert_id=" --data-urlencode "cert_domains=" --data-urlencode "cert_mode=upload" --data-urlencode "cert_cert_path=" --data-urlencode "cert_key_path=" --data-urlencode "cert_cert_pem@$W/c2.pem" --data-urlencode "cert_chain_pem=" --data-urlencode "cert_key_pem@$W/k.pem" "$ADMIN_URL/admin/settings/save?section=gateway")
case "$loc" in *saved=1*) fail "a mismatched pair was accepted" ;; *) pass "a mismatched pair is refused" ;; esac
sleep 4
served | grep -q 'Pasted Via UI' && pass "gateway keeps the good certificate" || fail "gateway changed after a refused upload: $(served)"

echo "gateway-ui-smoke: $fails failure(s)"
exit $fails
