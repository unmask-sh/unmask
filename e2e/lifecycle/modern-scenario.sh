#!/bin/sh
# unmask package-lifecycle scenarios on a current distribution, run INSIDE a
# container by e2e/lifecycle/modern.sh: Ubuntu (deb), AlmaLinux (rpm) or
# Alpine (apk), each with the nginx it ships.
#
# scenario.sh next to this file covers CentOS 6, the one distribution whose
# nginx.conf gets the load_module line edited in.  These three take the other
# road: the package manager resolves and removes the packages (no --nodeps),
# and the loader is a file dropped into the directory nginx.conf includes --
# a different directory on each of them, which is where an uninstall used to
# leave it behind.
#
# Mounts (read-only):
#   /work   dist/: the three packages at v$V1 and v$V2, and multi-modules/
#
# Emits "LC-PASS <name>" / "LC-FAIL <name>" per check, a final tally line
# "lifecycle: passed=N failed=M", and exits non-zero on any failure.
set -u
P=0; F=0
ok()  { P=$((P+1)); echo "  LC-PASS $1"; }
ng()  { F=$((F+1)); echo "  LC-FAIL $1${2:+ -- $2}"; }
V1=0.1.0; V2=0.1.1
PORT=8088
UA_BOT='curl/8.0'

# ---- the package family ---------------------------------------------------
if command -v dnf >/dev/null 2>&1; then
    FAM=rpm
    pkg_setup()   { dnf -q -y install nginx >/tmp/setup.log 2>&1; }
    pkg_files()   { echo "/work/unmask-$1-1.x86_64.rpm /work/unmask-plugin-nginx-$1-1.x86_64.rpm /work/unmask-web-nginx-$1-1.x86_64.rpm"; }
    pkg_install() { dnf -q -y install $(pkg_files "$1"); }
    # Not -q: dnf then drops what the scriptlets print, and what a removal
    # tells the operator is part of what is checked.
    pkg_remove()  { dnf -y remove unmask-plugin-nginx unmask-web-nginx unmask; }
elif command -v apt-get >/dev/null 2>&1; then
    FAM=deb
    export DEBIAN_FRONTEND=noninteractive
    # Retries: a mirror that drops a connection is retried by apt itself.
    pkg_setup()   { apt-get -o Acquire::Retries=5 -qq update >/tmp/setup.log 2>&1 && apt-get -o Acquire::Retries=5 -qq install -y nginx curl ca-certificates >>/tmp/setup.log 2>&1; }
    pkg_files()   { echo "/work/unmask_$1-1_amd64.deb /work/unmask-plugin-nginx_$1-1_amd64.deb /work/unmask-web-nginx_$1-1_amd64.deb"; }
    pkg_install() { apt-get -qq install -y $(pkg_files "$1"); }
    pkg_remove()  { apt-get -qq remove -y unmask-plugin-nginx unmask-web-nginx unmask; }
elif command -v apk >/dev/null 2>&1; then
    FAM=apk
    pkg_setup()   { apk add --no-cache nginx curl >/tmp/setup.log 2>&1; }
    pkg_files()   { echo "/work/unmask_$1-r1_x86_64.apk /work/unmask-plugin-nginx_$1-r1_x86_64.apk /work/unmask-web-nginx_$1-r1_x86_64.apk"; }
    pkg_install() { apk add --allow-untrusted $(pkg_files "$1"); }
    pkg_remove()  { apk del unmask-plugin-nginx unmask-web-nginx unmask; }
else
    echo "FATAL: no known package manager"; exit 2
fi

# ---- helpers --------------------------------------------------------------
ngxt() { nginx -t >/dev/null 2>&1 && echo ok || echo fail; }
# Every file nginx could read a load_module line from: nginx.conf and the
# directories distributions include at main scope.
loader_files() {
    grep -rlE '^[[:space:]]*load_module[^#]*ngx_http_unmask_module' \
        /etc/nginx/nginx.conf /etc/nginx/modules /etc/nginx/modules-enabled \
        /etc/nginx/modules-available /etc/nginx/modules.d /usr/share/nginx/modules 2>/dev/null
}
loader_count() { loader_files | wc -l | tr -d ' '; }
SERVE_PID=""
daemon_start() {
    chown -R unmask /var/lib/unmask 2>/dev/null
    su unmask -s /bin/sh -c '/usr/sbin/unmask serve -config /etc/unmask/config.yml' >>/var/log/unmask-serve.log 2>&1 &
    SERVE_PID=$!
    code=000
    for _ in $(seq 1 40); do
        code=$(curl -s -o /dev/null -w '%{http_code}' -m 2 http://127.0.0.1:9477/unmask/healthz 2>/dev/null || echo 000)
        [ "$code" = 200 ] && break
        sleep 0.5
    done
    echo "$code"
}
daemon_stop() {
    pkill -x unmask 2>/dev/null
    for _ in $(seq 1 20); do pgrep -x unmask >/dev/null 2>&1 || break; sleep 0.25; done
}
nginx_restart() {
    nginx -s stop >/dev/null 2>&1
    for _ in $(seq 1 20); do pgrep -x nginx >/dev/null 2>&1 || break; sleep 0.25; done
    mkdir -p /run/nginx /var/lib/nginx/tmp /var/log/nginx 2>/dev/null
    nginx >/tmp/nginx-start.log 2>&1
}

echo "### setup: the distribution's nginx ($FAM) ###"
pkg_setup
# When the archive's name did not resolve, once more through public
# resolvers: on 2026-11-11 GitHub's runners stopped resolving *.ubuntu.com
# inside containers for hours (AlmaLinux's and Alpine's mirrors resolved),
# and the job failed before it reached a single unmask package.  Where names
# resolve this never runs; where it runs, the resolvers stay for the rest of
# the scenario, whose installs may need the archive too.
if ! command -v nginx >/dev/null 2>&1 && grep -qiE 'resolv|lookup' /tmp/setup.log 2>/dev/null; then
    echo "    the archive's name did not resolve; trying public resolvers (1.1.1.1, 9.9.9.9)"
    printf 'nameserver 1.1.1.1\nnameserver 9.9.9.9\n' > /etc/resolv.conf
    pkg_setup
fi
# The package manager's own words when the distribution's nginx did not come:
# hidden, as they were, a failing mirror and a failing package looked alike.
command -v nginx >/dev/null 2>&1 || { echo "FATAL: nginx missing; the package manager said:"; tail -n 25 /tmp/setup.log 2>/dev/null; exit 2; }
NGINX_VER=$(nginx -v 2>&1 | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
MODULES_PATH=$(nginx -V 2>&1 | tr ' ' '\n' | sed -n 's|^--modules-path=||p' | head -1)
echo "    nginx $NGINX_VER, modules in $MODULES_PATH"
[ -f "/work/multi-modules/$NGINX_VER/ngx_http_unmask_module.so" ] \
    || { echo "FATAL: dist/ has no module for nginx $NGINX_VER (e2e/lifecycle/build.sh builds 1.20.1, 1.24.0 and 1.28.3)"; exit 2; }
[ "$(ngxt)" = ok ] || { echo "FATAL: the stock nginx configuration does not pass nginx -t"; exit 2; }
# Where a server{} block of the operator's goes on this distribution.
if [ -d /etc/nginx/http.d ]; then SITES=/etc/nginx/http.d; else SITES=/etc/nginx/conf.d; fi

echo "### scenario 1: fresh install (v$V1) ###"
pkg_install "$V1" >/tmp/i1.log 2>&1 \
    && ok "install v$V1 (package manager exit 0)" || ng "install v$V1" "$(tail -3 /tmp/i1.log | tr '\n' ' ')"
[ "$(ngxt)" = ok ] && ok "nginx -t after install" || ng "nginx -t after install" "$(nginx -t 2>&1 | tail -1)"
SO="$MODULES_PATH/ngx_http_unmask_module.so"
[ -e "$SO" ] && ok ".so placed in $MODULES_PATH" || ng ".so placed"
# (sha256sum: a minimal image has no cmp.)
sum_of() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }
if [ -e "$SO" ] && [ "$(sum_of "$SO")" = "$(sum_of "/work/multi-modules/$NGINX_VER/ngx_http_unmask_module.so")" ]; then
    ok ".so is the one built for nginx $NGINX_VER"
else
    ng ".so is the one built for nginx $NGINX_VER"
fi
[ "$(loader_count)" = 1 ] && ok "one load_module for the module ($(loader_files | tr '\n' ' '))" \
    || ng "one load_module for the module" "found in: $(loader_files | tr '\n' ' ')"
LOADER=$(loader_files | head -1)
grep -qE 'unmask_bv_secret' /var/lib/unmask/nginx/http.inc 2>/dev/null && ok "http.inc rendered with the module wired" || ng "http.inc rendered with the module wired"
code=$(daemon_start)
[ "$code" = 200 ] && ok "daemon serves healthz 200" || ng "healthz" "got $code; $(tail -2 /var/log/unmask-serve.log 2>/dev/null | tr '\n' ' ')"

# The operator's part of the quick start: a server{} that includes
# server.inc, a location that includes protect.inc.
mkdir -p /srv/lifecycle && echo '[origin]' > /srv/lifecycle/index.html
cat > "$SITES/zz-lifecycle.conf" <<EOF
server {
    listen 127.0.0.1:$PORT;
    server_name lifecycle.test;
    root /srv/lifecycle;
    include /var/lib/unmask/nginx/server.inc;
    location / {
        include /var/lib/unmask/nginx/protect.inc;
        try_files \$uri /index.html;
    }
}
EOF
[ "$(ngxt)" = ok ] && ok "nginx -t with a protected server block" || ng "nginx -t with a protected server block" "$(nginx -t 2>&1 | tail -2 | tr '\n' ' ')"
nginx_restart
http=$(curl -s -o /tmp/resp.html -w '%{http_code}' -m 5 -A "$UA_BOT" "http://127.0.0.1:$PORT/" 2>/dev/null || echo 000)
[ "$http" = 403 ] && grep -qi 'unmask' /tmp/resp.html \
    && ok "a client without a pass gets the challenge (403)" || ng "challenge served" "http=$http; $(tail -2 /tmp/nginx-start.log 2>/dev/null | tr '\n' ' ')"

echo "### scenario 2: upgrade v$V1 -> v$V2 ###"
SECRETS_BEFORE=$(grep -E 'bv_secret:|captcha_secret_base:|^[[:space:]]*driver:' /etc/unmask/config.yml 2>/dev/null | sort)
TOK_BEFORE=$(cat /var/lib/unmask/.setup-token 2>/dev/null || echo "")
pkg_install "$V2" >/tmp/i2.log 2>&1 \
    && ok "upgrade to v$V2 (package manager exit 0)" || ng "upgrade to v$V2" "$(tail -3 /tmp/i2.log | tr '\n' ' ')"
SECRETS_AFTER=$(grep -E 'bv_secret:|captcha_secret_base:|^[[:space:]]*driver:' /etc/unmask/config.yml 2>/dev/null | sort)
[ -n "$SECRETS_BEFORE" ] && [ "$SECRETS_AFTER" = "$SECRETS_BEFORE" ] && ok "secrets and DB driver kept across the upgrade" || ng "secrets and DB driver kept"
TOK_AFTER=$(cat /var/lib/unmask/.setup-token 2>/dev/null || echo "")
# With a token to compare: two empty reads are equal too.
[ -n "$TOK_BEFORE" ] && [ "$TOK_AFTER" = "$TOK_BEFORE" ] && ok "setup token not re-minted by the upgrade" || ng "setup token stable" "before=$TOK_BEFORE after=$TOK_AFTER"
[ "$(loader_count)" = 1 ] && ok "still one load_module after the upgrade" || ng "one load_module after the upgrade" "found in: $(loader_files | tr '\n' ' ')"
[ "$(ngxt)" = ok ] && ok "nginx -t after the upgrade" || ng "nginx -t after the upgrade" "$(nginx -t 2>&1 | tail -1)"
[ "$(/usr/sbin/unmask version 2>/dev/null | awk '{print $2}')" = "$V2" ] && ok "the new binary is in place (v$V2)" || ng "binary version" "$(/usr/sbin/unmask version 2>/dev/null | head -1)"
daemon_stop
code=$(daemon_start)
[ "$code" = 200 ] && ok "the upgraded daemon serves healthz 200" || ng "healthz after the upgrade" "got $code"
nginx_restart
http=$(curl -s -o /dev/null -w '%{http_code}' -m 5 -A "$UA_BOT" "http://127.0.0.1:$PORT/" 2>/dev/null || echo 000)
[ "$http" = 403 ] && ok "the challenge is still served after the upgrade" || ng "challenge after the upgrade" "http=$http"

echo "### scenario 3: the fail-safe strips a module nginx cannot load a configuration with ###"
echo 'bogus_host_directive_xyz on;' > "$SITES/zz-host-error.conf"
sh /usr/share/unmask/plugin/place-module.sh --verify >/tmp/v1.log 2>&1
[ "$(loader_count)" = 1 ] && ok "an error of the host's own does not disable unmask" || ng "host error must not disable unmask"
rm -f "$SITES/zz-host-error.conf"
echo 'unmask_bogus_xyz on;' >> /var/lib/unmask/nginx/http.inc
sh /usr/share/unmask/plugin/place-module.sh --verify >/tmp/v2.log 2>&1
[ "$(loader_count)" = 0 ] && ok "a broken render of unmask's strips the loader, wherever it was placed" \
    || ng "fail-safe strips the loader" "still in: $(loader_files | tr '\n' ' ')"
[ "$(ngxt)" = ok ] && ok "nginx -t passes after the fail-safe (nginx survives)" || ng "nginx survives the fail-safe" "$(nginx -t 2>&1 | tail -1)"
# The fail-safe rendered the configuration again without the module, which
# also dropped the broken line.  place-module.sh is what a systemd host runs
# before every nginx start: with the render whole, it wires the module back.
sh /usr/share/unmask/plugin/place-module.sh >/tmp/v3.log 2>&1
[ "$(loader_count)" = 1 ] && ok "the module is wired back once the render is whole" \
    || { ng "module wired back" "found in: $(loader_files | tr '\n' ' ')"; grep -E 'nginx -t|fail-safe|emerg|!!' /tmp/v3.log | head -8; }
[ ! -e /var/lib/unmask/nginx/.native-failsafe ] && ok "the fail-safe marker is cleared" || ng "fail-safe marker cleared"
[ "$(ngxt)" = ok ] && ok "nginx -t with the module back" || ng "nginx -t with the module back" "$(nginx -t 2>&1 | tail -1)"

echo "### scenario 4: removal leaves nginx able to start ###"
daemon_stop
nginx -s stop >/dev/null 2>&1
LOADER=$(loader_files | head -1)
pkg_remove >/tmp/rm.log 2>&1 \
    && ok "remove all three (package manager exit 0)" || ng "remove" "$(tail -3 /tmp/rm.log | tr '\n' ' ')"
[ ! -e "$SO" ] && ok ".so removed" || ng ".so removed"
[ "$(loader_count)" = 0 ] && ok "no load_module left behind (it was in $LOADER)" \
    || ng "no load_module left behind" "still in: $(loader_files | tr '\n' ' ')"
left=$(ls /etc/nginx/conf.d/*unmask* /etc/nginx/http.d/*unmask* 2>/dev/null | tr '\n' ' ')
[ -z "$left" ] && ok "the http-level includes are gone" || ng "http-level includes gone" "$left"
# What is left is the operator's own server block, which still includes the
# rendered files: the removal has to say so, by file, since nginx will not
# start with them.
grep -q "zz-lifecycle.conf" /tmp/rm.log && ok "the removal names the server block that still includes unmask's files" \
    || ng "the removal names the leftover include" "$(grep -ci 'include' /tmp/rm.log) line(s) mention an include"
rm -f "$SITES/zz-lifecycle.conf"
[ "$(ngxt)" = ok ] && ok "nginx -t passes once that block is gone (back to stock)" || ng "nginx -t after removal" "$(nginx -t 2>&1 | tail -2 | tr '\n' ' ')"

echo ""
echo "lifecycle: passed=$P failed=$F"
[ "$F" = 0 ]
