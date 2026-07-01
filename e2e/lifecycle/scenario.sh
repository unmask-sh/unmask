#!/bin/sh
# unmask package-lifecycle scenarios, run INSIDE a CentOS 6 container by
# e2e/lifecycle/run.sh.  Covers the install/upgrade/removal/fail-safe surfaces
# the fresh-install distro matrix masks (= the 2026-06-08 GA audit's core gap).
#
# CentOS 6 (SysVinit + nginx.org direct-edit + glibc 2.12) is the fullest case
# testable in plain docker: SysVinit scripts run without a pid-1 init, and it is
# the only matrix distro whose nginx.conf gets the direct load_module edit.
# (systemd service lifecycle / SELinux enforcing need a real VM -> distro-check.)
#
# Mounts (read-only):
#   /work       dist/ with the v1 rpms + multi-modules-glibc212/
#   /work-pkgs  initscripts.rpm (host-fetched; the minimal image lacks it)
#
# Emits "LC-PASS <name>" / "LC-FAIL <name>" per check + a final tally line
# "lifecycle: passed=N failed=M" and exits non-zero on any failure.
set -u
P=0; F=0
ok()  { P=$((P+1)); echo "  LC-PASS $1"; }
ng()  { F=$((F+1)); echo "  LC-FAIL $1${2:+ -- $2}"; }
lm()  { grep -q 'load_module.*ngx_http_unmask_module' /etc/nginx/nginx.conf 2>/dev/null && echo present || echo gone; }
ngxt(){ nginx -t >/dev/null 2>&1 && echo ok || echo fail; }
V1=0.1.0; V2=0.1.1

echo "### setup: initscripts + nginx 1.18.0 (nginx.org) ###"
rpm -Uvh --nodeps /work-pkgs/initscripts.rpm >/dev/null 2>&1
rm -f /etc/yum.repos.d/CentOS-*.repo
curl -fsS -o /tmp/nginx.rpm "http://nginx.org/packages/centos/6/x86_64/RPMS/nginx-1.18.0-2.el6.ngx.x86_64.rpm" \
  || { echo "FATAL: cannot fetch nginx"; exit 2; }
rpm -Uvh --nodeps /tmp/nginx.rpm >/dev/null 2>&1
command -v nginx >/dev/null 2>&1 || { echo "FATAL: nginx missing"; exit 2; }

echo "### scenario 1: fresh install (v$V1) ###"
rpm -Uvh --nodeps /work/unmask-$V1-1.x86_64.rpm /work/unmask-plugin-nginx-$V1-1.x86_64.rpm /work/unmask-web-nginx-$V1-1.x86_64.rpm >/tmp/i1.log 2>&1 \
  && ok "install v$V1 (rpm scriptlets exit 0)" || ng "install v$V1" "$(tail -1 /tmp/i1.log)"
[ "$(ngxt)" = ok ] && ok "nginx -t after install" || ng "nginx -t after install" "$(nginx -t 2>&1 | tail -1)"
[ -e /usr/lib64/nginx/modules/ngx_http_unmask_module.so ] && ok ".so placed" || ng ".so placed"
SO_MD5=$(md5sum /usr/lib64/nginx/modules/ngx_http_unmask_module.so 2>/dev/null | awk '{print $1}')
SRC_MD5=$(md5sum /work/multi-modules-glibc212/1.18.0/ngx_http_unmask_module.so 2>/dev/null | awk '{print $1}')
[ -n "$SO_MD5" ] && [ "$SO_MD5" = "$SRC_MD5" ] && ok ".so == glibc212/1.18.0 (correct ABI)" || ng ".so ABI match" "$SO_MD5 vs $SRC_MD5"
[ "$(lm)" = present ] && ok "load_module in nginx.conf (direct-edit path)" || ng "load_module present"
grep -qE '^map_hash_bucket_size' /var/lib/unmask/nginx/http.inc && ok "map_hash in http.inc (not nginx.conf)" || ng "map_hash in http.inc"
[ "$(grep -cE 'map_hash' /etc/nginx/nginx.conf 2>/dev/null)" = 0 ] && ok "nginx.conf has no map_hash" || ng "nginx.conf map_hash leak"
service unmask start >/dev/null 2>&1
code=000; for i in $(seq 1 15); do code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:9477/unmask/healthz 2>/dev/null||echo 000); [ "$code" = 200 ]&&break; sleep 0.4; done
[ "$code" = 200 ] && ok "SysVinit service serves healthz 200" || ng "healthz" "got $code"
chkconfig --list unmask 2>/dev/null | grep -q '3:on' && ok "chkconfig boot-enabled" || ng "chkconfig on"

echo "### scenario 2: upgrade v$V1 -> v$V2 (config/token preserved, no dup) ###"
# Compare the bootstrap secrets + DB driver, NOT a whole-file md5: the running
# daemon writes the community-bans token into config.yml asynchronously, which
# would race a checksum.  The B1 audit concern is secret regeneration / a driver
# reset to sqlite, so assert exactly those survive the upgrade.
SECRETS_BEFORE=$(grep -E 'bv_secret:|captcha_secret_base:|^[[:space:]]*driver:' /etc/unmask/config.yml 2>/dev/null | sort)
TOK_BEFORE=$(cat /etc/unmask/.setup-token 2>/dev/null || echo "")
rpm -Uvh --nodeps /work/unmask-$V2-1.x86_64.rpm /work/unmask-plugin-nginx-$V2-1.x86_64.rpm /work/unmask-web-nginx-$V2-1.x86_64.rpm >/tmp/i2.log 2>&1 \
  && ok "upgrade to v$V2 (rpm -U scriptlets exit 0)" || ng "upgrade to v$V2" "$(tail -1 /tmp/i2.log)"
SECRETS_AFTER=$(grep -E 'bv_secret:|captcha_secret_base:|^[[:space:]]*driver:' /etc/unmask/config.yml 2>/dev/null | sort)
[ "$SECRETS_AFTER" = "$SECRETS_BEFORE" ] && ok "secrets + DB driver preserved across upgrade" || ng "secrets/driver preserved"
TOK_AFTER=$(cat /etc/unmask/.setup-token 2>/dev/null || echo "")
[ "$TOK_AFTER" = "$TOK_BEFORE" ] && ok "setup-token not re-minted on upgrade (no admin re-lock)" || ng "setup-token stable" "before=$TOK_BEFORE after=$TOK_AFTER"
[ "$(grep -c 'load_module.*ngx_http_unmask_module' /etc/nginx/nginx.conf 2>/dev/null)" = 1 ] && ok "no duplicate load_module after upgrade" || ng "single load_module" "count=$(grep -c 'load_module.*ngx_http_unmask_module' /etc/nginx/nginx.conf 2>/dev/null)"
[ "$(ngxt)" = ok ] && ok "nginx -t after upgrade" || ng "nginx -t after upgrade" "$(nginx -t 2>&1 | tail -1)"
[ "$(/usr/sbin/unmask version 2>&1 | awk '{print $2}')" = "$V2" ] && ok "new binary active (v$V2)" || ng "binary version" "$(/usr/sbin/unmask version 2>&1)"

echo "### scenario 3: render-verify fail-safe ###"
echo 'bogus_host_directive_xyz on;' > /etc/nginx/conf.d/zz-host.conf
sh /usr/share/unmask/plugin/place-module.sh --verify >/tmp/v1.log 2>&1
[ "$(lm)" = present ] && ok "host config error does NOT disable unmask" || ng "host-error false-disable"
rm -f /etc/nginx/conf.d/zz-host.conf
echo 'unmask_bogus_xyz on;' >> /var/lib/unmask/nginx/http.inc
sh /usr/share/unmask/plugin/place-module.sh --verify >/tmp/v2.log 2>&1
[ "$(lm)" = gone ] && ok "unmask-broken render auto-disables wiring" || ng "failsafe disable"
[ "$(ngxt)" = ok ] && ok "nginx -t passes after fail-safe disable (nginx survives)" || ng "nginx survives failsafe"

echo "### scenario 4: removal (rpm -e) leaves nginx clean ###"
# reinstall first (scenario 3 disabled the wiring)
rpm -e --nodeps unmask-plugin-nginx unmask-web-nginx unmask >/dev/null 2>&1
rpm -Uvh --nodeps /work/unmask-$V2-1.x86_64.rpm /work/unmask-plugin-nginx-$V2-1.x86_64.rpm /work/unmask-web-nginx-$V2-1.x86_64.rpm >/dev/null 2>&1
[ "$(lm)" = present ] && ok "reinstall restores load_module" || ng "reinstall"
rpm -e --nodeps unmask-plugin-nginx unmask-web-nginx unmask >/tmp/rm.log 2>&1 \
  && ok "rpm -e all 3 (scriptlets exit 0)" || ng "rpm -e" "$(tail -1 /tmp/rm.log)"
[ "$(lm)" = gone ] && ok "no dangling load_module after removal" || ng "dangling load_module"
[ ! -e /usr/lib64/nginx/modules/ngx_http_unmask_module.so ] && ok ".so removed" || ng ".so removed"
[ ! -e /etc/nginx/conf.d/00-unmask.conf ] && ok "http.inc symlink removed" || ng "symlink removed"
[ "$(ngxt)" = ok ] && ok "nginx -t passes after full removal (back to stock)" || ng "nginx -t after removal" "$(nginx -t 2>&1 | tail -1)"

echo ""
echo "lifecycle: passed=$P failed=$F"
[ "$F" = 0 ]
