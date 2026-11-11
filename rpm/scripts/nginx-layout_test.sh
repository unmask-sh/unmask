#!/bin/sh
# Test for the nginx-layout block: which nginx is a distribution's (its
# /etc/nginx is wired by the packages) and which is built from source (its
# files are left alone; the operator includes two directories of unmask's).
#
# The block is carried, byte for byte, by every package script that has to
# know -- a script runs alone, and the package that shipped another may be
# gone by then.  This test fails when two copies differ, and runs the
# functions of the block with stand-ins for the two things it asks nginx
# (`nginx -V`, and the configuration as nginx reads it).  No nginx, no root.
#
# POSIX sh, so that it also runs where /bin/sh is dash or busybox:
#   sh rpm/scripts/nginx-layout_test.sh
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
fails=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails+1)); }
check() { # <desc> <expected> <actual>
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected=\"$2\" got=\"$3\")"; fi
}
T=$(mktemp -d)
trap 'rm -rf "$T"' EXIT

block() { sed -n '/^# >>> nginx-layout >>>$/,/^# <<< nginx-layout <<<$/p' "$1"; }

# ---- 1. one block, the same in every script that carries it ----
CARRIERS="place-module.sh preremove-plugin-nginx.sh postinstall-web-nginx.sh postremove-web-nginx.sh postinstall.sh"
ref=$DIR/place-module.sh
block "$ref" > "$T/ref"
[ -n "$(block "$ref")" ] && pass "the block is there in place-module.sh" || fail "the block is there in place-module.sh"
for f in $CARRIERS; do
    [ "$f" = place-module.sh ] && continue
    if [ -z "$(block "$DIR/$f")" ]; then
        fail "the block is there in $f"
    elif [ "$(block "$DIR/$f")" = "$(block "$ref")" ]; then
        pass "the block is the same in $f"
    else
        fail "the block is the same in $f (diff: $(block "$DIR/$f" | diff - "$T/ref" 2>/dev/null | head -3 | tr '\n' ' '))"
    fi
done
# A script that names unmask's own directories has the block to name them with.
for f in "$DIR"/*.sh; do
    case "$f" in *_test.sh) continue ;; esac
    if grep -q 'OWN_\(MAIN\|HTTP\|SO\|NGINX\)_DIR' "$f" && [ -z "$(block "$f")" ]; then
        fail "$(basename "$f") names unmask's own nginx directories without carrying the block"
    fi
done

# ---- 2. the functions ----
block "$ref" > "$T/layout.sh"
nginx() { :; }
# shellcheck source=/dev/null
. "$T/layout.sh"

v() { _NL_V=$1; }
_nl_nginx_v() { printf '%s\n' "$_NL_V"; }

# nginx_conf_path: as the nginx was built.
v 'nginx version: nginx/1.26.3
built with OpenSSL 3.0.13 30 Jan 2024
configure arguments: --prefix=/etc/nginx --sbin-path=/usr/sbin/nginx --modules-path=/usr/lib64/nginx/modules --conf-path=/etc/nginx/nginx.conf --with-compat'
check "nginx.org's package: its --conf-path" /etc/nginx/nginx.conf "$(nginx_conf_path)"
nginx_is_packaged && r=packaged || r=selfbuilt
check "nginx.org's package is a packaged nginx" packaged "$r"

v "nginx version: nginx/1.22.1
configure arguments: --with-cc-opt='-g -O2 -ffile-prefix-map=/build/nginx-AoTv4W/nginx-1.22.1=. -fstack-protector-strong' --with-ld-opt='-Wl,-z,relro -Wl,-z,now -fPIC' --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --modules-path=/usr/lib/nginx/modules --with-compat"
check "Debian's package (quoted options with spaces ahead of it)" /etc/nginx/nginx.conf "$(nginx_conf_path)"

v 'nginx version: nginx/1.26.3
built with OpenSSL 1.1.1w  11 Sep 2023
configure arguments: --user=www --group=www --prefix=/www/server/nginx --with-openssl=/www/server/nginx/src/openssl --with-http_ssl_module --with-ld-opt=-Wl,-E --with-compat'
check "a hosting panel's build: conf/nginx.conf under its prefix" /www/server/nginx/conf/nginx.conf "$(nginx_conf_path)"
nginx_is_packaged && r=packaged || r=selfbuilt
check "a hosting panel's build is a self-built nginx" selfbuilt "$r"

v 'nginx version: nginx/1.28.3
configure arguments: --with-compat --with-http_ssl_module'
check "built with no prefix at all: nginx's own default" /usr/local/nginx/conf/nginx.conf "$(nginx_conf_path)"

v 'nginx version: nginx/1.28.3
configure arguments: --prefix=/opt/nginx --conf-path=etc/nginx.conf --with-compat'
check "a relative --conf-path is under the prefix" /opt/nginx/etc/nginx.conf "$(nginx_conf_path)"

v 'nginx version: nginx/1.28.3
configure arguments: --prefix=/opt/nginx --conf-path=/etc/nginx/nginx.conf --with-compat'
nginx_is_packaged && r=packaged || r=selfbuilt
check "built from source onto the distributions' path: wired like a packaged one" packaged "$r"

v ''
check "an nginx that answers nothing: the distributions' path" /etc/nginx/nginx.conf "$(nginx_conf_path)"
v 'sh: nginx: Permission denied'
check "an nginx that cannot be asked: the distributions' path" /etc/nginx/nginx.conf "$(nginx_conf_path)"

# No nginx on PATH at all.
(
    unset -f nginx
    PATH=$T/nowhere
    check "no nginx installed: the distributions' path" /etc/nginx/nginx.conf "$(nginx_conf_path)"
    exit "$fails"
); fails=$?

# own_includes_missing: from the configuration as nginx reads it.
v 'configure arguments: --prefix=/www/server/nginx --with-compat'
dump() { _NL_D=$1; }
_nl_nginx_dump() { printf '%s' "$_NL_D"; }
miss() { own_includes_missing | tr '\n' ' ' | sed 's/ $//'; }

dump '# configuration file /www/server/nginx/conf/nginx.conf:
user  www www;
events { }
http {
    include mime.types;
    include /www/server/panel/vhost/nginx/*.conf;
}'
check "neither line is there" "main http" "$(miss)"

dump '# configuration file /www/server/nginx/conf/nginx.conf:
include /usr/share/unmask/nginx/modules-enabled/*.conf;
user  www www;
events { }
http {
    include /www/server/panel/vhost/nginx/*.conf;
}'
check "the module line is there, the http one is not" "http" "$(miss)"

dump '# configuration file /www/server/nginx/conf/nginx.conf:
include /usr/share/unmask/nginx/modules-enabled/*.conf;
http {
    include /www/server/panel/vhost/nginx/*.conf;
}
# configuration file /www/server/panel/vhost/nginx/0.unmask.conf:
include /usr/share/unmask/nginx/conf.d/*.conf;'
check "both are there, the http one in a file of the vhost directory" "" "$(miss)"

dump '    include   "/usr/share/unmask/nginx/modules-enabled/*.conf" ;
http {
	include '"'"'/usr/share/unmask/nginx/conf.d/*.conf'"'"';
}'
check "quoted and spaced otherwise, they are still there" "" "$(miss)"

dump '# include /usr/share/unmask/nginx/modules-enabled/*.conf;
http {
    #include /usr/share/unmask/nginx/conf.d/*.conf;
    include /usr/share/unmask/nginx/conf.d/other.conf;
}'
check "commented out, or another file of the directory: not there" "main http" "$(miss)"

# The configuration does not load (nginx -T prints nothing): the main file.
mkdir -p "$T/p/conf"
printf 'include /usr/share/unmask/nginx/modules-enabled/*.conf;\nhttp {\n}\n' > "$T/p/conf/nginx.conf"
v "configure arguments: --prefix=$T/p --with-compat"
dump ''
check "a configuration that does not load is read from its main file" "http" "$(miss)"

# own_includes_say: the lines, and the file they go into.
v 'configure arguments: --prefix=/www/server/nginx --with-compat'
dump 'http { }'
out=$(own_includes_say unmask-plugin-nginx)
has() { printf '%s\n' "$out" | grep -qF -- "$1" && echo yes || echo no; }
check "says whose nginx it is" yes "$(has 'unmask-plugin-nginx: this nginx was not installed from a package')"
check "names the file" yes "$(has 'Add to /www/server/nginx/conf/nginx.conf, once:')"
check "names the module include, and where" yes "$(has 'include /usr/share/unmask/nginx/modules-enabled/*.conf;     <- as the first line of the file')"
check "names the http include, and where" yes "$(has 'include /usr/share/unmask/nginx/conf.d/*.conf;     <- as the first line inside http { }')"
check "says a restart is what loads a module" yes "$(has 'restart nginx (a reload does not load a module)')"
dump 'include /usr/share/unmask/nginx/modules-enabled/*.conf;
http { }'
out=$(own_includes_say unmask-web-nginx)
check "with the module line there, only the http one is named" "no yes" "$(has 'modules-enabled') $(has 'conf.d/*.conf;     <- as the first line inside http')"
dump 'include /usr/share/unmask/nginx/modules-enabled/*.conf;
http { include /usr/share/unmask/nginx/conf.d/*.conf; }'
check "with both there, nothing is said" "" "$(own_includes_say unmask-plugin-nginx)"

# ---- the group nginx's workers run in (postinstall.sh, which shares the
# daemon's sockets with it) ----
# nginx.conf's `user` first; where the file names none, what the binary was
# configured with -- a self-built nginx often says it there and nowhere else.
eval "$(sed -n '/^nginx_worker_group() {/,/^}/p' "$DIR/postinstall.sh")"
me=$(id -un)
mygrp=$(id -gn)
nginx() { :; }      # there is one to ask (the function asks `command -v nginx`)
printf 'user %s %s;\n' "$me" "$mygrp" > "$T/wg-both.conf"
printf 'user %s;\n' "$me" > "$T/wg-user.conf"
printf 'worker_processes auto;\n' > "$T/wg-none.conf"
v "configure arguments: --prefix=/x --user=no-such-user-unmask --group=no-such-group-unmask"
check "worker group: nginx.conf's user and group" "$mygrp" "$(nginx_worker_group "$T/wg-both.conf")"
check "worker group: a user alone has its own group, not the binary's" "$mygrp" "$(nginx_worker_group "$T/wg-user.conf")"
v "configure arguments: --prefix=/x --user=$me --group=$mygrp"
check "worker group: no user in the file -> the binary's --group" "$mygrp" "$(nginx_worker_group "$T/wg-none.conf")"
v "configure arguments: --prefix=/x --user=$me"
check "worker group: no user in the file -> the group of the binary's --user" "$mygrp" "$(nginx_worker_group "$T/wg-none.conf")"
v "configure arguments: --prefix=/x"
check "worker group: neither says" "" "$(nginx_worker_group "$T/wg-none.conf")"
v "configure arguments: --prefix=/x --user=$me --group=no-such-group-unmask"
check "worker group: a group this host does not have" "" "$(nginx_worker_group "$T/wg-none.conf")"

# ---- nginx_missing: what the nginx was built without ----
# unmask's files read $realip_remote_addr; an nginx configured without the
# realip module has no such variable and gets nothing of unmask to read.
v 'nginx version: nginx/1.22.1
configure arguments: --with-cc-opt=-g --prefix=/usr/share/nginx --conf-path=/etc/nginx/nginx.conf --with-compat --with-http_ssl_module --with-http_realip_module --with-http_auth_request_module'
check "nginx_missing: a distribution's build lacks nothing" "" "$(nginx_missing)"
v 'nginx version: nginx/1.28.3
configure arguments: --prefix=/usr/local/nginx --with-compat --with-http_ssl_module --with-http_v2_module'
check "nginx_missing: a plain ./configure has no realip module" "realip" "$(nginx_missing)"
v ''
check "nginx_missing: an nginx that answers nothing is not judged" "" "$(nginx_missing)"
v 'sh: nginx: Permission denied'
check "nginx_missing: nor one that cannot be asked" "" "$(nginx_missing)"

echo "----"
[ "$fails" -eq 0 ] && echo "nginx-layout_test: all passed" || echo "nginx-layout_test: $fails FAILED"
exit "$fails"
