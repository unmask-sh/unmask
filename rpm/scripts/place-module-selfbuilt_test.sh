#!/bin/sh
# Test for place-module.sh on an nginx built from source: by hand under a
# prefix, or by a hosting panel.  Its nginx.conf is somewhere else, it names
# no modules path, and the file is its builder's -- so the placer writes
# nothing of that nginx's.  It keeps the module and the conf that loads it in
# directories of unmask's own, and says which include lines to add.
#
#   - placed for such an nginx: the module and its loader in unmask's own
#     directories, http.inc linked into unmask's own http directory, the two
#     include lines named -- and nginx.conf, the prefix and /etc/nginx as
#     they were;
#   - with the two lines there: nothing more is asked for;
#   - an nginx that does not take the module (built without --with-compat):
#     refused before anything is wired, in words, and nothing is left behind;
#   - a fork that names an nginx version: not placed;
#   - no module for its version: the module is taken out, the operator's
#     lines and file stay;
#   - a load_module the operator wrote: theirs, no second one beside it.
#
# The script is run for real against a throwaway root: a copy with its
# absolute paths pointed into a temporary directory, and stand-ins for nginx,
# ldd and unmask on PATH.  No nginx, no root.  POSIX sh:
#   sh rpm/scripts/place-module-selfbuilt_test.sh
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
SH=${UNMASK_TEST_SH:-/bin/sh}
fails=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails+1)); }
check() { if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected=\"$2\" got=\"$3\")"; fi; }
SO=ngx_http_unmask_module.so

new_root() {
    T=$(mktemp -d)
    PREFIX=$T/www/server/nginx
    OWN=$T/usr/share/unmask/nginx
    BUNDLE=$T/usr/share/unmask/plugin/openssl3
    mkdir -p "$T/stub" "$PREFIX/conf" "$PREFIX/sbin" "$BUNDLE" "$T/var/lib/unmask/nginx" "$T/site"
    echo "MODULE-1.26.3" > "$BUNDLE/ngx_http_unmask_module-1.26.3.so"
    : > "$T/var/lib/unmask/nginx/http.inc"
    echo nginx > "$T/kind"          # nginx | fork
    echo yes > "$T/compat"          # yes | no
    {
        echo "user  www www;"
        echo "stream {"
        echo "    include $T/site/tcp/*.conf;"     # the first include of a panel's nginx.conf: not a place for modules
        echo "}"
        echo "events { }"
        echo "http"
        echo "    {"
        echo "        include mime.types;"
        echo "        include $T/site/*.conf;"
        echo "    }"
    } > "$PREFIX/conf/nginx.conf"
    cp "$PREFIX/conf/nginx.conf" "$T/nginx.conf.orig"
    # nginx: built under a prefix, no --conf-path, no --modules-path.
    { printf '#!/bin/sh\nROOT=%s\nPREFIX=%s\n' "$T" "$PREFIX"; cat <<'STUB'
echo "nginx $*" >> "$ROOT/calls.log"
case "${1:-}" in
    -v) [ "$(cat "$ROOT/kind")" = fork ] && echo "Tengine version: Tengine/3.1.0" >&2
        echo "nginx version: nginx/1.26.3" >&2; exit 0 ;;
    -V) echo "nginx version: nginx/1.26.3" >&2
        echo "built with OpenSSL 1.1.1w  11 Sep 2023" >&2
        compat=""; [ "$(cat "$ROOT/compat")" = yes ] && compat=" --with-compat"
        echo "configure arguments: --user=www --group=www --prefix=$PREFIX --with-http_ssl_module$compat" >&2
        exit 0 ;;
    -T) cat "$PREFIX/conf/nginx.conf"
        for f in "$ROOT"/site/*.conf; do [ -f "$f" ] && { echo "# configuration file $f:"; cat "$f"; }; done
        exit 0 ;;
    -t) ;;
    *)  exit 0 ;;
esac
# nginx -t.  With -c: the placer asking whether this nginx takes the module.
conf=$PREFIX/conf/nginx.conf
while [ $# -gt 0 ]; do [ "$1" = -c ] && conf=$2; shift; done
if grep -q '^load_module' "$conf" 2>/dev/null && [ "$(cat "$ROOT/compat")" != yes ]; then
    so=$(sed -n 's/^load_module "\(.*\)";.*/\1/p' "$conf" | head -1)
    echo "nginx: [emerg] module \"$so\" is not binary compatible in $conf:1" >&2
    echo "nginx: configuration file $conf test failed" >&2
    exit 1
fi
echo "nginx: configuration file $conf test is successful" >&2
exit 0
STUB
    } > "$T/stub/nginx"
    printf '#!/bin/sh\ncase "${1:-}" in --version) echo "ldd (GNU libc) 2.36" ;; *) : ;; esac\n' > "$T/stub/ldd"
    printf '#!/bin/sh\necho "unmask $*" >> %s/calls.log\nexit 0\n' "$T" > "$T/stub/unmask"
    chmod +x "$T"/stub/*
    : > "$T/calls.log"
    # The system has libcrypto.so.3 and no libcrypto.so.1.1, like every current
    # distribution: the placer looks in the usual directories.
    mkdir -p "$T/usr/lib64" && : > "$T/usr/lib64/libcrypto.so.3"
    sed -e "s|/usr/share/unmask|$T/usr/share/unmask|g" \
        -e "s|/var/lib/unmask|$T/var/lib/unmask|g" \
        -e "s|/usr/sbin/unmask|$T/stub/unmask|g" \
        -e "s|/etc/nginx|$T/etc/nginx|g" \
        -e "s|/lib/ld-|$T/lib/ld-|g" \
        -e "s|for d in /lib64 /usr/lib64 /lib /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu; do|for d in $T/usr/lib64; do|" \
        "$DIR/place-module.sh" > "$T/place-module.sh"
    grep -q "for d in $T/usr/lib64; do" "$T/place-module.sh" \
        || { echo "FATAL: the list of library directories in place-module.sh changed; this test would read the host's"; exit 2; }
}
place() { PATH="$T/stub:$PATH" "$SH" "$T/place-module.sh" "$@" > "$T/out" 2> "$T/err"; }
out_has() { cat "$T/out" "$T/err" | grep -qF -- "$1" && echo yes || echo no; }
conf_same() { cmp -s "$PREFIX/conf/nginx.conf" "$1" && echo same || echo changed; }
under_prefix() { find "$PREFIX" -type f | sed "s|$PREFIX/||" | sort | tr '\n' ' ' | sed 's/ $//'; }

# --- 1. placed, with nothing of that nginx's written ---
new_root
place; rc=$?
check "1 the placer succeeds" 0 "$rc"
check "1 it takes the nginx for a self-built one" yes "$(out_has "an nginx built from source (configuration: $PREFIX/conf/nginx.conf)")"
check "1 the module of the family the system can load (3), for a static 1.1.1w" "MODULE-1.26.3" "$(cat "$OWN/modules/$SO" 2>/dev/null)"
check "1 its loader is in unmask's own directory" "load_module \"$OWN/modules/$SO\";" "$(sed 's/;.*/;/' "$OWN/modules-enabled/50-mod-unmask.conf" 2>/dev/null)"
check "1 http.inc is linked into unmask's own http directory" "$T/var/lib/unmask/nginx/http.inc" "$(readlink "$OWN/conf.d/00-unmask.conf" 2>/dev/null)"
check "1 the note of where things went names both" "so $OWN/modules/$SO|conf $OWN/modules-enabled/50-mod-unmask.conf|" "$(tr '\n' '|' < "$T/var/lib/unmask/plugin/.wired")"
check "1 nginx.conf is as it was" same "$(conf_same "$T/nginx.conf.orig")"
check "1 nothing was added under the prefix" "conf/nginx.conf" "$(under_prefix)"
check "1 the stream block's include directory got no loader" absent "$([ -e "$T/site/tcp/50-mod-unmask.conf" ] && echo present || echo absent)"
check "1 no /etc/nginx was made" absent "$([ -e "$T/etc/nginx" ] && echo present || echo absent)"
check "1 the module include is named, and where" yes "$(out_has "include $OWN/modules-enabled/*.conf;     <- as the first line of the file")"
check "1 the http include is named, and where" yes "$(out_has "include $OWN/conf.d/*.conf;     <- inside http { }")"
check "1 it says what a rebuilt nginx needs" yes "$(out_has "BEFORE it is started")"

# --- 2. the operator has added the two lines ---
{ echo "include $OWN/modules-enabled/*.conf;"; cat "$T/nginx.conf.orig"; } > "$PREFIX/conf/nginx.conf"
echo "include $OWN/conf.d/*.conf;" > "$T/site/0.unmask.conf"
cp "$PREFIX/conf/nginx.conf" "$T/nginx.conf.wired"
place; rc=$?
check "2 the placer succeeds" 0 "$rc"
check "2 the module is found unchanged" yes "$(out_has "module unchanged")"
check "2 nothing more is asked for" no "$(out_has "was not installed from a package")"
check "2 nginx.conf is as the operator left it" same "$(conf_same "$T/nginx.conf.wired")"

# --- 3. the same nginx built without --with-compat ---
echo no > "$T/compat"
place; rc=$?
check "3 the placer refuses" 1 "$rc"
check "3 it says what nginx said" yes "$(out_has "is not binary compatible")"
check "3 it names --with-compat" yes "$(out_has "configured --with-compat")"
check "3 the loader is gone" absent "$([ -e "$OWN/modules-enabled/50-mod-unmask.conf" ] && echo present || echo absent)"
check "3 the module file is gone" absent "$([ -e "$OWN/modules/$SO" ] && echo present || echo absent)"
check "3 the fail-safe's marker says why" yes "$(grep -q 'does not load the module' "$T/var/lib/unmask/nginx/.native-failsafe" 2>/dev/null && echo yes || echo no)"
check "3 nginx.conf is as the operator left it" same "$(conf_same "$T/nginx.conf.wired")"
echo yes > "$T/compat"
place; rc=$?
check "3 built --with-compat again, it is placed again" "0 MODULE-1.26.3" "$rc $(cat "$OWN/modules/$SO" 2>/dev/null)"

# --- 4. a fork that names an nginx version ---
echo fork > "$T/kind"
place; rc=$?
check "4 the placer refuses a fork" 1 "$rc"
check "4 it says so" yes "$(out_has "a fork of nginx, not nginx 1.26.3 -- nothing placed")"
check "4 the module is taken out" absent "$([ -e "$OWN/modules/$SO" ] && echo present || echo absent)"
echo nginx > "$T/kind"
place

# --- 5. no module for this nginx's version ---
mv "$BUNDLE/ngx_http_unmask_module-1.26.3.so" "$T/held.so"
place; rc=$?
check "5 the placer says none was placed" 1 "$rc"
check "5 it names the version" yes "$(out_has "no module for nginx 1.26.3 -- nothing placed")"
check "5 the loader and the module are gone" "absent absent" "$([ -e "$OWN/modules-enabled/50-mod-unmask.conf" ] && echo present || echo absent) $([ -e "$OWN/modules/$SO" ] && echo present || echo absent)"
check "5 nginx.conf still carries the operator's lines, untouched" same "$(conf_same "$T/nginx.conf.wired")"
mv "$T/held.so" "$BUNDLE/ngx_http_unmask_module-1.26.3.so"

# --- 6. a load_module the operator wrote themselves ---
{ echo "load_module \"/opt/own/$SO\";"; cat "$T/nginx.conf.orig"; } > "$PREFIX/conf/nginx.conf"
cp "$PREFIX/conf/nginx.conf" "$T/nginx.conf.own"
place; rc=$?
check "6 the placer succeeds" 0 "$rc"
check "6 no second loader is put beside the operator's line" absent "$([ -e "$OWN/modules-enabled/50-mod-unmask.conf" ] && echo present || echo absent)"
check "6 it says the include follows upgrades, the line does not" yes "$(out_has "follows every upgrade of unmask and of nginx")"
check "6 the operator's line is theirs: nginx.conf is as it was" same "$(conf_same "$T/nginx.conf.own")"

rm -rf "$T"
echo "----"
[ "$fails" -eq 0 ] && echo "place-module-selfbuilt_test: all passed" || echo "place-module-selfbuilt_test: $fails FAILED"
exit "$fails"
