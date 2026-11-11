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
#   - a load_module the operator wrote: theirs, no second one beside it;
#   - the nginx is built again (a panel installs another build and tests its
#     configuration before it starts anything): the watch's run takes the
#     module out and has the include files rendered with nothing in them,
#     whatever nginx.conf comes back loads, and the ordinary run puts the
#     module and the full configuration back once the lines are there;
#   - an http include that comes after the sites: rendered inert rather than
#     an nginx that does not start;
#   - nothing written into a closed pipe where SIGPIPE is ignored.
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
    # A systemd is there (the watch on the binary is written), and /run for the lock.
    mkdir -p "$T/run/systemd/system" "$T/etc/systemd/system"
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
        realip=" --with-http_realip_module"; [ -f "$ROOT/no-realip" ] && realip=""
        echo "configure arguments: --user=www --group=www --prefix=$PREFIX --with-http_ssl_module$realip$compat" >&2
        exit 0 ;;
    -T) cat "$PREFIX/conf/nginx.conf"
        for f in "$ROOT"/site/*.conf; do [ -f "$f" ] && { echo "# configuration file $f:"; cat "$f"; }; done
        # A long configuration: what reads it must read all of it.
        [ -f "$ROOT/long-dump" ] && { i=0; while [ $i -lt 4000 ]; do echo "    # a line of some site, number $i, long enough to fill a pipe before its reader is done"; i=$((i+1)); done; }
        exit 0 ;;
    -t) ;;
    *)  exit 0 ;;
esac
# nginx -t.  With -c: the placer asking whether this nginx takes the module.
conf=$PREFIX/conf/nginx.conf
asked=""
while [ $# -gt 0 ]; do [ "$1" = -c ] && { conf=$2; asked=1; }; shift; done
OWN=$ROOT/usr/share/unmask/nginx
fail() { echo "nginx: [emerg] $1" >&2; echo "nginx: configuration file $conf test failed" >&2; exit 1; }
if [ -n "$asked" ]; then
    if grep -q '^load_module' "$conf" 2>/dev/null && [ "$(cat "$ROOT/compat")" != yes ]; then
        so=$(sed -n 's/^load_module "\(.*\)";.*/\1/p' "$conf" | head -1)
        fail "module \"$so\" is not binary compatible in $conf:1"
    fi
    echo "nginx: configuration file $conf test is successful" >&2
    exit 0
fi
# The configuration itself.  What stops a real nginx there:
#   - a loader it reads for a module this build does not take;
#   - http.inc as rendered for the module, read without the module loaded;
#   - a server block that includes unmask's server.inc (a protected site:
#     $ROOT/site-uses-unmask) with anything in it, while http.inc -- which
#     defines what it names -- is not read ahead of the sites.
all=$(cat "$conf" "$ROOT"/site/*.conf 2>/dev/null)
loaded=no
if printf '%s\n' "$all" | grep -q "^include $OWN/modules-enabled/\*\.conf;" && [ -f "$OWN/modules-enabled/50-mod-unmask.conf" ]; then
    [ "$(cat "$ROOT/compat")" = yes ] || fail "module \"$OWN/modules/ngx_http_unmask_module.so\" is not binary compatible in $OWN/modules-enabled/50-mod-unmask.conf:1"
    loaded=yes
fi
printf '%s\n' "$all" | grep -q '^load_module .*ngx_http_unmask_module' && loaded=yes
http=no
printf '%s\n' "$all" | grep -q "^include $OWN/conf\.d/\*\.conf;" && http=yes
rendered=$(cat "$ROOT/rendered" 2>/dev/null || echo full)
if [ "$http" = yes ] && [ "$rendered" = full ] && [ "$loaded" = no ]; then
    fail "unknown directive \"unmask_bv_secret\" in $OWN/conf.d/00-unmask.conf:46"
fi
if [ -f "$ROOT/site-uses-unmask" ] && [ "$rendered" != inert ]; then
    if [ "$http" = no ] || [ -f "$ROOT/http-after-sites" ]; then
        fail "unknown log format \"unmask_minimal\" in $ROOT/var/lib/unmask/nginx/server.inc:39"
    fi
fi
echo "nginx: configuration file $conf test is successful" >&2
exit 0
STUB
    } > "$T/stub/nginx"
    printf '#!/bin/sh\ncase "${1:-}" in --version) echo "ldd (GNU libc) 2.36" ;; *) : ;; esac\n' > "$T/stub/ldd"
    # unmask render-nginx: what it would write follows the marker, as the
    # real render does -- full, without the module, or with nothing in the
    # files a server includes.
    { printf '#!/bin/sh\nROOT=%s\n' "$T"; cat <<'STUB'
echo "unmask $*" >> "$ROOT/calls.log"
[ "${1:-}" = render-nginx ] || exit 0
m=$ROOT/var/lib/unmask/nginx/.native-failsafe
[ -f "$ROOT/render-fails" ] && exit 1      # no database to read the settings from
if [ ! -e "$m" ]; then echo full
elif grep -q '^inert:' "$m"; then echo inert
else echo degraded
fi > "$ROOT/rendered"
exit 0
STUB
    } > "$T/stub/unmask"
    printf '#!/bin/sh\necho "systemctl $*" >> %s/calls.log\nexit 0\n' "$T" > "$T/stub/systemctl"
    chmod +x "$T"/stub/*
    # The script asks `command -v nginx` whether there is one.  The copy asks
    # for this name instead -- a link to the stand-in, as a panel's
    # /usr/bin/nginx is one -- so that "the nginx is gone" is this root's to
    # say, whatever the host running the test has installed.
    ln -s nginx "$T/stub/unmask-test-nginx"
    : > "$T/calls.log"
    # The system has libcrypto.so.3 and no libcrypto.so.1.1, like every current
    # distribution: the placer looks in the usual directories.
    mkdir -p "$T/usr/lib64" && : > "$T/usr/lib64/libcrypto.so.3"
    sed -e "s|/usr/share/unmask|$T/usr/share/unmask|g" \
        -e "s|/var/lib/unmask|$T/var/lib/unmask|g" \
        -e "s|/usr/sbin/unmask|$T/stub/unmask|g" \
        -e "s|/etc/nginx|$T/etc/nginx|g" \
        -e "s|/etc/systemd/system|$T/etc/systemd/system|g" \
        -e "s|/run/systemd/system|$T/run/systemd/system|g" \
        -e "s|/run/unmask-place-module.lock|$T/run/unmask-place-module.lock|g" \
        -e "s|command -v nginx|command -v unmask-test-nginx|g" \
        -e "s|:/usr/local/sbin:/usr/local/bin|:$T/usr/local/sbin:$T/usr/local/bin|" \
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
MARKER_REL=var/lib/unmask/nginx/.native-failsafe
marker() { if [ ! -e "$T/$MARKER_REL" ]; then echo none; elif grep -q '^inert:' "$T/$MARKER_REL"; then echo inert; else echo degraded; fi; }
marker_says() { grep -qF -- "$1" "$T/$MARKER_REL" 2>/dev/null && echo yes || echo no; }
rendered() { cat "$T/rendered" 2>/dev/null || echo full; }
renders() { grep -c '^unmask render-nginx' "$T/calls.log"; }
is_there() { [ -e "$1" ] && echo present || echo absent; }
nginx_t() { PATH="$T/stub:$PATH" nginx -t >/dev/null 2>&1 && echo passes || echo fails; }
WATCH_REL=etc/systemd/system/unmask-nginx-binary.path
NOTE_REL=var/lib/unmask/plugin/.nginx-includes
note() { cat "$T/$NOTE_REL" 2>/dev/null || echo none; }
systemctls() { grep '^systemctl ' "$T/calls.log" | sed 's/^systemctl //' | tr '\n' '|'; }

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
check "1 the http include is named, and where" yes "$(out_has "include $OWN/conf.d/*.conf;     <- as the first line inside http { }")"
check "1 the watch names this nginx's binary" "PathChanged=$T/stub/nginx" "$(grep '^PathChanged=' "$T/$WATCH_REL" 2>/dev/null)"
check "1 the watch starts the shipped service" "Unit=unmask-nginx-binary.service" "$(grep '^Unit=' "$T/$WATCH_REL" 2>/dev/null)"
check "1 the watch is switched on, without waiting on anything" "daemon-reload|enable unmask-nginx-binary.path|--no-block restart unmask-nginx-binary.path|" "$(systemctls)"
check "1 it says what happens when this nginx is built again" yes "$(out_has "takes its module out the moment the binary changes")"
check "1 the build the module is in place for is noted" "$T/stub/nginx" "$(sed 's/^[0-9a-f]*  //' "$T/var/lib/unmask/plugin/.nginx-binary" 2>/dev/null)"
check "1 no marker: nothing was taken out" none "$(marker)"
check "1 what the configuration lacks is noted for doctor" "missing: main http" "$(note)"

# --- 2. the operator has added the two lines ---
{ echo "include $OWN/modules-enabled/*.conf;"; cat "$T/nginx.conf.orig"; } > "$PREFIX/conf/nginx.conf"
echo "include $OWN/conf.d/*.conf;" > "$T/site/0.unmask.conf"
cp "$PREFIX/conf/nginx.conf" "$T/nginx.conf.wired"
: > "$T/calls.log"
place; rc=$?
check "2 the placer succeeds" 0 "$rc"
check "2 the watch is as it was: systemd is not asked again" "" "$(systemctls)"
check "2 the module is found unchanged" yes "$(out_has "module unchanged")"
check "2 nothing more is asked for" no "$(out_has "was not installed from a package")"
check "2 nginx.conf is as the operator left it" same "$(conf_same "$T/nginx.conf.wired")"
check "2 the watch, unchanged, is not written again" no "$(out_has "watch on")"
check "2 the note for doctor says both lines are there" ok "$(note)"

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
check "6 their line loads the module: the full configuration is back" "none full" "$(marker) $(rendered)"
check "6 and the note for doctor counts their line" ok "$(note)"

# --- 7. the nginx is built again: what the watch on its binary does ---
# A panel removes the build, installs another, puts an nginx.conf in place
# and runs nginx -t on it before it starts anything; when that fails it stops
# there and no nginx runs.
rm -rf "$T"
new_root
wired_conf() {
    {
        echo "include $OWN/modules-enabled/*.conf;"
        echo "user  www www;"
        echo "events { }"
        echo "http"
        echo "    {"
        echo "include $OWN/conf.d/*.conf;"
        echo "        include mime.types;"
        echo "        include $T/site/*.conf;"
        echo "    }"
    } > "$PREFIX/conf/nginx.conf"
}
place
wired_conf                      # the operator adds the two lines ...
: > "$T/site-uses-unmask"       # ... and a site includes server.inc
place; rc=$?
check "7 wired, a site protected: nothing is out" "0 none full passes" "$rc $(marker) $(rendered) $(nginx_t)"
check "7 the watch follows the link to the binary itself" "PathChanged=$T/stub/nginx" "$(grep '^PathChanged=' "$T/$WATCH_REL" 2>/dev/null)"
n=$(renders)
place --nginx-changed; rc=$?
check "7 the watch fires on the same build (a touch, a chmod): nothing is done" "0 none $n present" "$rc $(marker) $(renders) $(is_there "$OWN/modules/$SO")"

echo "# another build" >> "$T/stub/nginx"
cp "$PREFIX/conf/nginx.conf" "$T/nginx.conf.before"
: > "$T/calls.log"
place --nginx-changed; rc=$?
ran=$(grep -c '^nginx -[^Vv]' "$T/calls.log")
check "7 another build: the watch's run succeeds" 0 "$rc"
check "7 the module and its loader are out" "absent absent" "$(is_there "$OWN/modules/$SO") $(is_there "$OWN/modules-enabled/50-mod-unmask.conf")"
check "7 the marker asks for the inert render, and says why" "inert yes" "$(marker) $(marker_says 'the nginx binary changed')"
check "7 the files are rendered again, inert" "1 inert" "$(renders) $(rendered)"
check "7 nginx.conf is not touched" same "$(conf_same "$T/nginx.conf.before")"
check "7 what was noted of the old build's nginx.conf is dropped" none "$(note)"
check "7 it says what happens next" yes "$(out_has "the next build loads its configuration")"
check "7 nginx -t passes with the operator's lines there" passes "$(nginx_t)"
check "7 the watch's run asks nginx for its build options and nothing else" 0 "$ran"
place --nginx-changed
check "7 fired again, out already: nothing more is done" 1 "$(renders)"
cp "$T/nginx.conf.orig" "$PREFIX/conf/nginx.conf"
check "7 an older nginx.conf without the lines loads too, protected site and all" passes "$(nginx_t)"

# --- 8. the new build does not take the module (built without --with-compat) ---
# nginx's service starts it: the ordinary run.
echo no > "$T/compat"
place; rc=$?
check "8 the placer refuses" 1 "$rc"
check "8 unmask stays out, for the reason of now" "inert yes" "$(marker) $(marker_says 'does not load the module')"
check "8 rendered inert" inert "$(rendered)"
check "8 nginx -t passes: the sites start, without unmask" passes "$(nginx_t)"
check "8 the refused build's nginx.conf is noted for doctor all the same" "missing: main http" "$(note)"

# --- 9. built again --with-compat, the nginx.conf still without the lines ---
echo yes > "$T/compat"
echo "# a third build" >> "$T/stub/nginx"
place --nginx-changed
place; rc=$?
check "9 the module is placed for the build" "0 MODULE-1.26.3" "$rc $(cat "$OWN/modules/$SO" 2>/dev/null)"
check "9 the lines are missing: unmask stays out, and the marker says that" "inert yes" "$(marker) $(marker_says "does not include unmask's directories (missing: main http)")"
check "9 the two lines are named" "yes yes" "$(out_has "<- as the first line of the file") $(out_has "<- as the first line inside http { }")"
check "9 it says what it waits for" yes "$(out_has "stays rendered without unmask until")"
check "9 rendered inert, and nginx -t passes" "inert passes" "$(rendered) $(nginx_t)"
check "9 the watch's run finds the build it knows: the module stays" present "$(place --nginx-changed; is_there "$OWN/modules/$SO")"

# --- 10. the operator adds the lines, and nginx is started again ---
wired_conf
check "10 with the lines added and nothing run yet, nginx -t passes" passes "$(nginx_t)"
place; rc=$?
check "10 the ordinary run puts the full configuration back" "0 none full" "$rc $(marker) $(rendered)"
check "10 it says the fail-safe cleared" yes "$(out_has "fail-safe cleared")"
check "10 nginx -t passes with the module wired" passes "$(nginx_t)"

# --- 11. the nginx is gone: a panel between two builds ---
rm -f "$T/stub/unmask-test-nginx"
: > "$T/calls.log"
place --nginx-changed; rc=$?
check "11 the watch's run takes unmask out" "0 inert absent absent" "$rc $(marker) $(is_there "$OWN/modules/$SO") $(is_there "$OWN/modules-enabled/50-mod-unmask.conf")"
check "11 the marker says the binary is gone" yes "$(marker_says 'the nginx binary is gone')"
check "11 rendered inert, and no nginx was run" "inert 0" "$(rendered) $(grep -c '^nginx ' "$T/calls.log")"
place; rc=$?
check "11 the ordinary run without an nginx says so, and unmask stays out" "1 yes inert" "$rc $(out_has 'no nginx command on this host') $(marker)"
ln -s nginx "$T/stub/unmask-test-nginx"

# --- 12. the http include after the sites ---
# A server that includes server.inc names a log format the http directory
# defines; read after the sites, it is not defined yet.  nginx does not start
# on that -- with the module out either.  The last step is the inert render.
wired_conf
: > "$T/http-after-sites"
place; rc=$?
check "12 the placer ends" 0 "$rc"
check "12 the full configuration does not load, nor the one without the module" yes "$(out_has "nginx -t still fails on unmask's files without the module")"
check "12 so the include files are rendered with nothing in them" "inert inert yes" "$(marker) $(rendered) $(out_has "rendered with nothing in them")"
check "12 and nginx -t passes" passes "$(nginx_t)"
rm -f "$T/http-after-sites"
place; rc=$?
check "12 with the line moved ahead of the sites, the full configuration is back" "0 none full passes" "$rc $(marker) $(rendered) $(nginx_t)"

# --- 13. a long configuration, where SIGPIPE is ignored ---
# systemd starts its services that way, and this runs before every nginx
# start: a reader that stops at the first match leaves its writers saying
# "Broken pipe" into the journal.
: > "$T/long-dump"
( trap '' PIPE; place )
check "13 nothing is written into a closed pipe" 0 "$(grep -ci 'broken pipe' "$T/err")"
check "13 and the run did what it does" yes "$(out_has "module unchanged")"

# --- 14. the first nginx this plugin sees is one it refuses ---
# Installed after the plugin, or by a panel's Quick install: watched all the
# same -- it is the one that will be built again.
rm -rf "$T"
new_root
echo no > "$T/compat"
place; rc=$?
check "14 refused" 1 "$rc"
check "14 the watch is written for it, and switched on" "PathChanged=$T/stub/nginx yes" "$(grep '^PathChanged=' "$T/$WATCH_REL" 2>/dev/null) $(systemctls | grep -q 'restart unmask-nginx-binary.path' && echo yes || echo no)"
check "14 and its nginx.conf is noted for doctor" "missing: main http" "$(note)"

# --- 15. the render cannot run when the binary changes ---
# No database to read the settings from: the include files stay as they
# were, and the watch's run says so instead of saying they are empty.
rm -rf "$T"
new_root
place
echo "# another build" >> "$T/stub/nginx"
: > "$T/render-fails"
place --nginx-changed; rc=$?
check "15 the watch's run ends without an error of its own" 0 "$rc"
check "15 the module is out, and the marker asks for the inert render" "absent inert" "$(is_there "$OWN/modules/$SO") $(marker)"
check "15 it says the files are as they were, and what to run" "yes yes no" "$(out_has "could not run") $(out_has "unmask render-nginx") $(out_has "carry nothing, so the next build")"
rm -f "$T/render-fails"

# --- 16. no systemd: no watch, and the words for it ---
rm -rf "$T"
new_root
rmdir "$T/run/systemd/system"
place; rc=$?
check "16 the placer succeeds" 0 "$rc"
check "16 no watch is written, and systemd is not asked" "absent " "$(is_there "$T/$WATCH_REL") $(systemctls)"
check "16 it says to run the placer before the rebuilt nginx starts" yes "$(out_has "BEFORE it is started")"

# --- 17. no nginx on the host, and nothing wired ---
# The rpm and deb packages install no nginx, so the placer meets a host
# without one: it says so, says how the module gets placed once there is
# one, and writes nothing.
rm -rf "$T"
new_root
rm -f "$T/stub/unmask-test-nginx"
: > "$T/calls.log"
place; rc=$?
check "17 without an nginx the placer says so and places nothing" "1 yes" "$rc $(out_has 'no nginx command on this host, so no module was placed')"
check "17 it names the run that places the module later" yes "$(out_has "sudo sh $T/usr/share/unmask/plugin/place-module.sh")"
check "17 nothing is written: no marker, no render, no watch, no module" "none 0 absent absent" "$(marker) $(renders) $(is_there "$T/$WATCH_REL") $(is_there "$OWN/modules/$SO")"

# --- 18. the nginx is linked into /usr/local/sbin and nowhere else ---
# Where a build by hand is commonly linked: on a root shell's PATH and
# systemd's, not on the one apt and rpm give a package's scripts.  The
# placer looks there when the PATH it was given has no nginx.
rm -rf "$T"
new_root
mkdir -p "$T/usr/local/sbin" && mv "$T/stub/unmask-test-nginx" "$T/usr/local/sbin/unmask-test-nginx"
ln -sf "$T/stub/nginx" "$T/usr/local/sbin/unmask-test-nginx"
place; rc=$?
check "18 an nginx only in /usr/local/sbin is found and gets its module" "0 yes MODULE-1.26.3" "$rc $(out_has "an nginx built from source") $(cat "$OWN/modules/$SO" 2>/dev/null)"

# --- 19. an nginx built without the realip module ---
# unmask's http files read $realip_remote_addr, and that nginx has no such
# variable: with them included it does not load its configuration, and its
# error names no file of unmask's.  So it gets nothing to read -- not the
# module, not the links in the http directory, not a directive in what a
# server block includes -- and is told which configure option it lacks.
rm -rf "$T"
new_root
mkdir -p "$T/usr/share/unmask" "$T/var/lib/unmask/nginx" "$OWN/conf.d"
: > "$T/usr/share/unmask/nginx-reload-if-stale.sh"          # unmask-web-nginx is installed
echo "upstream unmask_daemon { server 127.0.0.1:9477; }" > "$T/var/lib/unmask/nginx/upstream.conf"
echo "# lb gate" > "$T/var/lib/unmask/nginx/forward-auth-lbtrust.conf"
web_links() { echo "$(is_there "$OWN/conf.d/00-unmask-upstream.conf") $(is_there "$OWN/conf.d/zz-unmask-fa-lbtrust.conf")"; }
place; rc=$?
check "19 with the module, the placer puts the web package's links beside http.inc" "0 present present" "$rc $(web_links)"
: > "$T/no-realip"
: > "$T/calls.log"
place; rc=$?
check "19 an nginx without the realip module is refused" "1 yes" "$rc $(out_has "this nginx cannot read unmask's configuration -- nothing placed")"
check "19 the option to add is named" yes "$(out_has "Add --with-http_realip_module to its configure line")"
check "19 the module and its loader are out" "absent absent" "$(is_there "$OWN/modules/$SO") $(is_there "$OWN/modules-enabled/50-mod-unmask.conf")"
check "19 nothing is left in the http directory" "absent absent absent" "$(is_there "$OWN/conf.d/00-unmask.conf") $(web_links)"
check "19 the marker asks for the inert render, and says why" "inert yes inert" "$(marker) $(marker_says 'built without --with-http_realip_module') $(rendered)"
check "19 nginx.conf is as it was, and nginx was not run for a test" "same 0" "$(conf_same "$T/nginx.conf.orig") $(grep -c '^nginx -t' "$T/calls.log")"
# A file of the operator's under one of the names is not a link, and stays.
echo "# the operator's own" > "$OWN/conf.d/00-unmask-upstream.conf"
place --verify; rc=$?
check "19 the web package's check does the same, without the report" "0 no inert" "$rc $(out_has "nothing placed") $(marker)"
check "19 a file of that name is the operator's and stays" present "$(is_there "$OWN/conf.d/00-unmask-upstream.conf")"
rm -f "$OWN/conf.d/00-unmask-upstream.conf"
# Built again with the module: the ordinary run places everything back.
rm -f "$T/no-realip"
place; rc=$?
check "19 built again with the realip module: placed, and the links are back" "0 MODULE-1.26.3 present present present" "$rc $(cat "$OWN/modules/$SO" 2>/dev/null) $(is_there "$OWN/conf.d/00-unmask.conf") $(web_links)"
# Without unmask-web-nginx its links are not the placer's to make.
rm -f "$T/usr/share/unmask/nginx-reload-if-stale.sh" "$OWN/conf.d/00-unmask-upstream.conf" "$OWN/conf.d/zz-unmask-fa-lbtrust.conf"
place; rc=$?
check "19 without the web package, its links are not made" "0 absent absent" "$rc $(web_links)"

rm -rf "$T"
echo "----"
[ "$fails" -eq 0 ] && echo "place-module-selfbuilt_test: all passed" || echo "place-module-selfbuilt_test: $fails FAILED"
exit "$fails"
