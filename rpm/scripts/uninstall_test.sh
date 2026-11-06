#!/bin/sh
# Test for removing unmask-plugin-nginx and unmask-web-nginx: what the removal
# takes out of nginx, what it leaves, and what it tells the operator.
#
# The module's load_module is put where nginx.conf says modules are loaded
# from -- a different directory per distribution -- and the removal used to
# look in a fixed list that was not the same list in the two places that kept
# one.  Where the directory was on neither (/etc/nginx/modules, or one of the
# operator's own), removing the package deleted the .so and left the
# 50-mod-unmask.conf that names it: nginx died on dlopen() at its next start.
# So:
#
#   - place, then remove, on each kind of host: nothing of the package's is
#     left in nginx, and nginx.conf is what it was;
#   - with the placer's note of where it put things, and without it (an
#     install from before the note);
#   - only what the package put there goes: a load_module the operator wrote
#     stays, and is named;
#   - the lines of the operator's own server blocks that include unmask's
#     files are named, once, whichever of the two packages goes first -- and
#     `nginx -t` is run and its answer printed.  nginx is never reloaded or
#     restarted from a package script.
#
# The scripts are run for real, against a throwaway root: copies with their
# absolute paths pointed into a temporary directory, and a PATH that holds
# stand-ins for the commands they call.  The stand-in for nginx answers -t the
# way nginx would for the handful of things that matter here: a load_module
# whose file is missing, a directive of the module without the module, an
# include of a file that is not there, a log format or an upstream nobody
# defined.  No VM, no root, no nginx.
#
# POSIX sh throughout, so that it also runs where /bin/sh is dash or busybox:
#   bash rpm/scripts/uninstall_test.sh
#   UNMASK_TEST_SH=/bin/dash sh rpm/scripts/uninstall_test.sh
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
SH=${UNMASK_TEST_SH:-/bin/sh}
fails=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails+1)); }
check() { # <desc> <expected> <actual>
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected=\"$2\" got=\"$3\")"; fi
}

SO=ngx_http_unmask_module.so
CONF=50-mod-unmask.conf
TAG='# unmask-plugin-nginx: auto-added'

# new_root <debian|rhel|alpine|none|custom>
# A throwaway root in $T, laid out the way that kind of host's nginx package
# lays it out, with the unmask package's rendered files in place and a site
# of the operator's.
#   debian   include /etc/nginx/modules-enabled/*.conf;
#   rhel     include /usr/share/nginx/modules/*.conf;
#   alpine   include /etc/nginx/modules/*.conf; and http.d inside http {}
#   none     no include ahead of http {} (nginx.org's package): the line goes
#            into nginx.conf itself
#   custom   two directories of the operator's own, on no list
new_root() {
    LAYOUT=$1
    T=$(mktemp -d)
    N=$T/etc/nginx
    MP=$T/usr/lib64/nginx/modules
    PLUG=$T/usr/share/unmask/plugin
    RD=$T/var/lib/unmask/nginx
    WIRED=$T/var/lib/unmask/plugin/.wired
    HTTPD=$N/conf.d
    MODDIR=
    case "$LAYOUT" in
        debian) MODDIR=$N/modules-enabled ;;
        rhel)   MODDIR=$T/usr/share/nginx/modules ;;
        alpine) MODDIR=$N/modules; HTTPD=$N/http.d ;;
        custom) MODDIR=$N/dyn-a; mkdir -p "$N/dyn-b" ;;
    esac
    # How the placer wires the module here: a conf in that directory, or a
    # line in nginx.conf itself.
    if [ -n "$MODDIR" ]; then WIRES=conf; else WIRES=line; fi
    mkdir -p "$T/stub" "$T/tools" "$T/pkg" "$N/conf.d" "$HTTPD" "$MP" "$RD" \
             "$T/etc/unmask/forward-auth" "$T/usr/sbin" "$T/usr/share/unmask"
    [ -n "$MODDIR" ] && mkdir -p "$MODDIR"
    : > "$T/calls.log"
    printf 'server:\n  port: 9477\n' > "$T/etc/unmask/config.yml"
    {
        echo "user nginx;"
        case "$LAYOUT" in
            alpine) echo "include $MODDIR/*.conf;"; echo "include $N/conf.d/*.conf;" ;;
            custom) echo "include $N/dyn-a/*.conf;"; echo "include $N/dyn-b/*.conf;" ;;
            none)   ;;
            *)      echo "include $MODDIR/*.conf;" ;;
        esac
        echo "events { }"
        echo "http {"
        echo "    include $HTTPD/*.conf;"
        echo "}"
    } > "$N/nginx.conf"
    cp "$N/nginx.conf" "$T/nginx.conf.orig"
    SITE=$HTTPD/site.conf
    site_without_includes

    # ---- the stand-ins ----
    mkstub() { # <name>; the body on stdin
        { printf '#!/bin/sh\nROOT=%s\n' "$T"; cat; } > "$T/stub/$1"
        chmod +x "$T/stub/$1"
    }
    mkstub nginx <<'STUB'
echo "nginx $*" >> "$ROOT/calls.log"
conf=$ROOT/etc/nginx/nginx.conf
case "${1:-}" in
    -v) echo "nginx version: nginx/1.26.3" >&2; exit 0 ;;
    -V) echo "nginx version: nginx/1.26.3" >&2
        echo "built with OpenSSL 3.0.13 30 Jan 2024" >&2
        echo "configure arguments: --prefix=$ROOT/etc/nginx --modules-path=$ROOT/usr/lib64/nginx/modules --with-compat" >&2
        exit 0 ;;
    -t) ;;
    *)  exit 0 ;;
esac
# nginx -t, for what matters here.  Read nginx.conf and what it includes in
# order, and stop at the first thing nginx would stop at.
loaded=0; logfmts=" "; upstreams=" "; vars=" "; need_up=""; need_var=""
die() {
    echo "nginx: [emerg] $1" >&2
    echo "nginx: configuration file $conf test failed" >&2
    exit 1
}
stmt() { # <file> <line> <one directive>
    local f="$1" n="$2" s="$3" p m w
    case "$s" in
        "load_module "*)
            p=$(printf '%s' "${s#load_module }" | tr -d "\"' ")
            [ -e "$p" ] || die "dlopen() \"$p\" failed ($p: cannot open shared object file: No such file or directory) in $f:$n"
            case "$p" in *ngx_http_unmask_module*)
                [ "$loaded" = 0 ] || die "module \"ngx_http_unmask_module\" is already loaded in $f:$n"
                loaded=1 ;;
            esac ;;
        "include "*)
            p=$(printf '%s' "${s#include }" | tr -d "\"' ")
            case "$p" in /*) ;; *) p="$ROOT/etc/nginx/$p" ;; esac
            case "$p" in
                *[*?[]*) for m in $p; do [ -f "$m" ] && read_conf "$m"; done ;;
                *)  [ -f "$p" ] || die "open() \"$p\" failed (2: No such file or directory) in $f:$n"
                    read_conf "$p" ;;
            esac ;;
        unmask_bv_secret*)
            [ "$loaded" = 1 ] || die "unknown directive \"unmask_bv_secret\" in $f:$n" ;;
        unmask_*)
            die "unknown directive \"${s%% *}\" in $f:$n" ;;
        "log_format "*) w=${s#log_format }; logfmts="$logfmts${w%% *} " ;;
        "access_log "*) w=${s##* }
            case "$logfmts" in *" $w "*) ;; *) die "unknown log format \"$w\" in $f:$n" ;; esac ;;
        "upstream "*)   w=${s#upstream }; upstreams="$upstreams${w%% *} " ;;
        "proxy_pass http://"*) w=${s#proxy_pass http://}; need_up="$need_up ${w%%[/ ]*}@$f:$n" ;;
        "map "*|"geo "*) w=${s##* }; vars="$vars${w#?} " ;;
        "set "*) case "$s" in *unmask_bv_kind*) need_var="$need_var unmask_bv_kind" ;; esac ;;
    esac
}
read_conf() { # <file>
    local f="$1" n=0 line rest s d='[{};]'
    while IFS= read -r line || [ -n "$line" ]; do
        n=$((n + 1))
        rest=${line%%#*}
        while [ -n "$rest" ]; do
            case "$rest" in
                *$d*) s=${rest%%$d*}; rest=${rest#*$d} ;;
                *)    s=$rest; rest="" ;;
            esac
            s=${s#"${s%%[![:space:]]*}"}
            s=${s%"${s##*[![:space:]]}"}
            [ -n "$s" ] && stmt "$f" "$n" "$s"
        done
    done < "$f"
}
read_conf "$conf"
for w in $need_up; do
    case "$upstreams" in
        *" ${w%%@*} "*) ;;
        *) die "host not found in upstream \"${w%%@*}\" in ${w#*@}" ;;
    esac
done
for w in $need_var; do
    [ "$loaded" = 1 ] && break
    case "$vars" in *" $w "*) ;; *) die "unknown \"$w\" variable" ;; esac
done
echo "nginx: the configuration file $conf syntax is ok" >&2
echo "nginx: configuration file $conf test is successful" >&2
exit 0
STUB
    mkstub ldd <<'STUB'
case "${1:-}" in
    --version) echo "ldd (GNU libc) 2.34" ;;
    *) echo "	libcrypto.so.3 => /lib64/libcrypto.so.3 (0x00007f0000000000)" ;;
esac
STUB
    mkstub systemctl <<'STUB'
echo "systemctl $*" >> "$ROOT/calls.log"
STUB
    mkstub hostname <<'STUB'
echo test-host
STUB
    # The unmask binary, for `render-nginx`: the configuration for the module,
    # or -- while the fail-safe's marker is there -- the one without it.
    { printf '#!/bin/sh\nROOT=%s\n' "$T"; cat <<'STUB'
echo "unmask $*" >> "$ROOT/calls.log"
d=$ROOT/var/lib/unmask/nginx
case "${1:-}" in
    render-nginx)
        if [ -e "$d/.native-failsafe" ]; then
            {
                echo "# NATIVE FAIL-SAFE ACTIVE: rendered without the module"
                echo "log_format unmask_minimal '\$remote_addr';"
                echo "map \$remote_addr \$unmask_bv_kind { default \"\"; }"
            } > "$d/http.inc"
        else
            {
                echo "log_format unmask_minimal '\$remote_addr';"
                echo "unmask_bv_secret                \"0123456789abcdef\";"
                [ -e "$ROOT/render-broken" ] && echo "unmask_from_the_future on;"
            } > "$d/http.inc"
        fi
        {
            echo "access_log syslog:server=unix:/run/unmask/log.sock unmask_minimal;"
            echo "set \$unmask_kind \$unmask_bv_kind;"
            echo "location ^~ /unmask/ { proxy_pass http://unmask_daemon; }"
            # unmask's own files include each other.
            [ -e "$ROOT/server-includes-protect" ] && echo "include $d/protect.inc;"
        } > "$d/server.inc"
        echo "set \$unmask_protect \$unmask_bv_kind;" > "$d/protect.inc"
        ;;
esac
exit 0
STUB
    } > "$T/usr/sbin/unmask"
    chmod +x "$T/usr/sbin/unmask"
    "$T/usr/sbin/unmask" render-nginx

    # What the scripts need from the system, and nothing else: no real nginx,
    # systemctl or restorecon may be reachable from here.  `sh` is the shell
    # under test, for the scripts that start another.
    for c in awk sed grep cat cp mv rm rmdir mkdir chmod ln readlink cmp tr head sort ls dirname basename date; do
        p=$(command -v "$c") && ln -s "$p" "$T/tools/$c"
    done
    ln -s "$SH" "$T/tools/sh"

    # The scripts, with their absolute paths pointed into the root.  The last
    # line is for the awk program that looks for Alpine's http.d, which spells
    # the path with its slashes escaped.
    TE=$(printf '%s' "$T" | sed 's|[/.]|\\\\&|g')
    {
        for p in /usr/share/nginx /usr/share/unmask /usr/sbin/unmask /var/lib/unmask /etc/nginx \
                 /etc/unmask /etc/systemd/system /run/systemd/system /run/unmask /run/nginx /lib/apk /lib/ld-; do
            printf 's|%s|%s%s|g\n' "$p" "$T" "$p"
        done
        printf 's|\\\\/etc\\\\/nginx\\\\/http\\\\.d\\\\/|%s\\\\/etc\\\\/nginx\\\\/http\\\\.d\\\\/|g\n' "$TE"
    } > "$T/paths.sed"
    for s in place-module.sh postinstall-plugin-nginx-fat.sh postinstall-plugin-nginx.sh \
             preremove-plugin-nginx.sh postinstall-web-nginx.sh postremove-web-nginx.sh; do
        sed -f "$T/paths.sed" "$DIR/$s" > "$T/pkg/$s"
    done
}

# The operator's site: as it is before they add the two includes the README
# names (and after they took them out again), and with them.
site_with_includes() {
    {
        echo "server {"
        echo "    listen 80;"
        echo "    include $RD/server.inc;"
        echo "    location / {"
        echo "        include $RD/protect.inc;"
        echo "    }"
        echo "}"
    } > "$SITE"
}
site_without_includes() { printf 'server {\n    listen 80;\n    location / {\n    }\n}\n' > "$SITE"; }

# run <script> <args...>: a package script, as the package manager calls it.
run() {
    _s=$1; shift
    PATH="$T/stub:$T/tools" "$SH" "$T/pkg/$_s" "$@" > "$T/out" 2>&1
    RC=$?
}
# What each package's install and removal amount to.
plugin_install() {      # the bundle variant: the placer and a module per nginx version
    mkdir -p "$PLUG/openssl3"
    cp "$T/pkg/place-module.sh" "$PLUG/place-module.sh"
    printf 'MODULE-FOR-1.26.3' > "$PLUG/openssl3/ngx_http_unmask_module-1.26.3.so"
    run postinstall-plugin-nginx-fat.sh 1
}
plugin_install_single() {   # the single-nginx variant: one staged module, no placer
    mkdir -p "$PLUG"
    printf 'MODULE-FOR-1.26.3' > "$PLUG/$SO"
    run postinstall-plugin-nginx.sh 1
}
plugin_prerm() { : > "$T/calls.log"; run preremove-plugin-nginx.sh "$@"; }
plugin_files_gone() { rm -rf "$PLUG"; }     # the package manager, after the preremove
web_install() {
    echo "location = /unmask-auth { proxy_pass http://unmask_daemon; }" > "$T/etc/unmask/forward-auth/server.inc"
    echo "auth_request /unmask-auth;" > "$T/etc/unmask/forward-auth/protect.inc"
    run postinstall-web-nginx.sh 1
}
web_postrm() { : > "$T/calls.log"; run postremove-web-nginx.sh "$@"; }
# The packages, then the operator's two lines -- in the order the README has it.
install_all() { plugin_install; web_install; site_with_includes; }

# What nginx itself would say now: "ok", or the error.
ngx_t() {
    if PATH="$T/stub:$T/tools" "$T/stub/nginx" -t > "$T/ngx.out" 2>&1; then echo ok
    else sed -n 's/^nginx: \[emerg\] //p' "$T/ngx.out" | sed "s|$T||g"; fi
}
says()    { grep -cF -- "$1" "$T/out"; }
there()   { if [ -e "$1" ] || [ -L "$1" ]; then echo there; else echo gone; fi; }
# How the module is loaded now: "conf" (the package's file in nginx.conf's
# directory), "line" (the tagged line in nginx.conf itself), "both" or "no".
wired() {
    _w=no
    [ -n "$MODDIR" ] && [ -e "$MODDIR/$CONF" ] && _w=conf
    if grep -q "^load_module .*$TAG" "$N/nginx.conf"; then
        if [ "$_w" = conf ]; then _w=both; else _w=line; fi
    fi
    echo "$_w"
}
# What 0.1.55 left on a host whose awk is busybox's (every Alpine install): the
# directory was not found, so the line is in nginx.conf itself, there is no
# conf, and no note.
line_install() {
    plugin_install
    rm -f "$MODDIR/$CONF" "$WIRED"
    { echo "load_module \"$MP/$SO\";  $TAG, removed on uninstall"; cat "$T/nginx.conf.orig"; } > "$N/nginx.conf"
    cp "$N/nginx.conf" "$T/nginx.conf.line"
}
same()    { if [ "$(cat "$1")" = "$(cat "$2")" ]; then echo same; else echo changed; fi; }
inode()   { ls -i "$1" | awk '{print $1}'; }
# The lines the removal told the operator to take out, as "file:line".
listed()  { sed -n 's/^    \([^ ]*:[0-9][0-9]*\): .*include .*/\1/p' "$T/out" | sed "s|$T||g" | tr '\n' ' ' | sed 's/ $//'; }
touched_nginx() { grep -cE '^nginx -s|^systemctl .*(reload|restart|stop|start).*nginx' "$T/calls.log"; }

# --- place, then remove, on each kind of host ----------------------------------
# The package manager's arguments differ too: rpm 0, dpkg "remove", and apk
# the version (told apart by /lib/apk).
for layout in debian rhel alpine none; do
    new_root "$layout"
    install_all
    case "$WIRES" in
        line) check "$layout: the load_module line is put into nginx.conf itself" line "$(wired)" ;;
        conf) check "$layout: the load_module conf is put where nginx.conf loads modules from" conf "$(wired)" ;;
    esac
    check "$layout: the module is in nginx's modules path" there "$(there "$MP/$SO")"
    check "$layout: the placer notes where it put the module" 1 "$(grep -cx "so $MP/$SO" "$WIRED")"
    case "$WIRES" in
        line) check "$layout: ...and no conf, having written none" 0 "$(grep -c '^conf ' "$WIRED")" ;;
        conf) check "$layout: ...and the conf" 1 "$(grep -cx "conf $MODDIR/$CONF" "$WIRED")" ;;
    esac
    # Alpine includes conf.d outside the http block and http.d inside it.
    check "$layout: http.inc is linked into nginx's http block" there "$(there "$HTTPD/00-unmask.conf")"
    check "$layout: nginx loads the result" ok "$(ngx_t)"

    case "$layout" in
        debian) plugin_prerm remove ;;
        alpine) mkdir -p "$T/lib/apk"; plugin_prerm 0.1.56-r1 ;;
        *)      plugin_prerm 0 ;;
    esac
    check "$layout: the removal ends well" 0 "$RC"
    check "$layout: the module is gone" gone "$(there "$MP/$SO")"
    check "$layout: nothing loads the module any more" no "$(wired)"
    check "$layout: nginx.conf is what it was before the install" same "$(same "$N/nginx.conf" "$T/nginx.conf.orig")"
    check "$layout: no load_module for the module is left anywhere" 0 "$(grep -rl 'load_module.*ngx_http_unmask_module' "$N" "$T/usr/share" 2>/dev/null | grep -vc "^$PLUG/")"
    check "$layout: the note is gone, and its directory with it" gone "$(there "$T/var/lib/unmask/plugin")"
    check "$layout: the removal says what it removed" 1 "$(says "unmask-plugin-nginx: removed $MP/$SO")"
    # http.inc sets the module's directives: the link that loads it goes with
    # the module, and the operator's own includes are named.
    check "$layout: the link that loads http.inc goes with the module" gone "$(there "$HTTPD/00-unmask.conf")"
    check "$layout: the operator's includes are named, file and line" "${SITE#"$T"}:3 ${SITE#"$T"}:5" "$(listed)"
    check "$layout: ...with what to do about them" 1 "$(says 'Remove these lines before the next nginx reload or restart:')"
    check "$layout: nginx -t was run, and its answer printed" 1 "$(says "unmask-plugin-nginx: WARNING -- 'nginx -t' does NOT pass.")"
    check "$layout: ...the error with it" 1 "$(says 'unknown log format "unmask_minimal"')"
    check "$layout: nginx is neither reloaded nor restarted" 0 "$(touched_nginx)"
    plugin_files_gone
    # The operator does as told: nginx loads again, with unmask-web-nginx
    # still installed.
    site_without_includes
    check "$layout: with those lines out, nginx loads" ok "$(ngx_t)"

    # The rest of the uninstall.  The includes were named by the package
    # that took http.inc away; this one has none left to name.
    [ "$layout" = none ] && rm -f "$T/etc/unmask/forward-auth/server.inc" "$T/etc/unmask/forward-auth/protect.inc"
    case "$layout" in
        debian) web_postrm remove ;;
        alpine) web_postrm 0.1.56-r1 ;;
        *)      web_postrm 0 ;;
    esac
    check "$layout: unmask-web-nginx's links are gone" 0 "$(ls "$N/conf.d" "$HTTPD" | grep -cE '^(00|zz)-unmask')"
    check "$layout: unmask-web-nginx says nginx -t passes" 1 "$(says "unmask-web-nginx: 'nginx -t' passes.")"
    check "$layout: ...and that nginx was not reloaded" 1 "$(says 'nginx was NOT reloaded.')"
    check "$layout: ...which is true" 0 "$(touched_nginx)"
    check "$layout: nginx loads without unmask" ok "$(ngx_t)"
    rm -rf "$T"
done

# --- an upgrade removes nothing -------------------------------------------------
new_root rhel
install_all
plugin_prerm 1
check "rpm upgrade: the old package's preremove leaves the module" there "$(there "$MP/$SO")"
check "rpm upgrade: ...and what loads it" "$WIRES" "$(wired)"
check "rpm upgrade: ...and says nothing" "" "$(cat "$T/out")"
plugin_prerm upgrade 0.1.56-1
check "deb upgrade: what loads the module stays" "$WIRES" "$(wired)"
check "deb upgrade: nothing is said" "" "$(cat "$T/out")"
web_postrm 1
check "rpm upgrade: unmask-web-nginx's postremove leaves the links" there "$(there "$HTTPD/00-unmask-upstream.conf")"
# This used to end every upgrade with "snippet removed.  remember to: sudo
# nginx -s reload", of a snippet that was still there.
check "rpm upgrade: ...and says nothing" "" "$(cat "$T/out")"
web_postrm upgrade 0.1.56-1
check "deb upgrade: unmask-web-nginx's postremove says nothing" "" "$(cat "$T/out")"
check "an upgrade never runs nginx -t from the removal scripts" 0 "$(grep -c '^nginx -t' "$T/calls.log")"
rm -rf "$T"

# --- an install whose line is in nginx.conf, on a host that has a directory -----
# Through 0.1.55 the placer's awk program stopped under busybox awk, so on
# Alpine it found no directory and wrote the line into nginx.conf -- although
# Alpine's nginx.conf includes /etc/nginx/modules/*.conf.  It finds the
# directory now.  An install made before must not get a conf beside its line:
# nginx refuses a module loaded twice.  The line stays where it is.
new_root alpine
line_install
web_install
site_with_includes
check "a line in nginx.conf: nginx loads it" ok "$(ngx_t)"
run postinstall-plugin-nginx-fat.sh 2
check "upgrade over a line in nginx.conf: the line stays, and no conf is put beside it" line "$(wired)"
check "upgrade over a line in nginx.conf: nginx.conf is left as it was" same "$(same "$N/nginx.conf" "$T/nginx.conf.line")"
check "upgrade over a line in nginx.conf: the module is loaded once, and nginx loads" ok "$(ngx_t)"
check "upgrade over a line in nginx.conf: it says the line is there" 1 "$(says "load_module already present in $N/nginx.conf (= idempotent skip)")"
check "upgrade over a line in nginx.conf: the note has the module and no conf" "1 0" "$(grep -cx "so $MP/$SO" "$WIRED") $(grep -c '^conf ' "$WIRED")"
# A conf of the package's beside the line, however it got there: one of the
# two has to go, and it is the conf.
echo "load_module \"$MP/$SO\";  $TAG, removed on uninstall" > "$MODDIR/$CONF"
check "a conf beside the line: nginx refuses the module twice" 'module "ngx_http_unmask_module" is already loaded in /etc/nginx/modules/50-mod-unmask.conf:1' "$(ngx_t)"
run postinstall-plugin-nginx-fat.sh 2
check "a conf beside the line: the next run takes the conf away" line "$(wired)"
check "a conf beside the line: nginx loads again" ok "$(ngx_t)"
# The module moved (the modules path, or its home on a read-only /usr): the
# line follows it.
sed "1s|\"$MP/$SO\"|\"$T/var/lib/unmask/plugin/$SO\"|" "$T/nginx.conf.line" > "$N/nginx.conf"
run postinstall-plugin-nginx-fat.sh 2
check "a line naming another path: brought up to date, still one line and no conf" "line 1" "$(wired) $(grep -c "^load_module \"$MP/$SO\";  $TAG" "$N/nginx.conf")"
mkdir -p "$T/lib/apk"; plugin_prerm 0.1.56-r1
check "removal of an install whose line is in nginx.conf: the line goes" same "$(same "$N/nginx.conf" "$T/nginx.conf.orig")"
check "...and the module" gone "$(there "$MP/$SO")"
site_without_includes
check "...and nginx loads" ok "$(ngx_t)"
rm -rf "$T"

# --- an install from before the note: nginx.conf, then the known directories ---
# /etc/nginx/modules was on neither of the two lists the removal used to go by.
new_root alpine
install_all
rm -f "$WIRED"
plugin_prerm 0
check "no note, a conf in /etc/nginx/modules: found" gone "$(there "$MODDIR/$CONF")"
check "no note: the module is gone" gone "$(there "$MP/$SO")"
site_without_includes
check "no note: nginx loads after the removal" ok "$(ngx_t)"
rm -rf "$T"

new_root none
install_all
rm -f "$WIRED"
plugin_prerm 0
check "no note, no include directory: the line the placer tagged is taken out of nginx.conf" same "$(same "$N/nginx.conf" "$T/nginx.conf.orig")"
check "no note: it says so" 1 "$(says "unmask-plugin-nginx: removed the load_module line from $N/nginx.conf")"
rm -rf "$T"

# A directory of the operator's own, on no list: nginx.conf names it.
new_root custom
install_all
check "a directory on no list: the conf is put there" there "$(there "$N/dyn-a/$CONF")"
rm -f "$WIRED"
plugin_prerm 0
check "no note, a directory on no list: found through nginx.conf" gone "$(there "$N/dyn-a/$CONF")"
rm -rf "$T"

# nginx.conf no longer names the directory first (the operator reordered two
# includes): only the note knows where the conf went, and nginx still reads it.
new_root custom
install_all
{ echo "user nginx;"; echo "include $N/dyn-b/*.conf;"; echo "include $N/dyn-a/*.conf;"
  echo "events { }"; echo "http {"; echo "    include $HTTPD/*.conf;"; echo "}"; } > "$N/nginx.conf"
plugin_prerm 0
check "nginx.conf changed since: the conf is found through the note" gone "$(there "$N/dyn-a/$CONF")"
site_without_includes
check "nginx.conf changed since: nginx loads after the removal" ok "$(ngx_t)"
rm -rf "$T"

# No note and nginx.conf no longer names the directory at all: the known ones.
new_root debian
install_all
rm -f "$WIRED"
sed "/modules-enabled/d" "$T/nginx.conf.orig" > "$N/nginx.conf"
plugin_prerm remove
check "no note, nginx.conf changed since: found in the known directories" gone "$(there "$MODDIR/$CONF")"
rm -rf "$T"

# The note is in the unmask user's tree: it is read as a hint, and a path is
# taken only when it ends in one of the package's two file names.
new_root debian
install_all
mkdir -p "$T/elsewhere"
printf 'keep\n' > "$T/victim.conf"; printf 'keep\n' > "$T/victim.so"
printf 'load_module x;\n' > "$T/elsewhere/$CONF"
{ echo "conf $T/victim.conf"; echo "so $T/victim.so"; echo "conf $T/elsewhere/$CONF"; echo "so relative/$SO"; } >> "$WIRED"
plugin_prerm remove
check "a path in the note that is not one of the package's files is left alone" "there there" "$(there "$T/victim.conf") $(there "$T/victim.so")"
check "a conf of the package's name, wherever the note says it is, goes" gone "$(there "$T/elsewhere/$CONF")"
rm -rf "$T"

# The note is rewritten only when it changed (the placer runs before every
# nginx start), and a link planted at its name is replaced, not written through.
new_root rhel
plugin_install
ino=$(inode "$WIRED")
run postinstall-plugin-nginx-fat.sh 2
check "a second run of the placer leaves the note alone" "$ino" "$(inode "$WIRED")"
printf 'keep\n' > "$T/victim"
rm -f "$WIRED"; ln -s "$T/victim" "$WIRED"
run postinstall-plugin-nginx-fat.sh 2
check "a link planted at the note's name is not written through" keep "$(cat "$T/victim")"
check "...it is replaced by the note" "no 1" "$([ -L "$WIRED" ] && echo yes || echo no) $(grep -cx "so $MP/$SO" "$WIRED")"
rm -rf "$T"

# --- only what the package put there goes ---------------------------------------
# A load_module the operator wrote in nginx.conf, naming the modules path (the
# line the documentation once had them add).  The placer leaves it to them, and
# so does the removal -- which takes the file it names.
new_root debian
{ echo "load_module \"$MP/$SO\";"; cat "$T/nginx.conf.orig"; } > "$N/nginx.conf"
cp "$N/nginx.conf" "$T/nginx.conf.operator"
install_all
check "the operator's load_module: the placer adds none of its own" gone "$(there "$MODDIR/$CONF")"
check "the operator's load_module: nginx loads" ok "$(ngx_t)"
plugin_prerm remove
check "the operator's load_module: the module file goes" gone "$(there "$MP/$SO")"
check "the operator's load_module: nginx.conf is not touched" same "$(same "$N/nginx.conf" "$T/nginx.conf.operator")"
check "the operator's load_module: named, file and line" 1 "$(says "    $N/nginx.conf:1: load_module \"$MP/$SO\";")"
check "the operator's load_module: said to be theirs" 1 "$(says 'a load_module for the unmask module that this package did not write')"
check "the operator's load_module: said to name the file that went" 1 "$(says 'It names the module file removed above: nginx does not start until that line is removed too.')"
check "the operator's load_module: nginx -t says the same" 1 "$(says "dlopen() \"$MP/$SO\" failed")"
# No module is left, so http.inc cannot load either: one trap, not two.
check "the operator's load_module: http.inc is unlinked all the same" gone "$(there "$HTTPD/00-unmask.conf")"
check "the operator's load_module: their includes are named" "${SITE#"$T"}:3 ${SITE#"$T"}:5" "$(listed)"
sed '1d' "$T/nginx.conf.operator" > "$N/nginx.conf"; site_without_includes
check "the operator's load_module: with that line and the includes out, nginx loads" ok "$(ngx_t)"
rm -rf "$T"

# A conf of the operator's own, loading a module they built themselves: not
# this package's file, and the module still loads after the removal.
new_root debian
mkdir -p "$T/opt/own"; printf 'OWN-BUILD' > "$T/opt/own/$SO"
echo "load_module $T/opt/own/$SO;" > "$MODDIR/10-own-unmask.conf"
install_all
plugin_prerm remove
check "the operator's own conf: left in place" there "$(there "$MODDIR/10-own-unmask.conf")"
check "the operator's own conf: their module too" there "$(there "$T/opt/own/$SO")"
check "the operator's own conf: the package's copy of the module goes" gone "$(there "$MP/$SO")"
check "the operator's own conf: named" 1 "$(says "    $MODDIR/10-own-unmask.conf:1: load_module $T/opt/own/$SO;")"
check "the operator's own conf: not said to name a file that went" 0 "$(says 'It names the module file removed above')"
check "the operator's own conf: http.inc stays linked, their module loads it" there "$(there "$HTTPD/00-unmask.conf")"
check "the operator's own conf: no line is named for removal" "" "$(listed)"
check "the operator's own conf: nginx -t passes" 1 "$(says "unmask-plugin-nginx: 'nginx -t' passes.")"
rm -rf "$T"

# In nginx.conf, only the line carrying the placer's tag is the package's: a
# commented-out line of the operator's stays, and is not reported.
new_root none
install_all
echo "# load_module modules/$SO;   (the line we had before the package wrote its own)" >> "$N/nginx.conf"
{ cat "$T/nginx.conf.orig"; echo "# load_module modules/$SO;   (the line we had before the package wrote its own)"; } > "$T/nginx.conf.operator"
plugin_prerm 0
check "the tagged line goes, a commented-out load_module of the operator's stays" same "$(same "$N/nginx.conf" "$T/nginx.conf.operator")"
check "...and is not reported as theirs to remove" 0 "$(says 'did not write')"
rm -rf "$T"

# --- the lines named are the ones nginx reads, and the operator's ---------------
new_root debian
install_all
: > "$T/server-includes-protect"; "$T/usr/sbin/unmask" render-nginx
mkdir -p "$N/snippets" "$N/sites-available" "$N/vhosts" "$T/srv/sites"
{ sed '$d' "$N/nginx.conf"                         # everything but the http block's closing brace
  echo "    include vhosts/*.conf;"                 # relative: read against nginx.conf's directory
  echo "    include \"$T/srv/sites/*.conf\" ;"      # quoted, and outside /etc/nginx
  echo "}"; } > "$T/nginx.conf.larger"
cp "$T/nginx.conf.larger" "$N/nginx.conf"
{ echo "server {"; echo "    include $RD/server.inc;"
  echo "    # include $RD/protect.inc;"                              # commented out
  echo "    location / { include snippets/protect.conf; }"           # an include of an include
  echo "}"; } > "$SITE"
echo "include $RD/protect.inc;" > "$N/snippets/protect.conf"
printf 'server {\n\tinclude "%s/server.inc";\n}\n' "$RD" > "$N/vhosts/b.conf"
echo "server { include $RD/server.inc; }" > "$T/srv/sites/c.conf"
echo "server { include $RD/server.inc; }" > "$N/sites-available/disabled"     # nginx never reads it
echo "server { include $RD/server.inc; }" > "$HTTPD/site.conf.bak"            # nor this
check "a larger configuration loads" ok "$(ngx_t)"
plugin_prerm remove
check "named: what nginx reads, wherever it is -- and nothing else" \
      "/etc/nginx/conf.d/site.conf:2 /etc/nginx/snippets/protect.conf:1 /etc/nginx/vhosts/b.conf:2 /srv/sites/c.conf:1" "$(listed)"
check "not named: unmask's own server.inc, which includes protect.inc" 0 "$(grep -c "^    $RD/" "$T/out")"
rm -rf "$T"

# An include of http.inc the operator wrote by hand (the unmask package's
# install output offers it as the alternative to unmask-web-nginx) loads the
# module's directives just as the link does, and is named with the others.
new_root rhel
plugin_install
rm -f "$HTTPD/00-unmask.conf"
{ echo "upstream unmask_daemon { server 127.0.0.1:9477; }"; echo "include $RD/http.inc;"; } > "$HTTPD/00-by-hand.conf"
site_with_includes
check "an include of http.inc by hand loads" ok "$(ngx_t)"
plugin_prerm 0
check "an include of http.inc by hand is named" "/etc/nginx/conf.d/00-by-hand.conf:2 ${SITE#"$T"}:3 ${SITE#"$T"}:5" "$(listed)"
rm -rf "$T"

# --- whichever package goes first names the includes, once ----------------------
# unmask-web-nginx first: it takes the links out of nginx's http block, names
# the includes, and unmask-plugin-nginx after it has none to name again.
new_root rhel
install_all
rm -f "$T/etc/unmask/forward-auth/server.inc" "$T/etc/unmask/forward-auth/protect.inc"     # rpm removed them
web_postrm 0
check "web-nginx first: it names the operator's includes" "${SITE#"$T"}:3 ${SITE#"$T"}:5" "$(listed)"
check "web-nginx first: under its own name" 1 "$(says 'unmask-web-nginx: your nginx configuration still includes files that nginx cannot read without this package.')"
check "web-nginx first: nginx -t does not pass, and it says so" 1 "$(says "unmask-web-nginx: WARNING -- 'nginx -t' does NOT pass.")"
check "web-nginx first: no word about reloading a configuration that does not load" 0 "$(says 'Apply when you choose')"
plugin_prerm 0
check "then the plugin: the module and its conf go" "gone gone" "$(there "$MP/$SO") $(there "$MODDIR/$CONF")"
check "then the plugin: the includes are not named a second time" "" "$(listed)"
check "then the plugin: nginx -t still does not pass, and it says so" 1 "$(says "unmask-plugin-nginx: WARNING -- 'nginx -t' does NOT pass.")"
check "then the plugin: no word about a restart that would fail" 0 "$(says 'Restart it when you choose')"
site_without_includes
check "with the includes out, nginx loads" ok "$(ngx_t)"
rm -rf "$T"

# The plugin first, and everything in order: it says so and names the restart.
new_root debian
install_all
site_without_includes
plugin_prerm remove
check "nothing left behind: nginx -t passes" 1 "$(says "unmask-plugin-nginx: 'nginx -t' passes.")"
check "nothing left behind: the restart is the operator's, and named" 1 "$(says 'sudo systemctl restart nginx')"
check "nothing left behind: no line is named for removal" 0 "$(says 'Remove these lines')"
# dpkg calls the postremove for the remove and again for the purge.
web_postrm remove
check "deb remove: unmask-web-nginx reports" 1 "$(says "unmask-web-nginx: 'nginx -t' passes.")"
web_postrm purge
check "deb purge after it: nothing is said twice" "" "$(cat "$T/out")"
rm -rf "$T"

# The forward-auth snippets are unmask-web-nginx's: it names an include of
# them whether or not the module was ever there, and the plugin never does.
new_root debian
web_install
{ echo "server {"; echo "    include $T/etc/unmask/forward-auth/server.inc;"
  echo "    location / { include $T/etc/unmask/forward-auth/protect.inc; }"; echo "}"; } > "$SITE"
check "forward-auth: the configuration loads" ok "$(ngx_t)"
web_postrm remove
check "forward-auth: the includes are named" "${SITE#"$T"}:2 ${SITE#"$T"}:3" "$(listed)"
check "forward-auth: nginx -t does not pass, and it says so" 1 "$(says "unmask-web-nginx: WARNING -- 'nginx -t' does NOT pass.")"
rm -rf "$T"

# --- the fail-safe takes the module out by the same function --------------------
# A render nginx cannot load: place-module.sh strips the module, and unmask
# renders a configuration that loads without it.  /etc/nginx/modules was not on
# the fail-safe's list either.
new_root alpine
install_all
: > "$T/render-broken"; "$T/usr/sbin/unmask" render-nginx
check "a render nginx cannot load" 'unknown directive "unmask_from_the_future" in /etc/nginx/http.d/00-unmask.conf:3' "$(ngx_t)"
PATH="$T/stub:$T/tools" "$SH" "$PLUG/place-module.sh" --verify > "$T/out" 2>&1
check "fail-safe: the conf is taken out of /etc/nginx/modules" gone "$(there "$MODDIR/$CONF")"
check "fail-safe: the module is taken out" gone "$(there "$MP/$SO")"
check "fail-safe: the note goes with them" gone "$(there "$WIRED")"
check "fail-safe: nginx loads the configuration rendered without the module" ok "$(ngx_t)"
# Removing the package in that state breaks nothing: the http.inc that is
# linked now names none of the module's directives, so it stays, and no line
# is named.
mkdir -p "$T/lib/apk"; plugin_prerm 0.1.56-r1
check "removal under the fail-safe: http.inc stays linked" there "$(there "$HTTPD/00-unmask.conf")"
check "removal under the fail-safe: no line is named" "" "$(listed)"
check "removal under the fail-safe: nginx -t passes" 1 "$(says "unmask-plugin-nginx: 'nginx -t' passes.")"
check "removal under the fail-safe: no restart is asked for, nothing was removed" 0 "$(says 'Restart it when you choose')"
rm -rf "$T"

# The fail-safe runs with nobody at the console, ahead of an nginx start: a
# load_module line in nginx.conf goes whoever wrote it, as before.
new_root debian
{ echo "load_module \"$MP/$SO\";"; cat "$T/nginx.conf.orig"; } > "$N/nginx.conf"
install_all
: > "$T/render-broken"; "$T/usr/sbin/unmask" render-nginx
PATH="$T/stub:$T/tools" "$SH" "$PLUG/place-module.sh" --verify > "$T/out" 2>&1
check "fail-safe: an operator's load_module line in nginx.conf is taken out, so that nginx starts" same "$(same "$N/nginx.conf" "$T/nginx.conf.orig")"
check "fail-safe: nginx loads" ok "$(ngx_t)"
rm -rf "$T"

# --- the single-nginx variant: no placer on disk, the same preremove -----------
new_root alpine
plugin_install_single
web_install
site_with_includes
check "single-nginx variant: the conf is put where nginx.conf loads modules from" there "$(there "$MODDIR/$CONF")"
check "single-nginx variant: it keeps the same note" "1 1" "$(grep -cx "so $MP/$SO" "$WIRED") $(grep -cx "conf $MODDIR/$CONF" "$WIRED")"
check "single-nginx variant: nginx loads" ok "$(ngx_t)"
check "single-nginx variant: there is no placer to call" gone "$(there "$PLUG/place-module.sh")"
mkdir -p "$T/lib/apk"; plugin_prerm 0.1.56-r1
check "single-nginx variant: the conf goes" gone "$(there "$MODDIR/$CONF")"
check "single-nginx variant: the module goes" gone "$(there "$MP/$SO")"
check "single-nginx variant: the includes are named" "${SITE#"$T"}:3 ${SITE#"$T"}:5" "$(listed)"
rm -rf "$T"

# Over a line the bundle variant once wrote into nginx.conf: it adds no conf
# beside it, and its removal takes the line.
new_root alpine
line_install
plugin_files_gone
plugin_install_single
web_install
check "single-nginx variant over a line in nginx.conf: no conf beside it" line "$(wired)"
check "single-nginx variant over a line in nginx.conf: nginx loads" ok "$(ngx_t)"
mkdir -p "$T/lib/apk"; plugin_prerm 0.1.56-r1
check "single-nginx variant over a line in nginx.conf: the removal takes the line" same "$(same "$N/nginx.conf" "$T/nginx.conf.orig")"
rm -rf "$T"

# --- nginx already removed, and a second run -----------------------------------
# Without nginx the preremove used to stop before removing anything, and the
# conf waited for the next nginx to fail on it.
new_root debian
install_all
rm -f "$T/stub/nginx"
plugin_prerm remove
check "nginx no longer installed: what loaded the module goes all the same" no "$(wired)"
check "nginx no longer installed: the module too (the note has its path)" gone "$(there "$MP/$SO")"
check "nginx no longer installed: the removal ends well" 0 "$RC"
plugin_prerm remove
check "a second run finds nothing to remove" 0 "$(says 'removed')"
check "a second run ends well" 0 "$RC"
rm -rf "$T"

# --- one implementation, in the files that need it ------------------------------
# A package script runs alone, so what two of them share is carried by both;
# these fail when the copies drift apart.
block() { sed -n "/^# >>> $2 >>>\$/,/^# <<< $2 <<<\$/p" "$DIR/$1"; }
for pair in "unwire place-module.sh preremove-plugin-nginx.sh" "leftover preremove-plugin-nginx.sh postremove-web-nginx.sh"; do
    set -- $pair
    a=$(block "$2" "$1"); b=$(block "$3" "$1")
    if [ -n "$a" ] && [ "$(printf '%s\n' "$a" | wc -l)" -gt 20 ]; then pass "the $1 block is there in $2"; else fail "the $1 block is there in $2"; fi
    if [ "$a" = "$b" ]; then pass "the $1 block is the same in $2 and $3"
    else fail "the $1 block is the same in $2 and $3 (copy it from one to the other)"; fi
done
# The single-nginx postinstall writes the note the shared block reads, and the
# conf under the name it removes.
state=$(sed -n 's/^WIRED_STATE=//p' "$DIR/place-module.sh")
check "the single-nginx postinstall keeps its note where the removal reads it" "$state" "$(sed -n 's/^WIRED_STATE=//p' "$DIR/postinstall-plugin-nginx.sh")"
conf=$(sed -n 's/^LOAD_CONF=//p' "$DIR/place-module.sh")
check "the single-nginx postinstall names its conf as the removal does" 1 "$(grep -c "DROP=\"\$INCLUDE_DIR/$conf\"" "$DIR/postinstall-plugin-nginx.sh")"

echo
if [ "$fails" -gt 0 ]; then
    echo "uninstall_test: $fails FAILED"
    exit 1
fi
echo "uninstall_test: all passed"
