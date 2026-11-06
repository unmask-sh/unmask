#!/bin/sh
# preremove for unmask-plugin-nginx (both variants: the bundle with a module
# per nginx version, and the single-nginx one).
#
# Takes away what the postinstall put into nginx -- the module file and the
# load_module that names it -- from where it was put, and then says what is
# left for the operator: a load_module of their own, the lines of their
# server blocks that include unmask's files, and whether nginx still loads
# its configuration.  nginx itself is neither reloaded nor restarted from
# here.  Skipped on upgrade ($1=1) (= the new version overwrites the same path).

# Only on a genuine removal.  rpm: $1="0"; dpkg: $1="remove".  apk passes the
# package version string as $1, and nfpm wires this as apk's pre-deinstall hook
# (= uninstall-only by spec, upgrades use a separate pre-upgrade hook), so on
# Alpine this is always a removal -- detect it via /lib/apk (= same idiom as
# postremove.sh).  Without this, `apk del unmask-plugin-nginx` would leave the
# .so and the load_module .conf behind.
do_remove=0
if [ -d /lib/apk ]; then
    do_remove=1
else
    case "${1:-0}" in
        0|remove) do_remove=1 ;;
    esac
fi
[ "$do_remove" = 1 ] || exit 0

SO_NAME=ngx_http_unmask_module.so
# The module's home on a host whose /usr is read-only (see place-module.sh).
FALLBACK_SO_DIR=/var/lib/unmask/plugin
NGINX_CONF=/etc/nginx/nginx.conf

# >>> unwire >>>
# Taking the module out of nginx again: the load_module wiring and the .so.
#
# The lines between the two markers are the same, byte for byte, in
# place-module.sh (the fail-safe, which strips the module so that nginx still
# starts) and in preremove-plugin-nginx.sh (the package's removal);
# uninstall_test.sh fails when they differ.  A copy in each rather than a call
# from one to the other: the single-nginx variant of the plugin shares the
# preremove and ships no place-module.sh, and the fail-safe runs before every
# nginx start, where it must not depend on a second file being there.
#
# The two used to carry a list of directories each, and the lists disagreed.
# The directory is not theirs to list: nginx.conf decides it (an include of
# /etc/nginx/modules/*.conf, or of a directory of the operator's own, names
# one that was on neither), and a 50-mod-unmask.conf left behind names a .so
# that is gone -- nginx then dies on dlopen() at its next start.  So removal
# goes by where the conf was PUT, and looks in all of:
#   - the path the placer noted when it put the conf there ($WIRED_STATE);
#   - the directory nginx.conf names now, found the way the placer finds it
#     (main_include_dir);
#   - the directories the distributions use ($LOAD_CONF_DIRS): an install from
#     before the note, whose nginx.conf has changed since.
WIRED_STATE=/var/lib/unmask/plugin/.wired
LOAD_CONF=50-mod-unmask.conf
LOAD_CONF_DIRS="/etc/nginx/modules-enabled /etc/nginx/modules.d /etc/nginx/modules-available /etc/nginx/modules /usr/share/nginx/modules"
# The comment the placer puts on a load_module line it adds to nginx.conf
# itself (a host with no include directory): what tells that line from one
# the operator wrote.
LOAD_TAG="# unmask-plugin-nginx: auto-added"

# main_include_dir: the directory of the first absolute-path include ahead of
# nginx.conf's http block -- where the distribution's nginx.conf loads its
# modules from (modules-enabled/, /usr/share/nginx/modules/, modules/).
# Nothing when nginx.conf has no such include.
#
# Spelled for every awk the packages meet.  busybox's (Alpine) takes a bare
# "{" in a regex for an interval and ends a regex at a "/" inside brackets:
# through 0.1.55 it stopped on this program ("bad regex"), no directory was
# found on Alpine, and the line went into nginx.conf instead -- on the one
# distribution whose nginx.conf includes /etc/nginx/modules/*.conf.
main_include_dir() {
    [ -r "$NGINX_CONF" ] || return 0
    awk '
        /^[[:space:]]*http[[:space:]]*[{]/ { exit }
        /^[[:space:]]*include[[:space:]]/ {
            for (i = 1; i <= NF; i++) {
                if (substr($i, 1, 1) == "/") { print $i; exit }
            }
        }
    ' "$NGINX_CONF" | sed 's|/\*\.conf;$||; s|;$||' | head -1
}

# _uw_rm <path>: remove one file the package put there and, on a removal, say so.
_uw_rm() {
    [ -f "$1" ] || [ -L "$1" ] || return 0
    if rm -f "$1" 2>/dev/null; then
        UNWIRE_REMOVED=1
        [ "$_uw_mode" = remove ] && echo "unmask-plugin-nginx: removed $1"
    elif [ "$_uw_mode" = remove ]; then
        echo "unmask-plugin-nginx: WARNING -- could not remove $1 -- remove it by hand." >&2
    fi
    return 0
}

# unwire_module <strip|remove>: take the load_module wiring and the .so away.
#
#   strip   the fail-safe.  Says nothing (its caller does).  A load_module
#           line in nginx.conf goes whoever wrote it, as it always has: this
#           runs with nobody at the console, ahead of an nginx start that the
#           line would stop.
#   remove  the package's removal.  Says what it removed.  Only what the
#           package put there goes: a load_module the operator wrote is
#           theirs, so it stays and is handed back in $UNWIRE_FOREIGN
#           ("file:line:text" lines) for the caller to name -- this time the
#           operator is reading.
#
# $UNWIRE_REMOVED is 1 when anything was removed.
unwire_module() {
    _uw_mode=$1
    UNWIRE_FOREIGN=""
    UNWIRE_REMOVED=0

    # What the placer noted.  The note lives in the unmask user's tree, so it
    # is read as a hint and no more: a path is taken only when it ends in one
    # of the two names this package gives its files.
    if [ -r "$WIRED_STATE" ]; then
        while read -r _uw_k _uw_p; do
            case "$_uw_k:$_uw_p" in
                conf:/*/"$LOAD_CONF"|so:/*/"$SO_NAME") _uw_rm "$_uw_p" ;;
            esac
        done < "$WIRED_STATE"
    fi

    # The directory nginx.conf names now, then the known ones.
    _uw_dir=$(main_include_dir)
    [ -n "$_uw_dir" ] && _uw_rm "$_uw_dir/$LOAD_CONF"
    for _uw_d in $LOAD_CONF_DIRS; do
        _uw_rm "$_uw_d/$LOAD_CONF"
    done

    # The .so: nginx's modules path, and the home it gets on a read-only /usr.
    _uw_mp=""
    if command -v nginx >/dev/null 2>&1; then
        _uw_mp=$(nginx -V 2>&1 | tr ' ' '\n' | sed -n 's|^--modules-path=||p' | head -1)
    fi
    [ -n "$_uw_mp" ] && _uw_rm "$_uw_mp/$SO_NAME"
    _uw_rm "$FALLBACK_SO_DIR/$SO_NAME"

    # The line in nginx.conf itself.  Built beside it and renamed into place,
    # so that nginx.conf is never half-written; the copy first keeps its mode
    # and owner.
    _uw_re='load_module.*ngx_http_unmask_module'
    [ "$_uw_mode" = remove ] && _uw_re="$_uw_re.*$LOAD_TAG"
    if [ -w "$NGINX_CONF" ] && grep -q "$_uw_re" "$NGINX_CONF" 2>/dev/null; then
        _uw_t="$NGINX_CONF.unmask-unwire.$$"
        if cp -p "$NGINX_CONF" "$_uw_t" 2>/dev/null &&
           sed "/$_uw_re/d" "$NGINX_CONF" > "$_uw_t" 2>/dev/null &&
           mv -f "$_uw_t" "$NGINX_CONF" 2>/dev/null; then
            UNWIRE_REMOVED=1
            [ "$_uw_mode" = remove ] && echo "unmask-plugin-nginx: removed the load_module line from $NGINX_CONF"
        else
            rm -f "$_uw_t" 2>/dev/null
        fi
    fi

    # What is still there after that is not this package's: name it.
    if [ "$_uw_mode" = remove ]; then
        UNWIRE_FOREIGN=$(
            {
                [ -r "$NGINX_CONF" ] && grep -n 'load_module.*ngx_http_unmask_module' "$NGINX_CONF" /dev/null
                for _uw_d in "$_uw_dir" $LOAD_CONF_DIRS; do
                    [ -d "$_uw_d" ] || continue
                    for _uw_f in "$_uw_d"/*.conf; do
                        [ -f "$_uw_f" ] && grep -n 'load_module.*ngx_http_unmask_module' "$_uw_f" /dev/null
                    done
                done
            } 2>/dev/null | grep -v '^[^:]*:[0-9]*:[[:space:]]*#' | sort -u
        )
    fi

    rm -f "$WIRED_STATE" 2>/dev/null
    [ "$_uw_mode" = remove ] && rmdir "$FALLBACK_SO_DIR" 2>/dev/null
    return 0
}
# <<< unwire <<<

# >>> leftover >>>
# What a removal leaves for the operator: the lines of their own configuration
# that include unmask's files, and whether nginx still loads the whole.
#
# The lines between the two markers are the same, byte for byte, in
# preremove-plugin-nginx.sh and postremove-web-nginx.sh (uninstall_test.sh
# fails when they differ).  A copy in each: a package script runs alone, and
# the other package -- with every file it shipped -- may be gone by then.

# nginx_conf_files: what nginx reads -- nginx.conf and the files it includes,
# includes of includes too -- one path per line (a file reached twice is
# listed twice).  A relative include is read against nginx.conf's directory,
# as nginx reads it, and a mask is expanded by the shell.  Only these count:
# a line in a file nginx never includes (a disabled site, an editor's backup)
# stops nothing.  Each level is read in one pass (comments dropped, one
# directive per line), so a host with thousands of sites costs a handful of
# processes, not a handful per site.
nginx_conf_files() {
    [ -r "$NGINX_CONF" ] || return 0
    _cf_ifs=$IFS
    IFS='
'
    set -f
    _cf_level=$NGINX_CONF
    _cf_depth=0
    # Eight levels: an include that leads back to itself ends here.
    while [ -n "$_cf_level" ] && [ "$_cf_depth" -lt 8 ]; do
        printf '%s\n' "$_cf_level"
        _cf_next=""
        for _cf_p in $(sed 's/#.*//' $_cf_level 2>/dev/null | tr '{};' '\n\n\n' |
                       sed -n 's/^[[:space:]]*include[[:space:]]\{1,\}\(.*[^[:space:]]\)[[:space:]]*$/\1/p' | tr -d "\"'"); do
            case "$_cf_p" in
                /*) ;;
                *) _cf_p="${NGINX_CONF%/*}/$_cf_p" ;;
            esac
            set +f
            for _cf_m in $_cf_p; do
                [ -f "$_cf_m" ] && _cf_next="$_cf_next
$_cf_m"
            done
            set -f
        done
        _cf_level=$(printf '%s\n' "$_cf_next" | sed '/^$/d' | sort -u)
        _cf_depth=$((_cf_depth + 1))
    done
    set +f
    IFS=$_cf_ifs
}

# unmask_include_lines <ERE>: the lines, in what nginx reads, that include a
# file whose path matches the ERE -- "    file:line: text", ready to print.
# unmask's own files are left out: they include each other (server.inc may
# include protect.inc), and those are not lines for the operator to edit.
unmask_include_lines() {
    _il_files=$(nginx_conf_files | sort -u | grep -v -e '^/var/lib/unmask/' -e '^/etc/unmask/')
    [ -n "$_il_files" ] || return 0
    _il_ifs=$IFS
    IFS='
'
    set -f
    grep -nE "^([^#]*[[:space:];{}])?include[[:space:]]+[\"']?($1)[\"']?[[:space:]]*;" /dev/null $_il_files 2>/dev/null |
        sed 's/^\([^:]*:[0-9]*:\)[[:space:]]*/    \1 /'
    set +f
    IFS=$_il_ifs
}

# nginx_t_report <package>: run nginx -t and say what it answered; 0 when it
# passes.  nginx itself is left alone, neither reloaded nor restarted.
nginx_t_report() {
    # Alpine keeps nginx's pid file in /run/nginx, a directory its service
    # makes when it starts; without it nginx -t fails on a valid configuration.
    [ -d /run/nginx ] || mkdir -p /run/nginx 2>/dev/null || true
    if _nt_out=$(nginx -t 2>&1); then
        echo "$1: 'nginx -t' passes."
        return 0
    fi
    echo "$1: WARNING -- 'nginx -t' does NOT pass.  nginx was not touched: it keeps running on the"
    echo "  configuration it has loaded, and a reload or restart fails until this is fixed:"
    printf '%s\n' "$_nt_out" | sed 's/^/    /'
    return 1
}
# <<< leftover <<<

# ---- 1. the module and its load_module ----
# Whether or not nginx is still installed: this used to stop right here
# without it, and left the conf for the next nginx to fail on.
unwire_module remove

# A load_module the operator wrote themselves is theirs to remove.  Whether it
# still loads anything is nginx's to say: a dlopen() failure on the module's
# name means it named the file removed above (the usual case -- a line added
# by hand, pointing at the modules path), and then no module is left.
MODULE_GONE=1
if [ -n "$UNWIRE_FOREIGN" ]; then
    MODULE_GONE=0
    if command -v nginx >/dev/null 2>&1 && ! FOREIGN_T=$(nginx -t 2>&1); then
        case "$FOREIGN_T" in
            *"dlopen()"*ngx_http_unmask_module*) MODULE_GONE=1 ;;
        esac
    fi
    echo "unmask-plugin-nginx: left as it is -- a load_module for the unmask module that this package did not write:"
    printf '%s\n' "$UNWIRE_FOREIGN" | sed 's/^\([^:]*:[0-9]*:\)[[:space:]]*/    \1 /'
    if [ "$MODULE_GONE" = 1 ]; then
        echo "  It names the module file removed above: nginx does not start until that line is removed too."
    fi
fi

# The include for rendered.conf that early versions of this package dropped.
if [ -f /etc/nginx/conf.d/10-unmask-rendered.conf ]; then
    rm -f /etc/nginx/conf.d/10-unmask-rendered.conf
    echo "unmask-plugin-nginx: removed /etc/nginx/conf.d/10-unmask-rendered.conf"
fi

# ---- 2. http.inc, and the operator's own includes ----
# http.inc as rendered for the module sets the module's directives
# (unmask_bv_secret and the rest), and nginx stops at the first of them once
# the module is gone.  So the link that loads it -- 00-unmask.conf, which this
# package and unmask-web-nginx both create -- goes with the module: the rule
# unmask-web-nginx's postinstall applies from its side (no .so, no link).  It
# stays when http.inc is the one rendered without the module (the
# fail-safe's): that one names none of those directives, and what includes it
# still loads.  And it stays while a module of the operator's own loads.
#
# Whichever package takes that link away -- this one, or unmask-web-nginx
# when it is removed first -- is the one whose removal stops the operator's
# includes of server.inc / protect.inc from loading, and the one that names
# them.  The other finds no link and says nothing about them, so each line is
# listed once, whichever order the packages go in.
HTTP_INC=/var/lib/unmask/nginx/http.inc
if [ "$MODULE_GONE" = 1 ] && grep -q '^[[:space:]]*unmask_bv_secret[[:space:]]' "$HTTP_INC" 2>/dev/null; then
    HTTP_INC_WAS_LOADED=0
    for link in /etc/nginx/conf.d/00-unmask.conf /etc/nginx/http.d/00-unmask.conf; do
        if [ -L "$link" ] && [ "$(readlink "$link")" = "$HTTP_INC" ]; then
            rm -f "$link"
            echo "unmask-plugin-nginx: removed $link (it loaded http.inc, which nginx cannot read without the module)"
            HTTP_INC_WAS_LOADED=1
        fi
    done
    LEFT=$(unmask_include_lines '/var/lib/unmask/nginx/(http|server|protect)[.]inc')
    # An include of http.inc written by hand loaded it just as the link did.
    case "$LEFT" in
        */var/lib/unmask/nginx/http.inc*) HTTP_INC_WAS_LOADED=1 ;;
    esac
    if [ "$HTTP_INC_WAS_LOADED" = 1 ] && [ -n "$LEFT" ]; then
        echo "unmask-plugin-nginx: your nginx configuration still includes files that nginx cannot read without the module."
        echo "  Remove these lines before the next nginx reload or restart:"
        printf '%s\n' "$LEFT"
    fi
fi

# ---- 3. does nginx still load its configuration? ----
if command -v nginx >/dev/null 2>&1; then
    if nginx_t_report unmask-plugin-nginx && [ "$UNWIRE_REMOVED" = 1 ] && [ "$MODULE_GONE" = 1 ]; then
        echo "  → nginx was NOT restarted.  Restart it when you choose, to run without the module:"
        echo "    sudo systemctl restart nginx   (or: sudo service nginx restart)"
    fi
fi

exit 0
