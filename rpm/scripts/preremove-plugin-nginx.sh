#!/bin/sh
# preremove for unmask-plugin-nginx (both variants: the bundle with a module
# per nginx version, and the single-nginx one).
#
# Takes away what the postinstall put into nginx -- the module file and the
# load_module that names it -- from where it was put, and names a load_module
# of the operator's own, which it leaves.  Skipped on upgrade ($1=1) (= the
# new version overwrites the same path).

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
main_include_dir() {
    [ -r "$NGINX_CONF" ] || return 0
    awk '
        /^[[:space:]]*http[[:space:]]*{/ { exit }
        /^[[:space:]]*include[[:space:]]/ {
            for (i = 1; i <= NF; i++) {
                if ($i ~ /^[/]/) { print $i; exit }
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

echo "unmask-plugin-nginx: removal complete.  run 'nginx -t && systemctl reload nginx' to apply."

exit 0
