#!/bin/sh
# place-module.sh -- pick + place the unmask nginx native module for the host
# nginx.  Shipped on-disk at /usr/share/unmask/plugin/place-module.sh and run by
# BOTH the unmask-plugin-nginx postinstall AND the nginx.service ExecStartPre
# drop-in (10-unmask-repick.conf).  Running it before every nginx start is what
# closes the host-nginx-upgrade .so orphan: when the host upgrades nginx, the
# matching bundled .so is re-picked -- or, if none matches the new version, the
# wiring is fail-safe-stripped (disable_unmask_module) so nginx still starts
# WITHOUT the module instead of dying on an ABI-incompatible load_module.
# Idempotent.  Exits 0 when a module is in place for the host's nginx once it
# returns (placed now, or already there unchanged) and 1 when none is: no
# nginx to place one for, no bundled module for its version, a modules path
# that cannot be written, musl without gcompat.  The systemd drop-in prefixes
# the call with '-', so that 1 never blocks an nginx start; it is for the
# plugin postinstall, which then says that nothing was placed instead of
# "module placed", and for whoever reads the journal.  `--verify` exits 0.
#
# Only systemd hosts get the automatic per-start re-pick (via the drop-in).
# Non-systemd hosts (Alpine OpenRC -- which ships no nginx service at all -- and
# SysV) have no equivalent hook, so after upgrading the host nginx, re-run this
# script manually, or call it from the nginx service's pre-start (OpenRC
# start_pre) so every start re-picks.  The plugin postinstall prints the same
# reminder on non-systemd installs.
#
# Flow:
#   1. Get the host nginx version (= X.Y.Z) from `nginx -v`.
#   2. Look up the host nginx's libcrypto dependency to determine the
#      OpenSSL ABI (= 1.1 or 3).
#   3. Find /usr/share/unmask/plugin/{openssl10,openssl11,openssl3,glibc212}/ngx_http_unmask_module-X.Y.Z.so
#      built for exactly the host's version (= host 1.18.0 -> -1.18.0.so under
#      the matching ABI dir).  nginx loads no other: a module built for a
#      neighbouring patch release of the same branch is refused at start.
#      None -> say which version is missing and the ways out, then
#      disable_unmask_module (= strip the module, re-render the configuration
#      without it so nginx still starts) + exit 1.
#   4. Extract --modules-path= from `nginx -V`.
#   5. Copy the chosen .so to $modules_path/ngx_http_unmask_module.so —
#      or, when the modules path is unwritable (immutable /usr, ostree-style
#      distros), to /var/lib/unmask/plugin/ and point load_module there.
#   6. restorecon if selinux is in use.
#   7. Place the load_module line, and note where it and the .so went
#      (wired_record): the fail-safe and the package's removal take them away
#      from there (unwire_module).
#
# Arguments:
#   (none)            the run above: pick, place, check.
#   --verify          only the check at the end (the web-nginx postinstall).
#   --nginx-changed   the binary of an nginx built from source changed or
#                     went: take the module out and render the include files
#                     with nothing in them (see go_inert).  Run by the watch,
#                     unmask-nginx-binary.path.

PLUGIN_BASE=/usr/share/unmask/plugin
SO_NAME=ngx_http_unmask_module.so

# >>> nginx-layout >>>
# Whose nginx this is, and where unmask's part of its configuration lives.
#
# A distribution's nginx reads /etc/nginx/nginx.conf, and that file includes
# directories a package may put a file into: the packages wire unmask in
# there.  An nginx built from source -- by hand under /usr/local/nginx, by a
# hosting panel under a prefix of its own -- keeps its nginx.conf elsewhere,
# says nothing about directories, and the file is its builder's (a panel
# writes it again when it pleases).  The packages edit nothing of such an
# nginx.  They keep directories of their own, root's, and the operator
# includes two of them, once:
#
#     include /usr/share/unmask/nginx/modules-enabled/*.conf;    the first line of nginx.conf
#     include /usr/share/unmask/nginx/conf.d/*.conf;             the first line inside http { }
#
# (The first line inside http { }: ahead of every server block and of every
# include that brings the sites in.  A server that includes unmask's
# server.inc names a log format the http directory defines, and nginx wants
# the definition first.)
#
# Wildcard includes, which nginx accepts with nothing behind them: the module
# can be taken out again (the fail-safe) and the packages removed with the two
# lines still there, and nginx starts.  The module file is kept beside them
# ($OWN_SO_DIR), not under the prefix of that nginx.
#
# The lines between the two markers are the same, byte for byte, in every
# script that carries them; nginx-layout_test.sh fails when they differ.
OWN_NGINX_DIR=/usr/share/unmask/nginx
OWN_MAIN_DIR=$OWN_NGINX_DIR/modules-enabled
OWN_HTTP_DIR=$OWN_NGINX_DIR/conf.d
OWN_SO_DIR=$OWN_NGINX_DIR/modules
PACKAGED_NGINX_CONF=/etc/nginx/nginx.conf

# What a test overrides: `nginx -V`, and the configuration as nginx reads it
# (every included file; nothing when the configuration does not load).
_nl_nginx_v() { nginx -V 2>&1; }
_nl_nginx_dump() { nginx -T 2>/dev/null; }

# nginx_conf_path: the main configuration file of the nginx on PATH, as that
# nginx was built: --conf-path, or conf/nginx.conf under --prefix, or under
# nginx's own default prefix.  The distributions' path when there is no nginx
# to ask, or none that answers like one.
nginx_conf_path() {
    command -v nginx >/dev/null 2>&1 || { echo "$PACKAGED_NGINX_CONF"; return 0; }
    _nl_v=$(_nl_nginx_v)
    case "$_nl_v" in
        *"configure arguments:"*) ;;
        *) echo "$PACKAGED_NGINX_CONF"; return 0 ;;
    esac
    _nl_args=$(printf '%s\n' "$_nl_v" | tr ' ' '\n')
    _nl_conf=$(printf '%s\n' "$_nl_args" | sed -n 's|^--conf-path=||p' | head -1)
    _nl_prefix=$(printf '%s\n' "$_nl_args" | sed -n 's|^--prefix=||p' | head -1)
    [ -n "$_nl_prefix" ] || _nl_prefix=/usr/local/nginx
    case "$_nl_conf" in
        /*) echo "$_nl_conf" ;;
        "") echo "$_nl_prefix/conf/nginx.conf" ;;
        *)  echo "$_nl_prefix/$_nl_conf" ;;
    esac
}

# nginx_is_packaged: 0 when that file is the one the distributions use.
nginx_is_packaged() { [ "$(nginx_conf_path)" = "$PACKAGED_NGINX_CONF" ]; }

# own_includes_missing: which of the two include lines the configuration of
# a self-built nginx does not carry -- "main", "http", both (one per line) or
# nothing.  Read from the configuration as nginx reads it, so that a line in
# an included file counts; from the main file alone when that cannot be had.
own_includes_missing() {
    _nl_cfg=$(_nl_nginx_dump)
    [ -n "$_nl_cfg" ] || _nl_cfg=$(cat "$(nginx_conf_path)" 2>/dev/null)
    for _nl_k in main http; do
        case $_nl_k in
            main) _nl_d=$OWN_MAIN_DIR ;;
            *)    _nl_d=$OWN_HTTP_DIR ;;
        esac
        # grep reads to the end (no -q).  One that stops at the first match
        # leaves sed and printf writing into a closed pipe, and where SIGPIPE
        # is ignored -- a systemd service, which is where this runs before
        # every nginx start -- each of them says so in the journal.
        printf '%s\n' "$_nl_cfg" | sed 's/#.*//' |
            grep -E "(^|[[:space:];{}])include[[:space:]]+[\"']?$_nl_d/[*][.]conf[\"']?[[:space:]]*;" >/dev/null ||
            echo "$_nl_k"
    done
}

# own_includes_say <package>: name the include lines still to be added and the
# file they go into.  Says nothing once both are there.
own_includes_say() {
    _nl_miss=" $(own_includes_missing | tr '\n' ' ')"
    [ "$_nl_miss" = " " ] && return 0
    echo ""
    echo "$1: this nginx was not installed from a package, so nothing of its"
    echo "  configuration is edited.  Add to $(nginx_conf_path), once:"
    case "$_nl_miss" in *" main "*)
        echo ""
        echo "      include $OWN_MAIN_DIR/*.conf;     <- as the first line of the file"
        ;;
    esac
    case "$_nl_miss" in *" http "*)
        echo ""
        echo "      include $OWN_HTTP_DIR/*.conf;     <- as the first line inside http { }"
        ;;
    esac
    echo ""
    echo "  then  nginx -t  and restart nginx (a reload does not load a module)."
    echo "  Both lines can stay when unmask is removed: nginx reads them as nothing then."
}
# <<< nginx-layout <<<

# The configuration this run reads -- and, where it is a distribution's,
# writes to.  SELFBUILT_NGINX=1 is the nginx whose files are left alone.
NGINX_CONF=$(nginx_conf_path)
SELFBUILT_NGINX=0
[ "$NGINX_CONF" = "$PACKAGED_NGINX_CONF" ] || SELFBUILT_NGINX=1
# Fallback .so home for hosts whose /usr is read-only at runtime (Fedora
# Silverblue / ostree and friends).  The distro-conventional modules path is
# still preferred when writable: it inherits the right SELinux label and
# matches what nginx tooling expects.
FALLBACK_SO_DIR=/var/lib/unmask/plugin
# Breadcrumb dropped when the fail-safe strips the module (no bundled .so for
# the host nginx, or nginx -t failed referencing unmask).  Two readers: `unmask
# doctor` surfaces it so an operator sees protection is OFF rather than assuming
# install-and-go worked, and `unmask render-nginx` renders the DEGRADED
# configuration while it exists -- http.inc without the module's directives
# (its variables defined empty), server.inc without the ban and deny gates,
# protect.inc inert -- so a vhost that includes server.inc still starts and the
# admin UI stays reachable.  Cleared on the next successful `nginx -t` with the
# module wired, which also renders the full configuration again.
FAILSAFE_MARKER=/var/lib/unmask/nginx/.native-failsafe
# The http.inc auto-load symlink the two postinstalls create (= see the wiring
# step below for the http.d variant, and for a self-built nginx's).
HTTP_INC_LINKS="/etc/nginx/conf.d/00-unmask.conf /etc/nginx/http.d/00-unmask.conf $OWN_HTTP_DIR/00-unmask.conf"

# Hooks the unit test (place-module_test.sh) overrides; the defaults are the
# real thing.
#   _pm_render        : `unmask render-nginx`, quietly.  Non-zero when there is
#                       no unmask binary or the render failed.  Reads the marker
#                       itself: degraded while it exists, full once it is gone.
#   _pm_nginx_t       : `nginx -t`, output on stdout.
#   _pm_strip_module  : remove the load_module wiring and the .so.
#   _pm_module_wired  : 0 when a module .so is in place for nginx to load.
_pm_render() {
    [ -x /usr/sbin/unmask ] || return 1
    /usr/sbin/unmask render-nginx >/dev/null 2>&1
}
_pm_nginx_t() { nginx -t 2>&1; }
_pm_strip_module() { unwire_module strip; }
_pm_module_wired() {
    mp=$(nginx -V 2>&1 | tr ' ' '\n' | sed -n 's|^--modules-path=||p' | head -1)
    { [ -n "$mp" ] && [ -e "$mp/$SO_NAME" ]; } || [ -e "$FALLBACK_SO_DIR/$SO_NAME" ] || [ -e "$OWN_SO_DIR/$SO_NAME" ]
}

# ---- an nginx built from source that is built again ----
# A distribution replaces its nginx through the package manager and starts it
# through its service, where this script runs first (the drop-in) and picks
# the module for the new build.  An nginx built from source has other ways:
# a hosting panel removes the old build, installs another -- a version of its
# choosing, with or without --with-compat -- puts an nginx.conf in place (a
# new one, or a copy it kept, with or without the two include lines) and runs
# `nginx -t` on the result itself, before it starts anything.  When that test
# fails the panel stops there, and no nginx runs.  It fails on a module built
# for the old binary, and on a server block that includes unmask's server.inc
# while the http directory that defines what it names is not included.
#
# So for such an nginx the module is taken out, and what the server blocks
# include is rendered with nothing in it (go_inert), the moment its binary
# changes or goes: a systemd path unit watches the file and runs this script
# with --nginx-changed.  Whatever build and nginx.conf come next, they load.
# The way back is the ordinary run of this script -- before every start of
# nginx's service, from the packages, by hand: it places the module for the
# build that is there, and the full configuration is rendered again once the
# two include lines are in nginx.conf and nginx -t passes with them.

# The nginx binary the module on disk was placed for ("<sha256>  <path>").
NGINX_BIN_NOTE=/var/lib/unmask/plugin/.nginx-binary
# The watch on that file: written here, enabled by the package's postinstall,
# removed with the package.  Its service is shipped (unmask-nginx-binary.service).
WATCH_UNIT=/etc/systemd/system/unmask-nginx-binary.path
SYSTEMD_RUN_DIR=/run/systemd/system
# One run of this script at a time: the watch can fire while nginx's service
# is starting.
PM_LOCK=/run/unmask-place-module.lock

_pm_lock() {
    command -v flock >/dev/null 2>&1 || return 0
    # Asked in a subshell first: a redirection that fails on `exec` itself
    # ends the shell (not root, no /run).  Without the lock the run goes on.
    ( : >> "$PM_LOCK" ) 2>/dev/null || return 0
    exec 9>>"$PM_LOCK"
    flock -w 60 9 2>/dev/null || true
}

# nginx_bin_real: the nginx on PATH as a file, its links followed (a panel
# puts a link into /usr/bin).  Fails when there is none.
nginx_bin_real() {
    _br=$(command -v nginx 2>/dev/null) || return 1
    case "$_br" in
        /*) ;;
        *)  return 1 ;;
    esac
    _br_l=$(readlink -f "$_br" 2>/dev/null)
    [ -n "$_br_l" ] && _br=$_br_l
    [ -f "$_br" ] || return 1
    echo "$_br"
}

# nginx_bin_id <file>: what tells one build from another.
nginx_bin_id() { sha256sum "$1" 2>/dev/null | cut -d' ' -f1; }

# nginx_bin_note: note the build the module is now in place for.  Written the
# way the other note is (wired_record): beside it, then renamed.
nginx_bin_note() {
    _bn_bin=$(nginx_bin_real) || return 0
    _bn_new="$(nginx_bin_id "$_bn_bin")  $_bn_bin"
    [ "$(cat "$NGINX_BIN_NOTE" 2>/dev/null)" = "$_bn_new" ] && return 0
    mkdir -p "${NGINX_BIN_NOTE%/*}" 2>/dev/null || return 0
    _bn_tmp="$NGINX_BIN_NOTE.tmp.$$"
    rm -f "$_bn_tmp" 2>/dev/null
    if ( set -C; printf '%s\n' "$_bn_new" > "$_bn_tmp" ) 2>/dev/null; then
        mv -f "$_bn_tmp" "$NGINX_BIN_NOTE" 2>/dev/null || rm -f "$_bn_tmp" 2>/dev/null
    fi
    return 0
}

# includes_note: what this run found of the two include lines, for `unmask
# doctor`.  The daemon's user often cannot read the nginx.conf of an nginx
# built from source (a panel keeps it to root), and then doctor could only
# say that it does not know.  "ok", or "missing: main http"; the file's time
# is when this was looked at.
INCLUDES_NOTE=/var/lib/unmask/plugin/.nginx-includes
includes_note() {
    if _pm_scope_included; then
        _in_new=ok
    else
        _in_new="missing: $(own_includes_missing | tr '\n' ' ' | sed 's/ $//')"
    fi
    mkdir -p "${INCLUDES_NOTE%/*}" 2>/dev/null || return 0
    _in_tmp="$INCLUDES_NOTE.tmp.$$"
    rm -f "$_in_tmp" 2>/dev/null
    if ( set -C; printf '%s\n' "$_in_new" > "$_in_tmp" ) 2>/dev/null; then
        mv -f "$_in_tmp" "$INCLUDES_NOTE" 2>/dev/null || rm -f "$_in_tmp" 2>/dev/null
    fi
    return 0
}

# nginx_bin_same: 0 when the nginx on PATH is the build the note names.
nginx_bin_same() {
    _bs_bin=$(nginx_bin_real) || return 1
    _bs_was=$(cat "$NGINX_BIN_NOTE" 2>/dev/null)
    [ -n "$_bs_was" ] && [ "$(nginx_bin_id "$_bs_bin")  $_bs_bin" = "$_bs_was" ]
}

# watch_unit_write: the path unit for this nginx's binary, where there is a
# systemd to run it -- written, and switched on, only when it would differ
# from the one there (this runs before every nginx start, where the file is
# as a rule the same and nothing is done).  Switched on from here and not
# only from the package's postinstall: the nginx may be installed after the
# plugin, or be one the plugin refused and that was then built again, and
# the first run to see it is the one inside the start of nginx's service.
# Nothing waits on nginx there: the path unit has no ordering against it.
watch_unit_write() {
    [ -d "$SYSTEMD_RUN_DIR" ] || return 0
    _wu_bin=$(nginx_bin_real) || return 0
    _wu_new="# Written by unmask-plugin-nginx (place-module.sh) for an nginx built from
# source, and removed with the package.  When that nginx's binary changes or
# goes -- a rebuild, a hosting panel installing another version -- unmask
# takes its module out and renders its include files empty, so that the next
# build loads its configuration whatever it is.  The module is placed again
# before nginx's service starts.  See place-module.sh.
[Unit]
Description=unmask: watch the binary of an nginx built from source

[Path]
PathChanged=$_wu_bin
Unit=unmask-nginx-binary.service

[Install]
WantedBy=multi-user.target"
    [ "$(cat "$WATCH_UNIT" 2>/dev/null)" = "$_wu_new" ] && return 0
    printf '%s\n' "$_wu_new" > "$WATCH_UNIT" 2>/dev/null || return 0
    chmod 0644 "$WATCH_UNIT" 2>/dev/null
    echo "  watch on $_wu_bin: $WATCH_UNIT"
    if command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload >/dev/null 2>&1 || true
        systemctl enable unmask-nginx-binary.path >/dev/null 2>&1 || true
        systemctl --no-block restart unmask-nginx-binary.path >/dev/null 2>&1 || true
    fi
}

# _pm_marker <reason> [inert]: leave the fail-safe's marker.  With a second
# argument it also says that nginx does not read unmask's http directory: the
# render then puts nothing into the files a server block includes.
_pm_marker() {
    mkdir -p "$(dirname "$FAILSAFE_MARKER")" 2>/dev/null
    { echo "native wiring stripped by place-module fail-safe ($(date 2>/dev/null))"
      [ -n "${1:-}" ] && echo "reason: $1"
      [ -n "${2:-}" ] && echo "inert: nginx does not read unmask's http directory; server.inc and protect.inc carry no directive"
    } > "$FAILSAFE_MARKER" 2>/dev/null || true
}
_pm_marker_inert() { grep '^inert:' "$FAILSAFE_MARKER" >/dev/null 2>&1; }

# Whether a self-built nginx reads unmask's part of its configuration: the
# two include lines (own_includes_missing), or wiring of the operator's own
# that stands in for one -- a load_module they wrote for the module, an
# include of http.inc itself.  Both hold for a distribution's nginx, whose
# wiring is the packages' own.
#   _pm_http_included   : it reads http.inc.
#   _pm_scope_included  : it reads http.inc and loads the module.
# _pm_stands_in <main|http>: 0 when the operator's own line does that part.
_pm_stands_in() {
    _st_cfg=$(_nl_nginx_dump)
    [ -n "$_st_cfg" ] || _st_cfg=$(cat "$NGINX_CONF" 2>/dev/null)
    case $1 in
        main) _st_re='(^|[[:space:];{}])load_module[[:space:]].*ngx_http_unmask_module' ;;
        *)    _st_re="(^|[[:space:];{}])include[[:space:]]+[\"']?/var/lib/unmask/nginx/http[.]inc[\"']?[[:space:]]*;" ;;
    esac
    printf '%s\n' "$_st_cfg" | sed 's/#.*//' | grep -E "$_st_re" >/dev/null
}
_pm_http_included() {
    [ "${SELFBUILT_NGINX:-0}" = 1 ] || return 0
    own_includes_missing | grep '^http$' >/dev/null || return 0
    _pm_stands_in http
}
_pm_scope_included() {
    [ "${SELFBUILT_NGINX:-0}" = 1 ] || return 0
    for _sc_k in $(own_includes_missing); do
        _pm_stands_in "$_sc_k" || return 1
    done
    return 0
}

# _pm_own_wiring: 0 when anything of a self-built nginx's wiring is in place.
_pm_own_wiring() {
    [ -e "$OWN_SO_DIR/$SO_NAME" ] || [ -e "$OWN_MAIN_DIR/$LOAD_CONF" ] || [ -L "$OWN_HTTP_DIR/00-unmask.conf" ]
}

# go_inert <reason>: take the module out and render what the server blocks
# include with nothing in it.  nginx -- whichever build, with whichever
# nginx.conf -- then loads its configuration as if unmask were not installed.
#
# Answers as the render did: when `unmask render-nginx` could not run (no
# binary, a database it cannot reach) the files are as they were, and the
# caller says so.  What was noted of this nginx's include lines for doctor
# goes too: the next nginx.conf is another file.
go_inert() {
    _pm_strip_module
    _pm_marker "$1" inert
    rm -f "$INCLUDES_NOTE" 2>/dev/null
    _pm_render
}
# go_inert_say: what the caller prints after it.
go_inert_say() {
    if [ "$1" = 0 ]; then
        echo "  The module is out and unmask's include files carry nothing, so the next build loads its configuration"
        echo "  whatever it is.  Before nginx's service starts, the module is placed for that build; the full"
        echo "  configuration is rendered again once its nginx.conf carries the two include lines and nginx -t passes."
    else
        echo "  The module is out, but 'unmask render-nginx' could not run: unmask's include files are as they were."
        echo "  A server block that includes them may stop the next build from loading its configuration -- run"
        echo "    unmask render-nginx"
        echo "  once it can (see its error), or take the include lines out of the server blocks until then."
    fi
}

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
#     before the note, whose nginx.conf has changed since -- and unmask's own
#     one, which a self-built nginx includes (see nginx-layout above).
WIRED_STATE=/var/lib/unmask/plugin/.wired
LOAD_CONF=50-mod-unmask.conf
LOAD_CONF_DIRS="/etc/nginx/modules-enabled /etc/nginx/modules.d /etc/nginx/modules-available /etc/nginx/modules /usr/share/nginx/modules $OWN_MAIN_DIR"
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

    # The .so: nginx's modules path, the home it gets on a read-only /usr, and
    # the one beside unmask's own directories for a self-built nginx (whose
    # modules path is not written to, so nothing is looked for there).
    _uw_mp=""
    if [ "${SELFBUILT_NGINX:-0}" != 1 ] && command -v nginx >/dev/null 2>&1; then
        _uw_mp=$(nginx -V 2>&1 | tr ' ' '\n' | sed -n 's|^--modules-path=||p' | head -1)
    fi
    [ -n "$_uw_mp" ] && _uw_rm "$_uw_mp/$SO_NAME"
    _uw_rm "$FALLBACK_SO_DIR/$SO_NAME"
    _uw_rm "$OWN_SO_DIR/$SO_NAME"

    # The line in nginx.conf itself.  Built beside it and renamed into place,
    # so that nginx.conf is never half-written; the copy first keeps its mode
    # and owner.  Not in a self-built nginx's: no line there is this
    # package's (it loads the module through the include of $OWN_MAIN_DIR,
    # emptied above), and its file is not edited, by the fail-safe either -- a
    # load_module the operator wrote there is named below, on a removal.
    _uw_re='load_module.*ngx_http_unmask_module'
    [ "$_uw_mode" = remove ] && _uw_re="$_uw_re.*$LOAD_TAG"
    if [ "${SELFBUILT_NGINX:-0}" != 1 ] && [ -w "$NGINX_CONF" ] && grep -q "$_uw_re" "$NGINX_CONF" 2>/dev/null; then
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
    if [ "$_uw_mode" = remove ]; then
        rmdir "$FALLBACK_SO_DIR" "$OWN_SO_DIR" "$OWN_MAIN_DIR" 2>/dev/null
        rmdir "$OWN_NGINX_DIR" 2>/dev/null     # unless unmask-web-nginx still has its own in it
    fi
    return 0
}
# <<< unwire <<<

# wired_record <so path> [<conf path>]: note where the module and the conf
# that loads it were put, so that unwire_module looks there first, whatever
# nginx.conf says by then.  Rewritten only when it changed: this runs before
# every nginx start.  The directory is in the unmask user's tree, so the note
# is made under a fresh name and renamed into place -- a link planted at
# either name is replaced, never written through.
wired_record() {
    _wr_new="so $1"
    [ -n "${2:-}" ] && _wr_new="$_wr_new
conf $2"
    [ "$(cat "$WIRED_STATE" 2>/dev/null)" = "$_wr_new" ] && return 0
    mkdir -p "${WIRED_STATE%/*}" 2>/dev/null || return 0
    _wr_tmp="$WIRED_STATE.tmp.$$"
    rm -f "$_wr_tmp" 2>/dev/null
    if ( set -C; printf '%s\n' "$_wr_new" > "$_wr_tmp" ) 2>/dev/null; then
        mv -f "$_wr_tmp" "$WIRED_STATE" 2>/dev/null || rm -f "$_wr_tmp" 2>/dev/null
    fi
    return 0
}

# unmask_error <nginx -t output>: 0 when the failure is about OUR OWN wiring
# artifacts: the module itself (ngx_http_unmask...), our autoload/symlink confs
# (00-unmask*, 50-mod-unmask) and the render output (/var/lib/unmask/nginx/).
# A bare "unmask" match is too broad: an OPERATOR conf that includes a shipped
# forward-auth snippet (/etc/unmask/forward-auth/server.inc, per the web-nginx
# install instructions) mentions an unmask path too -- and when that file is
# transiently absent (mid-transaction on a reinstall: this runs from the plugin
# postinstall BEFORE web-nginx lays its files down), the broad match stripped a
# perfectly healthy native module.  Stripping can never fix those errors anyway
# (we don't touch operator vhosts), so leave them to the operator / the rest of
# the transaction.
unmask_error() {
    printf '%s\n' "$1" | grep -qiE 'ngx_http_unmask|00-unmask|50-mod-unmask|/var/lib/unmask/nginx/'
}
unmask_error_line() {
    printf '%s\n' "$1" | grep -iE 'ngx_http_unmask|00-unmask|50-mod-unmask|map_hash|/var/lib/unmask/nginx/' | head -1
}

# disable_unmask_module: take the module out so a stock nginx still starts.
# Used when no bundled .so matches the host nginx (= the host upgraded nginx to
# a version we don't ship a module for) and when `nginx -t` fails on unmask's
# wiring.  Leaving the old load_module + an ABI-incompatible .so in place makes
# nginx fail to start ENTIRELY -- the "host-nginx-upgrade orphan" outage.
# Coming up WITHOUT protection (degraded) beats a dead web server.
#
# The configuration is then re-rendered without the module (the marker written
# first is what tells `unmask render-nginx` to): http.inc stays included, because
# a vhost that includes server.inc -- the README's setup -- names http.inc's
# log_format and cannot start without it.  Before this re-render the fail-safe
# dropped http.inc instead, and such a host could not start nginx at all
# (`unknown log format "unmask_minimal"`).  Only when unmask cannot render --
# no binary, a config it cannot read -- is http.inc dropped from nginx as before.
# The bundled .so files stay under $PLUGIN_BASE for a later re-pick.
#
# One step further down, where http.inc itself is not read: an nginx built
# from source whose nginx.conf does not include unmask's http directory (the
# operator has not added the line, or a panel wrote the file anew), and any
# nginx on which `nginx -t` still fails on unmask's files with the module
# out.  server.inc and protect.inc are then rendered with nothing in them
# (the marker's `inert:` line asks the render for that): a server block that
# includes them loads, and the sites serve as they would without unmask.
disable_unmask_module() {
    _pm_strip_module
    _dm_inert=""
    _pm_http_included || _dm_inert=1
    _pm_marker "${1:-}" "$_dm_inert"
    if _pm_render; then
        echo "  fail-safe: stripped the unmask module (load_module + .so) and re-rendered the configuration WITHOUT it:"
        if [ -n "$_dm_inert" ]; then
            echo "             this nginx does not include unmask's http directory, so the files its server blocks include"
            echo "             carry nothing: nginx starts and the sites serve as without unmask, protection is OFF."
        else
            echo "             nginx starts and the admin UI stays reachable, protection is OFF until the module is back."
        fi
    else
        for f in $HTTP_INC_LINKS; do rm -f "$f" 2>/dev/null; done
        echo "  fail-safe: stripped unmask nginx wiring (load_module + http.inc + .so) so nginx still starts without the module"
        echo "             (unmask could not re-render the configuration; run 'unmask render-nginx' once it can)."
    fi
    if err=$(_pm_nginx_t); then
        echo "  nginx -t passes without the module.  'unmask doctor' names the cause; the marker $FAILSAFE_MARKER"
        echo "  clears, and the full configuration is rendered again, once nginx -t passes with the module wired."
    elif [ -z "$_dm_inert" ] && unmask_error "$err"; then
        # Still one of unmask's files, with the module out: what a server
        # block includes names something http.inc defines, and nginx does not
        # read http.inc (or reads it after the sites).  Nothing is left to
        # take out but the directives themselves.
        echo "  nginx -t still fails on unmask's files without the module:"
        printf '%s\n' "$err" | sed 's/^/       /'
        _pm_marker "${1:-}" inert
        if _pm_render && err=$(_pm_nginx_t); then
            echo "  so server.inc and protect.inc are now rendered with nothing in them: nginx -t passes, nginx starts and"
            echo "  the sites serve as without unmask.  'unmask doctor' names the cause."
        else
            echo "  and it fails with those rendered empty as well:"
            printf '%s\n' "$err" | sed 's/^/       /'
        fi
    else
        echo "  nginx -t still fails without the module:"
        printf '%s\n' "$err" | sed 's/^/       /'
    fi
}

# verify_or_disable: run `nginx -t` and, if it fails *because of unmask*, take
# the module out (disable_unmask_module) so nginx still starts.  A failure whose
# error does NOT reference unmask is a pre-existing host config error -- leave
# unmask alone and let the operator fix it (never mask their own bug).  This is
# the catch-all for a bad render: a missing community-bans map, a stale http.inc,
# an unknown directive -- anything that would otherwise leave nginx unable to
# start/reload after install.  Called at the end of the picker's own flow and,
# via `--verify`, by the web-nginx postinstall, so whichever wires last runs the
# final check.
#
# The way back: when the marker is there and nginx -t passes with a module in
# place, the marker goes and the full configuration is rendered -- which must
# load too, so it is checked once more, and stripped again if it does not (that
# strip renders the degraded configuration again, so this cannot loop).  With
# no module in place the degraded configuration is left as it is: nginx -t
# passing without a module says nothing about the module.
verify_or_disable() {
    command -v nginx >/dev/null 2>&1 || return 0
    if err=$(_pm_nginx_t); then
        if [ -e "$FAILSAFE_MARKER" ]; then
            if _pm_module_wired && _pm_scope_included; then
                rm -f "$FAILSAFE_MARKER" 2>/dev/null
                echo "  fail-safe cleared: nginx -t passes with the module wired; rendering the full configuration again."
                _pm_render || echo "  WARNING: 'unmask render-nginx' failed -- run it by hand, then nginx -t."
                if ! err=$(_pm_nginx_t); then
                    if unmask_error "$err"; then
                        echo "  !! nginx -t fails on the full configuration -- taking the module out again (fail-safe):"
                        printf '%s\n' "$err" | sed 's/^/       /'
                        disable_unmask_module "$(unmask_error_line "$err")"
                    else
                        echo "  nginx -t failed on the full configuration, but the error does NOT reference unmask (= host config error). Leaving unmask in place:"
                        printf '%s\n' "$err" | sed 's/^/       /'
                    fi
                fi
            elif _pm_module_wired; then
                # A self-built nginx: the module is in place and its nginx.conf
                # does not include both of unmask's directories.  The full
                # configuration cannot load there; the lines are named below.
                echo "  fail-safe still active ($FAILSAFE_MARKER): the module is in place, but $NGINX_CONF does not"
                echo "  include both of unmask's directories; the configuration stays rendered without unmask until it does"
                echo "  and nginx is started again."
            else
                echo "  fail-safe still active ($FAILSAFE_MARKER): no module in place for nginx to load; the configuration stays rendered without it."
            fi
        fi
        return 0
    fi
    if unmask_error "$err"; then
        echo "  !! nginx -t failed and the error references unmask -- disabling the module (fail-safe) so nginx still starts:"
        printf '%s\n' "$err" | sed 's/^/       /'
        disable_unmask_module "$(unmask_error_line "$err")"
    else
        echo "  nginx -t failed, but the error does NOT reference unmask (= pre-existing host config error). Leaving unmask in place:"
        printf '%s\n' "$err" | sed 's/^/       /'
    fi
}

# One run at a time (not when the unit test reads the functions).
[ -n "${PLACE_MODULE_TEST:-}" ] || _pm_lock

# --nginx-changed: the watch on a self-built nginx's binary saw the file
# change or go (unmask-nginx-binary.path).  Takes unmask out and nothing
# else; the ordinary run puts it back.  A change that leaves the build the
# module was placed for -- a touch, a chmod -- is none.
if [ "${1:-}" = "--nginx-changed" ]; then
    SELFBUILT_NGINX=1
    if nginx_bin_same; then
        exit 0
    fi
    if [ -e "$FAILSAFE_MARKER" ] && _pm_marker_inert && [ ! -e "$OWN_SO_DIR/$SO_NAME" ] && [ ! -e "$OWN_MAIN_DIR/$LOAD_CONF" ]; then
        exit 0      # out already
    fi
    if _nc_bin=$(nginx_bin_real); then
        _nc_why="the nginx binary changed ($_nc_bin is not the build the module was placed for)"
    else
        _nc_why="the nginx binary is gone (an nginx built from source is being replaced)"
    fi
    echo "unmask-plugin-nginx: $_nc_why."
    go_inert "$_nc_why"
    go_inert_say $?
    exit 0
fi

if ! command -v nginx >/dev/null 2>&1; then
    # An nginx built from source that was wired and is gone -- a panel is
    # between two builds: the next one must load whatever it finds.
    if _pm_own_wiring; then
        SELFBUILT_NGINX=1
        echo "unmask-plugin-nginx: the nginx built from source that carried the module is gone."
        go_inert "nginx is not installed (an nginx built from source was removed)"
        go_inert_say $?
    fi
    cat <<EOF
unmask-plugin-nginx: nginx is not installed, so skipped placing the module.
  Install nginx and then re-place by one of:
    1. dnf reinstall unmask-plugin-nginx
    2. Copy /usr/share/unmask/plugin/openssl{11,3}/ngx_http_unmask_module-<version>.so by hand to
       \$(nginx -V 2>&1 | tr ' ' '\n' | grep modules-path)
EOF
    exit 1
fi

# --verify: only re-test the already-placed wiring and fail-safe-disable it if
# *unmask* breaks `nginx -t` (no re-pick).  The web-nginx postinstall calls this
# after it (re)wires http.inc, so whichever package wires last runs the final
# check and a bad render never leaves nginx unable to start.
if [ "${1:-}" = "--verify" ]; then
    verify_or_disable
    exit 0
fi

# Detect musl libc (= Alpine / similar).  The bundled .so files are built
# against glibc; nginx on Alpine is linked against musl and cannot dlopen a
# glibc .so directly.  Alpine's `gcompat` package provides a glibc compat
# layer that lets dlopen + symbol resolution succeed.  If gcompat is present
# we proceed normally; otherwise we skip with a hint so apk add gcompat
# unblocks the operator.
if ldd --version 2>&1 | grep -qi musl \
   || [ -e /lib/ld-musl-x86_64.so.1 ] \
   || [ -e /lib/ld-musl-aarch64.so.1 ]; then
    if [ -e /lib/ld-linux-x86-64.so.2 ] || [ -e /lib/ld-linux-aarch64.so.1 ]; then
        echo "unmask-plugin-nginx: musl libc + gcompat detected (= Alpine with glibc compat). Proceeding with glibc-built module."
    else
        cat <<'EOF'
================================================================
unmask-plugin-nginx: musl libc without gcompat detected (= Alpine).
================================================================

The bundled module .so files are glibc-built.  Alpine's nginx is musl-
linked and cannot dlopen a glibc .so without the gcompat glibc compat
layer.  Install gcompat and rerun the unmask-plugin-nginx install:

  sudo apk add gcompat
  sudo apk add --no-cache unmask-plugin-nginx

(gcompat is listed as a soft `depends` in the apk metadata, so a plain
`apk add unmask-plugin-nginx` should already pull it in -- this branch
fires only when gcompat was explicitly excluded.)

Alternatively, run unmask in forward-auth mode -- the main `unmask`
package alone is enough; nginx subrequests the admin daemon.  See
https://unmask.sh/install/  ->  pick "nginx · auth_request".

The .so binaries stay under /usr/share/unmask/plugin/ for inspection.
================================================================
EOF
        exit 1
    fi
fi

# ---- 0.5. Determine the host nginx's OpenSSL ABI ----
# Look at the version of libcrypto.so the nginx binary links against, and
# pick the plugin .so built against the matching ABI.  Thanks to the
# custom ClientHello parser (= ja4_parser.c), the same source is ABI-
# compatible across OpenSSL 0.9.7+, and we ship one .so per ABI built
# from the same source.
PLUGIN_DIR=""
# Also detect glibc version (= CentOS 6 = 2.12 / CentOS 7 = 2.17 / RHEL 8 = 2.28 etc.).
# Pick the CentOS 6 family glibc 2.12 build (= ships its own libcrypto.so.10)
# when glibc is older than 2.14.
GLIBC_VER=""
if command -v ldd >/dev/null 2>&1; then
    GLIBC_VER=$(ldd --version 2>/dev/null | head -1 | sed -n 's|.*[ ]\([0-9][0-9]*\.[0-9][0-9]*\)$|\1|p')
fi
glibc_lt_214() {
    # arg: e.g. "2.12" / "2.17".  Returns 0 (true) for < 2.14 (= 2.0 .. 2.13.999).
    case "$1" in
        2.[0-9]|2.[0-9].*|2.1[0-3]|2.1[0-3].*) return 0 ;;
        *) return 1 ;;
    esac
}

# resolve_libcrypto: print the libcrypto SONAME the host nginx uses, or "" if
# undetermined.  Order: (1) ldd of the nginx binary, (2) `nginx -V`'s "built
# with OpenSSL X" (nginx.org / self-built nginx links OpenSSL statically, so
# ldd is silent), (3) newest libcrypto SONAME present on the system.
# Pure-ish + test-injectable (= v0.1.1): tests override these hooks —
#   _rl_ldd_soname  : echoes the SONAME ldd would find ("" = none)
#   _rl_nginx_v     : echoes `nginx -V` output
#   _rl_have_so     : `_rl_have_so <soname>` returns 0 if that SONAME exists
# The default hooks below implement the real probes; place-module_test.sh
# redefines them to exercise ldd-silent / static-OpenSSL / LibreSSL cases.
_rl_ldd_soname() {
    command -v ldd >/dev/null 2>&1 || { echo ""; return; }
    ldd "$(command -v nginx)" 2>/dev/null | sed -n 's|.*\(libcrypto\.so\.[0-9.]*\).*|\1|p' | head -1
}
_rl_nginx_v() { nginx -V 2>&1; }
_rl_have_so() {
    for d in /lib64 /usr/lib64 /lib /usr/lib /usr/lib/x86_64-linux-gnu /usr/lib/aarch64-linux-gnu; do
        [ -e "$d/$1" ] && return 0
    done
    return 1
}

# install_so <src> <primary-dir> <fallback-dir>: atomically install the .so
# into primary-dir; when that fails (read-only /usr on an immutable distro),
# fall back to fallback-dir.  Prints the installed path on stdout, returns
# non-zero when neither landed.  tmp + rename(2) so a running nginx worker
# that still mmaps the old .so doesn't hit ETXTBSY mid-upgrade, and a SIGKILL
# during the copy can't leave a half-written .so on disk.
install_so() {
    _is_src=$1
    for _is_dir in "$2" "$3"; do
        [ -d "$_is_dir" ] || mkdir -p "$_is_dir" 2>/dev/null || continue
        _is_tmp="$_is_dir/$SO_NAME.tmp.$$"
        if cp -f "$_is_src" "$_is_tmp" 2>/dev/null \
           && chmod 0644 "$_is_tmp" 2>/dev/null \
           && mv -f "$_is_tmp" "$_is_dir/$SO_NAME" 2>/dev/null; then
            echo "$_is_dir/$SO_NAME"
            return 0
        fi
        rm -f "$_is_tmp" 2>/dev/null
    done
    return 1
}
# so_in_place <src> <primary-dir> <fallback-dir>: when the module already
# sitting at either location has exactly these bytes, print that path and
# return 0; install_so is then skipped.
#
# install_so's rename is atomic, but it still gives the path a new inode, and
# nginx loads a module only at startup -- so replacing even an identical file
# left the host needing an nginx restart before it was back in a known state.
# Most upgrades do not change the module at all (it is rebuilt far less often
# than the admin), and those should not touch nginx.
so_in_place() {
    for _sp_dir in "$2" "$3"; do
        if [ -f "$_sp_dir/$SO_NAME" ] && cmp -s "$1" "$_sp_dir/$SO_NAME"; then
            echo "$_sp_dir/$SO_NAME"
            return 0
        fi
    done
    return 1
}
# _rl_static_pick <own> <other>: the SONAME for an nginx that has OpenSSL 1.1
# or 3 linked in statically (a self-built nginx, a hosting panel's).
#
# The module then calls the OpenSSL inside the nginx binary -- nginx exports
# it, and the loader looks there first -- whichever of the two families the
# module was built in: the functions it uses are the same in both.  What the
# family does decide is the libcrypto the module FILE names, and the loader
# has to find that one on this system or the module is not loaded at all.
# Going by nginx's own OpenSSL alone picked the 1.1 module for an nginx built
# with a static 1.1.1 on a system that only has libcrypto.so.3 (every current
# distribution), and that module could not be opened.  So: nginx's own family
# when its libcrypto is on the system, the other one when only that is, and
# nginx's own again when neither is, for the error to name it.
# OpenSSL 1.0 is not part of this: its ex-data classes are numbered
# differently, and a module of another family would file its per-connection
# data under the wrong one.
_rl_static_pick() {
    if _rl_have_so "$1"; then echo "$1"
    elif _rl_have_so "$2"; then echo "$2"
    else echo "$1"
    fi
}
resolve_libcrypto() {
    local so ver
    so=$(_rl_ldd_soname)
    if [ -n "$so" ]; then echo "$so"; return; fi
    # ldd silent: parse `nginx -V`'s OpenSSL version.
    ver=$(_rl_nginx_v | sed -n 's|.*[Oo]pen[Ss][Ss][Ll] \([0-9][0-9.]*\).*|\1|p' | head -1)
    case "$ver" in
        3.*)   _rl_static_pick libcrypto.so.3 libcrypto.so.1.1; return ;;
        1.1.*) _rl_static_pick libcrypto.so.1.1 libcrypto.so.3; return ;;
        1.0.*) echo "libcrypto.so.10";  return ;;
    esac
    # Still unknown (LibreSSL/BoringSSL/no version): newest system SONAME.
    for cand in libcrypto.so.3 libcrypto.so.1.1 libcrypto.so.10; do
        _rl_have_so "$cand" && { echo "$cand"; return; }
    done
    echo ""
}

# list_versions <plugin-dir>: the nginx versions the bundle under plugin-dir
# carries a module for, newest first.
list_versions() {
    ls -1 "$1"/ngx_http_unmask_module-*.so 2>/dev/null | \
        sed -n 's|.*/ngx_http_unmask_module-\(.*\)\.so$|\1|p' | \
        sort -V -r
}

# pick_bundled <plugin-dir> <host-version>: print the path of the bundled .so
# built for exactly the host's nginx version, or return 1 when there is none.
#
# Exactly: nginx refuses a dynamic module built for any other version, a
# neighbouring patch release of the same branch included (ngx_module.c
# compares the module's nginx_version with its own and logs `module "..."
# version N instead of M`).  Through 0.1.53 this fell back to the closest
# patch of the same minor branch, calling it "assumes patch ABI
# compatibility": that module never loaded, the verify step's nginx -t failed
# on it, and the fail-safe stripped it -- the same end state as no module at
# all, reached after a misleading "closest match" line.
pick_bundled() {
    _pb_so="$1/${SO_NAME%.so}-$2.so"
    [ -f "$_pb_so" ] || return 1
    echo "$_pb_so"
}

# no_module_report <plugin-dir> <host-version>: what the operator can do when
# the bundle has no module for this nginx.  On stderr, like the other
# refusals; the fail-safe's own lines follow it.
no_module_report() {
    _nr_dir=$1; _nr_ver=$2
    {
        echo "================================================================"
        echo "unmask-plugin-nginx: no module for nginx ${_nr_ver} -- nothing placed."
        echo "================================================================"
        echo "nginx loads a module built for exactly its own version, ${_nr_ver}, and"
        echo "refuses every other at start -- a neighbouring patch release of the"
        echo "same branch included (its error log then says \"version N instead of M\")."
        echo ""
        echo "This bundle carries a module for these nginx versions (${_nr_dir};"
        echo "\`ls /usr/share/unmask/plugin/*/\` lists every build shipped):"
        for v in $(list_versions "$_nr_dir"); do echo "  - $v"; done
        echo ""
        echo "Until a module is in place, nginx runs WITHOUT unmask (the fail-safe"
        echo "below keeps it starting) and no request is challenged; \`unmask doctor\`"
        echo "and the admin's notification list say so.  Ways out:"
        echo "  1) Move nginx to a bundled version and keep it there: install that"
        echo "     version and pin the nginx package (dnf versionlock / apt-mark hold /"
        echo "     apk add 'nginx=<version>') so the distribution's updates do not move"
        echo "     it off the list; then restart nginx.  A systemd host runs this script"
        echo "     before every nginx start; elsewhere run it by hand first:"
        echo "       sh /usr/share/unmask/plugin/place-module.sh"
        echo "  2) Build the module for nginx ${_nr_ver} from the unmask source on"
        echo "     another host (make build-module NGINX_VERSION=${_nr_ver}) and put it"
        echo "     into this bundle as ${_nr_dir}/${SO_NAME%.so}-${_nr_ver}.so:"
        echo "     the next run of this script places it like a bundled one."
        echo "  3) Install a later unmask-plugin-nginx that bundles ${_nr_ver}:"
        echo "     https://unmask.sh/install/ lists the versions each release ships."
        echo "  4) Run without the module: forward-auth mode needs the main package"
        echo "     alone (https://unmask.sh/install/)."
        echo "================================================================"
    } >&2
}

# _pm_dry_load <so>: whether THIS nginx takes THIS file -- `nginx -t` on a
# configuration of three lines that loads the module and nothing else, in a
# directory of its own.  Nothing of the operator's is read or written for it.
# Prints what nginx said; non-zero when nginx refuses.  For a self-built
# nginx, which has reasons to refuse that a distribution's does not: built
# without --with-compat, or with a module of its own that changes nginx's
# structures.  Where no directory can be made to ask in, it does not stand in
# the way (the check after the wiring still looks).
_pm_dry_load() {
    _dl_dir=$(mktemp -d 2>/dev/null) || return 0
    mkdir -p "$_dl_dir/logs" 2>/dev/null
    printf 'load_module "%s";\npid %s/nginx.pid;\nevents {}\n' "$1" "$_dl_dir" > "$_dl_dir/nginx.conf"
    _dl_out=$(nginx -t -p "$_dl_dir/" -c "$_dl_dir/nginx.conf" 2>&1)
    _dl_rc=$?
    rm -rf "$_dl_dir"
    printf '%s\n' "$_dl_out"
    return "$_dl_rc"
}

# selfbuilt_refused_report <nginx's words>: what the operator reads when a
# self-built nginx does not take the module.  To stderr, like the report for
# a version with no module.
selfbuilt_refused_report() {
    {
        echo "================================================================"
        echo "unmask-plugin-nginx: this nginx does not take the module -- nothing placed"
        echo "================================================================"
        echo "Asked to load the module and nothing else, nginx -t said:"
        printf '%s\n' "$1" | grep -E 'emerg|error' | head -3 | sed 's/^/    /'
        echo ""
        case "$1" in
            *"not binary compatible"*)
                echo "An nginx built from source loads a packaged module only when it was"
                echo "configured --with-compat.  Add that option to its configure line and"
                echo "build it again -- with a hosting panel, in the custom parameters of"
                echo "its nginx build -- then run:"
                ;;
            *)
                echo "Once that is out of the way, run:"
                ;;
        esac
        echo "    sh $PLUGIN_BASE/place-module.sh"
        echo "Until then nginx runs WITHOUT unmask and no request is challenged;"
        echo "\`unmask doctor\` and the admin's notification list say so."
        echo "================================================================"
    } >&2
}

# Guard: when sourced by the unit test, stop here (no install side effects).
[ -n "${PLACE_MODULE_TEST:-}" ] && return 0 2>/dev/null

if command -v ldd >/dev/null 2>&1; then
    NGINX_BIN=$(command -v nginx)
    NGINX_LIBCRYPTO=$(_rl_ldd_soname)
    if [ -z "$NGINX_LIBCRYPTO" ]; then
        NGINX_LIBCRYPTO=$(resolve_libcrypto)
        # (An nginx with its OpenSSL built in: the module calls that one, and
        # is picked by the libcrypto its FILE names, which this system must
        # have -- see _rl_static_pick.  The line below then names the module's
        # family, not the OpenSSL inside nginx.)
        [ -n "$NGINX_LIBCRYPTO" ] && \
            echo "unmask-plugin-nginx: nginx -V/system probe -> $NGINX_LIBCRYPTO (ldd was silent: this nginx has its OpenSSL built in)"
    fi
    case "$NGINX_LIBCRYPTO" in
        libcrypto.so.3)
            PLUGIN_DIR="$PLUGIN_BASE/openssl3"
            echo "unmask-plugin-nginx: host OpenSSL = 3.x ($NGINX_LIBCRYPTO), glibc=$GLIBC_VER"
            ;;
        libcrypto.so.1.1)
            PLUGIN_DIR="$PLUGIN_BASE/openssl11"
            echo "unmask-plugin-nginx: host OpenSSL = 1.1.x ($NGINX_LIBCRYPTO), glibc=$GLIBC_VER"
            ;;
        libcrypto.so.10|libcrypto.so.1.0)
            # Separate CentOS 6 (= glibc 2.12) and CentOS 7 (= glibc 2.17).
            if [ -n "$GLIBC_VER" ] && glibc_lt_214 "$GLIBC_VER"; then
                PLUGIN_DIR="$PLUGIN_BASE/glibc212"
                echo "unmask-plugin-nginx: host OpenSSL = 1.0.x ($NGINX_LIBCRYPTO) + glibc=$GLIBC_VER < 2.14 -> CentOS 6 build path"
            else
                PLUGIN_DIR="$PLUGIN_BASE/openssl10"
                echo "unmask-plugin-nginx: host OpenSSL = 1.0.x ($NGINX_LIBCRYPTO), glibc=$GLIBC_VER"
            fi
            ;;
        *)
            echo "WARNING: unrecognized libcrypto: $NGINX_LIBCRYPTO. Trying OpenSSL 3 path." >&2
            PLUGIN_DIR="$PLUGIN_BASE/openssl3"
            ;;
    esac
else
    echo "WARNING: ldd not found, skipping OpenSSL ABI detection.  Trying the OpenSSL 3 path." >&2
    PLUGIN_DIR="$PLUGIN_BASE/openssl3"
fi

[ -d "$PLUGIN_DIR" ] || {
    echo "ERROR: plugin dir $PLUGIN_DIR does not exist.  Please verify the package contents." >&2
    exit 1
}

# ---- 1. host nginx version ----
HOST_VER=$(nginx -v 2>&1 | sed -n 's|.*nginx/\([0-9.]*\).*|\1|p')
if [ -z "$HOST_VER" ]; then
    echo "ERROR: failed to parse 'nginx -v'.  Skipping module placement." >&2
    exit 1
fi
echo "unmask-plugin-nginx: host nginx ${HOST_VER}"

# ---- 2. the bundled .so built for exactly this nginx ----
SRC=$(pick_bundled "$PLUGIN_DIR" "$HOST_VER") || {
    no_module_report "$PLUGIN_DIR" "$HOST_VER"
    # A re-run on a host nginx upgrade to an unbundled version leaves a now-
    # ABI-incompatible .so + load_module behind, which kills nginx on next
    # start.  Strip the wiring so nginx still comes up (degraded), not dead.
    disable_unmask_module "no bundled module for host nginx ${HOST_VER}"
    exit 1
}
echo "  exact match: $(basename "$SRC")"

# ---- 3. where the module file goes ----
# A distribution's nginx: its modules path, from `nginx -V`.  A self-built
# one: unmask's own directory beside the two that nginx includes -- nothing is
# written under its prefix, a modules path it may name included.
if [ "$SELFBUILT_NGINX" = 1 ]; then
    MODULES_PATH=$OWN_SO_DIR
    echo "unmask-plugin-nginx: an nginx built from source (configuration: $NGINX_CONF) -- its files are left as they are"
    # The watch on its binary and what its configuration includes (for
    # doctor), whatever this run goes on to find: a build the module is
    # refused by is watched too -- it is the one that will be built again.
    watch_unit_write
    includes_note
    # A fork that names an nginx version (Tengine does, and a panel offers it
    # beside nginx) is not that nginx: its structures differ, and a module
    # built for the version it names may load and then read the wrong fields.
    # Not placed there, whatever a load test would say.
    case "$(nginx -v 2>&1)" in
        *[Tt]engine*|*[Oo]pen[Rr]esty*)
            {
                echo "================================================================"
                echo "unmask-plugin-nginx: a fork of nginx, not nginx ${HOST_VER} -- nothing placed"
                echo "================================================================"
                nginx -v 2>&1 | sed 's/^/    /'
                echo "The bundled modules are built for nginx itself, version by version; a"
                echo "fork changes nginx's structures, and a module that loads into it can"
                echo "read the wrong fields.  Use nginx (one of the bundled versions), or the"
                echo "gateway container in front of this server: https://unmask.sh/install/"
                echo "================================================================"
            } >&2
            disable_unmask_module "a fork of nginx, not nginx ${HOST_VER}"
            exit 1
            ;;
    esac
    # Does it take the module at all?  Asked before anything is placed, so
    # that the answer comes here and in words, not as a failed `nginx -t`
    # after the operator has added the include lines.
    if ! _pm_dry_err=$(_pm_dry_load "$SRC"); then
        selfbuilt_refused_report "$_pm_dry_err"
        # A module wired by an earlier run would stop this nginx from starting.
        disable_unmask_module "nginx ${HOST_VER} does not load the module: $(printf '%s\n' "$_pm_dry_err" | grep -m1 -E 'emerg|error')"
        exit 1
    fi
else
    MODULES_PATH=$(nginx -V 2>&1 | tr ' ' '\n' | sed -n 's|^--modules-path=||p' | head -1)
    if [ -z "$MODULES_PATH" ]; then
        cat >&2 <<EOF
ERROR: nginx -V has no --modules-path, cannot place automatically.
  Place the chosen module by hand:
    cp $SRC /usr/lib/nginx/modules/$SO_NAME
EOF
        exit 1
    fi
fi

# ---- 4. install (with an immutable-/usr fallback) ----
MODULE_UNCHANGED=0
if DEST=$(so_in_place "$SRC" "$MODULES_PATH" "$FALLBACK_SO_DIR"); then
    MODULE_UNCHANGED=1
    echo "  module unchanged ($DEST) -- left in place; nginx does not need a restart for it"
else
    DEST=$(install_so "$SRC" "$MODULES_PATH" "$FALLBACK_SO_DIR") || {
        echo "ERROR: could not write the module to $MODULES_PATH nor $FALLBACK_SO_DIR. Skipping placement." >&2
        exit 1
    }
fi
if [ "$DEST" = "$FALLBACK_SO_DIR/$SO_NAME" ]; then
    echo "  modules-path $MODULES_PATH is not writable (immutable /usr?) -> placed under $FALLBACK_SO_DIR"
    echo "  note: SELinux-enforcing hosts may need a local label before nginx can load from there:"
    echo "        semanage fcontext -a -t lib_t '$FALLBACK_SO_DIR(/.*)?' && restorecon -R $FALLBACK_SO_DIR"
else
    # Placed at the conventional path: drop a stale fallback copy from an
    # earlier read-only phase so exactly one .so exists on the host.
    rm -f "$FALLBACK_SO_DIR/$SO_NAME" 2>/dev/null
fi

# ---- 5. selinux ----
if command -v restorecon >/dev/null 2>&1; then
    restorecon -F "$DEST" 2>/dev/null || true
fi

[ "$MODULE_UNCHANGED" = 1 ] || echo "  installed: $DEST"

# ---- 7. auto-place load_module ----
# Drop into the distro-conventional main-scope include dir (=
# /etc/nginx/modules-enabled/, /usr/share/nginx/modules/ or
# /etc/nginx/modules/).  Otherwise edit nginx.conf and add the line at the top
# (= outside http {}).  This is so it works on every distro out of the box.
#
# Tag the directive so it's recognizable as package-managed when it lands in the
# host nginx.conf (= the no-include-dir fallback below): a config-management tool
# or operator reading nginx.conf sees it's auto-added, not a hand edit, and the
# package's removal takes out the line that carries the tag and no other
# (unwire_module).  One line, so no begin/end block is needed.
LOAD_LINE="load_module \"$DEST\";  $LOAD_TAG, removed on uninstall"
LOAD_DROPPED=""
# The conf this run wrote, for the note the removal reads (wired_record).
DROP_PLACED=""

# A line this package itself wrote into nginx.conf stays where it is, and no
# conf is put beside it: nginx refuses a module loaded twice.  That is where
# the line went on every host whose directory an earlier version did not find
# -- every Alpine install through 0.1.55 (see main_include_dir).  It is not
# moved into the directory either: a downgrade looks for the line where its
# own placer left it.  The block for a host without a directory, below, keeps
# the path in it current.
OWN_LINE=""
if grep -q "^[[:space:]]*load_module.*ngx_http_unmask_module.*$LOAD_TAG" "$NGINX_CONF" 2>/dev/null; then
    OWN_LINE=1
fi

if [ "$SELFBUILT_NGINX" = 1 ]; then
    # unmask's own directory, which that nginx includes -- or will: the last
    # lines of this run name the include to add.  Not the directory of the
    # first include its nginx.conf happens to carry (main_include_dir), which
    # there is as likely a stream block's as a place for modules.
    mkdir -p "$OWN_MAIN_DIR" 2>/dev/null && chmod 0755 "$OWN_NGINX_DIR" "$OWN_MAIN_DIR" 2>/dev/null
fi
if [ -r "$NGINX_CONF" ] || [ "$SELFBUILT_NGINX" = 1 ]; then
    if [ "$SELFBUILT_NGINX" = 1 ]; then
        INCLUDE_DIR=$OWN_MAIN_DIR
    else
        INCLUDE_DIR=$(main_include_dir)
    fi
    if [ -n "$INCLUDE_DIR" ] && [ -d "$INCLUDE_DIR" ] && [ -n "$OWN_LINE" ]; then
        # A conf of ours beside the line: one of the two has to go.
        rm -f "$INCLUDE_DIR/$LOAD_CONF" 2>/dev/null
    elif [ -n "$INCLUDE_DIR" ] && [ -d "$INCLUDE_DIR" ]; then
        DROP="$INCLUDE_DIR/$LOAD_CONF"
        # Idempotency across FOREIGN wiring, not just our own file.  An
        # operator may already load the module themselves -- a hand-added
        # line in nginx.conf (the docs used to show exactly that) or their
        # own conf in this include dir.  This script runs before EVERY nginx
        # start via the service drop-in, so unconditionally dropping ours
        # next to theirs makes nginx -t fail with "module is already
        # loaded", and the verify fail-safe below then strips the module --
        # a self-inflicted outage on a perfectly healthy setup.  Skip (and
        # remove a stale drop of ours) when any other load_module for this
        # module exists; overwriting OUR OWN previous drop stays fine (= the
        # normal re-pick path).
        FOREIGN=""
        if grep -q "load_module.*ngx_http_unmask_module" "$NGINX_CONF" 2>/dev/null; then
            FOREIGN="$NGINX_CONF"
        else
            for f in "$INCLUDE_DIR"/*.conf; do
                [ -f "$f" ] || continue
                [ "$f" = "$DROP" ] && continue
                if grep -q "load_module.*ngx_http_unmask_module" "$f" 2>/dev/null; then
                    FOREIGN="$f"
                    break
                fi
            done
        fi
        if [ -n "$FOREIGN" ]; then
            rm -f "$DROP" 2>/dev/null
            echo "  load_module already present in $FOREIGN (= operator-managed; idempotent skip)"
            if [ "$SELFBUILT_NGINX" = 1 ]; then
                echo "  note: that line names a file no upgrade keeps current.  In its place,"
                echo "        include $OWN_MAIN_DIR/*.conf;   follows every upgrade of unmask and of nginx."
            fi
        else
            echo "$LOAD_LINE" > "$DROP"
            chmod 0644 "$DROP"
            # SELinux: a file created by this script in the include dir can land
            # with the wrong type; relabel it so nginx (httpd_t) can read it.
            command -v restorecon >/dev/null 2>&1 && restorecon -F "$DROP" 2>/dev/null || true
            echo "  load_module conf: $DROP"
            DROP_PLACED=$DROP
        fi
        LOAD_DROPPED=1
    fi
fi

# (A line already there and right needs no write: an nginx.conf that cannot be
# written is then no reason for the warning below.)
if [ -z "$LOAD_DROPPED" ] && [ "$SELFBUILT_NGINX" != 1 ] && { [ -w "$NGINX_CONF" ] || grep -qF "load_module \"$DEST\"" "$NGINX_CONF" 2>/dev/null; }; then
    # No main-scope include dir found (= e.g. CentOS 6 nginx.org 1.18), or
    # the line is in nginx.conf from an earlier run -> edit nginx.conf
    # directly and idempotently add load_module at the top.
    if ! grep -q "load_module.*ngx_http_unmask_module" "$NGINX_CONF"; then
        # Insert at the very top of nginx.conf (= keep existing lines,
        # add load_module as line 1).
        # Atomic edit: build the new file in a sibling tmp + rename(2) so a
        # SIGKILL / power loss between truncate and write doesn't leave
        # nginx.conf empty or half-written (= next `nginx -t` would die).
        tmp="$NGINX_CONF.tmp.$$"
        {
            echo "$LOAD_LINE"
            cat "$NGINX_CONF"
        } > "$tmp" && {
            chmod 0644 "$tmp"
            mv -f "$tmp" "$NGINX_CONF"
            echo "  load_module added to: $NGINX_CONF (= at the top of main scope)"
            LOAD_DROPPED=1
        } || rm -f "$tmp"
    elif grep -qF "load_module \"$DEST\"" "$NGINX_CONF"; then
        echo "  load_module already present in $NGINX_CONF (= idempotent skip)"
        LOAD_DROPPED=1
    else
        # A line exists but points at a different .so path — the module moved
        # between the modules path and the immutable-/usr fallback dir.
        # Replace it, or nginx keeps loading a stale copy that can be
        # ABI-incompatible after the next host-nginx upgrade.
        tmp="$NGINX_CONF.tmp.$$"
        {
            echo "$LOAD_LINE"
            grep -v 'load_module.*ngx_http_unmask_module' "$NGINX_CONF"
        } > "$tmp" && {
            chmod 0644 "$tmp"
            mv -f "$tmp" "$NGINX_CONF"
            echo "  load_module path updated in: $NGINX_CONF (-> $DEST)"
        } || rm -f "$tmp"
        LOAD_DROPPED=1
    fi
fi

if [ -z "$LOAD_DROPPED" ]; then
    echo ""
    echo "  WARNING: could not auto-place load_module.  Add this by hand:"
    echo "             at the top of $NGINX_CONF (= outside http {})"
    echo "               $LOAD_LINE"
fi

# Where the module went and, when this run wrote one, the conf that loads it:
# the fail-safe and the package's removal take them away from there.
wired_record "$DEST" "$DROP_PLACED"

# Wire http.inc into http {} scope now that the native plugin .so is present.
# unmask-web-nginx also creates this symlink (gated on the .so), so doing it here
# too makes install order between the two packages irrelevant; http.inc carries
# the C-module directives + plugin-variable maps that only load with this .so.
if [ -e "$DEST" ]; then
    PINCDIR=/etc/nginx/conf.d
    if [ "$SELFBUILT_NGINX" = 1 ]; then
        PINCDIR=$OWN_HTTP_DIR
    elif [ -d /etc/nginx/http.d ] && [ -r /etc/nginx/nginx.conf ] && awk '
        /^[[:space:]]*http[[:space:]]*\{/ { in_http=1 }
        in_http && /include[[:space:]]+\/etc\/nginx\/http\.d\// { found=1 }
        /^\}/ { in_http=0 }
        END { exit !found }' /etc/nginx/nginx.conf; then
        PINCDIR=/etc/nginx/http.d
    fi
    mkdir -p "$PINCDIR" /var/lib/unmask/nginx
    # unmask's own directories for a self-built nginx are root's and readable,
    # whatever umask this ran under.
    [ "$SELFBUILT_NGINX" = 1 ] && chmod 0755 "$OWN_NGINX_DIR" "$OWN_HTTP_DIR" "$OWN_SO_DIR" 2>/dev/null
    PSRC=/var/lib/unmask/nginx/http.inc
    PLINK=$PINCDIR/00-unmask.conf
    [ -e "$PSRC" ] || : > "$PSRC"
    if [ ! -e "$PLINK" ] || { [ -L "$PLINK" ] && [ "$(readlink "$PLINK")" != "$PSRC" ]; }; then
        ln -sf "$PSRC" "$PLINK"
        echo "  http.inc auto-load symlinked: $PLINK -> $PSRC"
    fi
fi

# Final gate: now that the .so + load_module + http.inc are wired, make sure the
# result actually loads.  If unmask broke `nginx -t` (bad render, missing map,
# ABI surprise), strip the wiring so nginx still starts; a non-unmask failure is
# left for the operator.
verify_or_disable

if [ "$SELFBUILT_NGINX" = 1 ]; then
    # The build the module is now in place for.
    nginx_bin_note
    # In place for this build, with the include lines missing: that is what
    # the marker says from here on, not what took the module out before.
    if [ -e "$FAILSAFE_MARKER" ] && _pm_module_wired && ! _pm_scope_included; then
        _tl_miss=$(own_includes_missing | tr '\n' ' ')
        _tl_why="$NGINX_CONF does not include unmask's directories (missing: ${_tl_miss% }); the module is in place for nginx ${HOST_VER}"
        if _pm_http_included; then
            _pm_marker "$_tl_why"
        elif _pm_marker_inert; then
            _pm_marker "$_tl_why" inert
        else
            _pm_marker "$_tl_why" inert
            _pm_render || true
        fi
    fi
    # The two include lines, as long as one is missing.
    own_includes_say unmask-plugin-nginx
fi

echo ""
echo "next steps (= on the nginx side):"
echo "  1. (web-nginx package handles 'include /var/lib/unmask/nginx/http.inc' via a symlink)"
if [ "$MODULE_UNCHANGED" = 1 ]; then
    echo "  2. The module did not change, so nginx needs nothing for it; a reload applies config changes as usual."
elif [ "$SELFBUILT_NGINX" = 1 ]; then
    echo "  2. The module file changed: restart nginx (a reload keeps the old module), the way"
    echo "       this nginx is restarted -- its service, its init script or its panel."
else
    # nginx loads a module only at startup: a reload keeps running the old one.
    echo "  2. The module file changed: restart nginx (a reload keeps the old module) --"
    echo "       nginx -t && systemctl restart nginx"
fi
if [ "$SELFBUILT_NGINX" = 1 ]; then
    # nginx loads a module built for exactly its own version and options.  A
    # distribution's nginx is started by a unit this package hooks into, and
    # the module is picked again before every start.  This one may be built
    # again and tested by whatever built it before any service starts it: the
    # watch on its binary takes unmask out for that (--nginx-changed).
    if [ -d "$SYSTEMD_RUN_DIR" ] && [ -f "$WATCH_UNIT" ]; then
        echo "  3. When this nginx is built again -- another version, other options, by hand or by a panel --"
        echo "     unmask takes its module out the moment the binary changes (unmask-nginx-binary.path), so the new"
        echo "     build loads its configuration; the module for that build is placed before nginx's service starts."
        echo "     Started some other way, run   sh $PLUGIN_BASE/place-module.sh   once it is built."
    else
        echo "  3. When this nginx is built again -- another version, other options -- run"
        echo "       sh $PLUGIN_BASE/place-module.sh"
        echo "     BEFORE it is started: it places the module for the new build, or takes"
        echo "     the module out when there is none, so that nginx starts either way."
    fi
fi

exit 0
