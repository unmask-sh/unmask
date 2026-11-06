#!/bin/sh
# unmask-web-nginx postremove.  Takes the links the postinstall created out of
# nginx's http block, then says what that leaves for the operator: the lines
# of their own server blocks that include unmask's files, and whether nginx
# still loads its configuration.
# We do NOT auto-reload (= the file may still exist via rpm/deb type=config|noreplace).

# Remove the symlinks the postinstall created (= prevents dangling links), but
# ONLY on a genuine uninstall — not on upgrade/reinstall.  rpm runs the OLD
# package's %postun *after* the new package's %post during an upgrade, so an
# unconditional rm here would delete the symlinks the new %post just created.
# rpm passes $1=0 on final removal ($1>=1 on upgrade); dpkg passes
# "remove"/"purge" on removal and "upgrade" on upgrade.
# Decide whether this invocation is a real removal (= clean symlinks) or an
# upgrade / reinstall (= keep them so the new %post-created links are not
# nuked).  Argument conventions vary:
#   rpm:   $1 = "0" on final remove, "1..." on upgrade
#   dpkg:  $1 = "remove" / "purge" on remove, "upgrade" on upgrade
#   apk:   $1 = the package version string (= "0.1.0"); there is no built-in
#          upgrade distinction at this hook since apk has separate pre/post-
#          upgrade hooks, so post-deinstall here always means uninstall.
#
# What is left is said once, at the removal: dpkg calls this again for the
# purge that follows a remove, with nothing new to say.  And never on an
# upgrade -- this used to end every upgrade with "snippet removed", of a
# snippet that was still there.
do_cleanup=0
do_report=0
if [ -d /lib/apk ]; then
    # apk hosts: post-deinstall is uninstall-only by spec.
    do_cleanup=1
    do_report=1
else
    case "${1:-}" in
        0|remove) do_cleanup=1; do_report=1 ;;
        purge)    do_cleanup=1 ;;
    esac
fi

NGINX_CONF=/etc/nginx/nginx.conf

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

# Whether this removal is the one that takes http.inc out of nginx (see below).
HAD_HTTP_INC=0

if [ "$do_cleanup" = 1 ]; then
    rm -f /etc/nginx/conf.d/00-unmask-maphash.conf /etc/nginx/http.d/00-unmask-maphash.conf
    sed -i '/unmask-maphash/d' /etc/nginx/nginx.conf 2>/dev/null || true
    for link in /etc/nginx/conf.d/00-unmask.conf \
                /etc/nginx/conf.d/00-unmask-upstream.conf \
                /etc/nginx/conf.d/zz-unmask-fa-lbtrust.conf \
                /etc/nginx/conf.d/00-unmask-fa-lbtrust.conf \
                /etc/nginx/conf.d/00-unmask-rendered.conf \
                /etc/nginx/http.d/00-unmask.conf \
                /etc/nginx/http.d/00-unmask-upstream.conf \
                /etc/nginx/http.d/zz-unmask-fa-lbtrust.conf \
                /etc/nginx/http.d/00-unmask-fa-lbtrust.conf \
                /etc/nginx/http.d/00-unmask-rendered.conf; do
        if [ -L "$link" ]; then
            case "$link" in
                */00-unmask.conf) HAD_HTTP_INC=1 ;;
            esac
            rm -f "$link"
        fi
    done

    # The SELinux runtime-label drop-in exists only to let nginx (httpd_t)
    # write the daemon's log socket, so it has no reason to outlive this
    # package.  postinstall writes it only where semanage is unavailable;
    # removing it when it is absent is a no-op.
    #
    # On an uninstall only, like the links above.  It used to sit outside this
    # block, so every rpm upgrade deleted it: rpm runs the old package's
    # postremove after the new one's postinstall has written it, and from the
    # daemon's next start (or the next boot) nginx could no longer write the
    # log socket -- native mode recorded zero events again.
    UNMASK_SELINUX_DROPIN=/etc/systemd/system/unmask.service.d/10-unmask-selinux-runtime.conf
    if [ -f "$UNMASK_SELINUX_DROPIN" ]; then
        rm -f "$UNMASK_SELINUX_DROPIN"
        rmdir /etc/systemd/system/unmask.service.d 2>/dev/null || true
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
fi

if [ "$do_report" = 1 ]; then
    # The operator's own server blocks still include unmask's files, which
    # the data-is-kept rule leaves on disk -- but the upstream and the maps
    # they name were in the links removed above, so nginx stops at them.
    #
    # The forward-auth snippets are this package's, and always named.  The
    # module's server.inc / protect.inc are named by whichever package takes
    # http.inc out of nginx: this one when the link was still there, and
    # unmask-plugin-nginx when it went first (its preremove removes the link
    # with the module, and lists them).  So each line is listed once,
    # whichever order the packages go in.
    LEFT_RE='/etc/unmask/forward-auth/(server|protect)[.]inc'
    if [ "$HAD_HTTP_INC" = 1 ]; then
        LEFT_RE='(/var/lib/unmask/nginx|/etc/unmask/forward-auth)/(server|protect)[.]inc'
    fi
    LEFT=$(unmask_include_lines "$LEFT_RE")
    if [ -n "$LEFT" ]; then
        echo "unmask-web-nginx: your nginx configuration still includes files that nginx cannot read without this package."
        echo "  Remove these lines before the next nginx reload or restart:"
        printf '%s\n' "$LEFT"
    fi
    if command -v nginx >/dev/null 2>&1; then
        if nginx_t_report unmask-web-nginx; then
            # Do NOT reload/restart nginx here -- touching the running web
            # server is the operator's call, as in the postinstall.
            echo "  → nginx was NOT reloaded.  Apply when you choose:  sudo nginx -s reload"
            echo "    (a restart instead, if unmask-plugin-nginx was removed as well:  sudo systemctl restart nginx)"
        fi
    fi
fi

exit 0
