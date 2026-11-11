#!/bin/bash
# Test for unmask-web-nginx's package scripts: the SELinux runtime-label
# drop-in across an install, an upgrade and a removal
# (postinstall-web-nginx.sh, postremove-web-nginx.sh), and the setup banner.
#
# On an SELinux host without semanage, nginx (httpd_t) can write the daemon's
# log socket only while /run/unmask carries httpd_var_run_t.  systemd recreates
# that directory on every start of unmask.service (RuntimeDirectory=), so a
# drop-in re-applies the label after each start.  Three things an install
# cannot show you until it is too late to matter:
#
#   - This package never restarts the daemon.  The unmask package restarts it
#     once in the same transaction; a second restart from here killed that
#     start part way, with any schema update it was applying.
#   - The drop-in survives an upgrade.  rpm runs the OLD package's postremove
#     after the NEW package's postinstall, and a postremove that removed the
#     drop-in whatever its arguments said deleted what the postinstall had
#     just written: the label was gone from the daemon's next start.
#   - An upgrade that finds the drop-in as it should be leaves it alone.
#
# And the setup banner -- forty lines, with the setup token -- comes only
# while the setup is still to be done, and shows the token where the unmask
# package writes it.  It used to come on every upgrade, after everything the
# unmask package had printed, and never found the token.
#
# The scripts are run for real, against a throwaway root: copies with their
# absolute paths pointed into a temporary directory, and a PATH that holds
# recording stand-ins for the commands they call.  No SELinux, no VM, no root.
#
# Run: bash rpm/scripts/postinstall-web-nginx_test.sh
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
fails=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails+1)); }
check() { # <desc> <expected> <actual>
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected=\"$2\" got=\"$3\")"; fi
}

# new_root <getenforce answer> <extra tools: "semanage", "chcon"> <systemd version>
# A throwaway root in $T, with the scripts copied in and pointed at it.
new_root() {
    local enforce="$1" tools="$2" sdver="$3" c p
    T=$(mktemp -d)
    mkdir -p "$T/stub" "$T/tools" "$T/etc/unmask" "$T/etc/nginx/conf.d" "$T/var/lib/unmask/nginx" \
             "$T/run/unmask" "$T/etc/systemd/system" "$T/usr/share/unmask" "$T/modules"
    : > "$T/calls.log"
    : > "$T/etc/nginx/nginx.conf"
    printf 'server:\n  port: 9477\n' > "$T/etc/unmask/config.yml"
    # stub <name> [body]: records "name args" and runs body (default: exit 0).
    stub() {
        printf '#!/bin/sh\necho "%s $*" >> "%s/calls.log"\n%s\n' "$1" "$T" "${2:-exit 0}" > "$T/stub/$1"
        chmod +x "$T/stub/$1"
    }
    stub getenforce "echo $enforce"
    stub getsebool 'echo "httpd_can_network_connect --> on"'
    stub setsebool
    stub restorecon
    stub hostname 'echo test-host'
    stub systemctl "case \"\$1\" in --version) echo 'systemd $sdver (test)' ;; esac; exit 0"
    # --conf-path as every distribution's nginx names it: without it the
    # scripts take the nginx for a self-built one and leave /etc/nginx alone
    # (nginx-layout).
    stub nginx "case \"\$1\" in -V) echo 'configure arguments: --conf-path=$T/etc/nginx/nginx.conf --modules-path=$T/modules' >&2 ;; esac; exit 0"
    for c in $tools; do stub "$c"; done
    # What the scripts need from the system, and nothing else: no real
    # systemctl, chcon or semanage may be reachable from here.
    for c in awk cat grep sed ln rm rmdir mkdir chmod dirname tr head readlink sort; do
        p=$(command -v "$c") && ln -s "$p" "$T/tools/$c"
    done
    for s in postinstall-web-nginx.sh postremove-web-nginx.sh; do
        sed -e "s|/var/lib/unmask|$T/var/lib/unmask|g" \
            -e "s|/etc/nginx|$T/etc/nginx|g" \
            -e "s|/etc/unmask|$T/etc/unmask|g" \
            -e "s|/etc/systemd/system|$T/etc/systemd/system|g" \
            -e "s|/run/unmask|$T/run/unmask|g" \
            -e "s|/run/nginx|$T/run/nginx|g" \
            -e "s|/usr/share/unmask|$T/usr/share/unmask|g" \
            -e "s|/lib/apk|$T/lib/apk|g" \
            "$DIR/$s" > "$T/$s"
    done
    DROPIN="$T/etc/systemd/system/unmask.service.d/10-unmask-selinux-runtime.conf"
}
# The package's postinstall / postremove, as the package manager calls them.
post()   { : > "$T/calls.log"; PATH="$T/stub:$T/tools" /bin/sh "$T/postinstall-web-nginx.sh" "$@" > "$T/out" 2>&1; }
postrm() { : > "$T/calls.log"; PATH="$T/stub:$T/tools" /bin/sh "$T/postremove-web-nginx.sh" "$@" > "$T/out" 2>&1; }

restarts() { grep -cE '^systemctl (restart|try-restart|start|reload-or-restart|condrestart|try-reload-or-restart) unmask' "$T/calls.log"; }
reloads()  { grep -c '^systemctl daemon-reload' "$T/calls.log"; }
called()   { grep -cE "$1" "$T/calls.log"; }
has_dropin() { [ -f "$DROPIN" ] && grep -q '^ExecStartPost=+' "$DROPIN" && echo yes || echo no; }

# --- an rpm install, then an upgrade, of a host without semanage -------------
new_root Enforcing chcon 252
post 1
check "install: the running daemon's directory is labelled now" 1 "$(called "^chcon -R -t httpd_var_run_t $T/run/unmask\$")"
check "install: the drop-in is written" yes "$(has_dropin)"
check "install: systemd is told about it" 1 "$(reloads)"
check "install: the daemon is not restarted (the label is already on)" 0 "$(restarts)"
cp "$DROPIN" "$T/dropin.written"

# The upgrade, in rpm's order: the new package's postinstall, then the old
# package's postremove with $1 = 1.
post 2
check "upgrade: the daemon is not restarted" 0 "$(restarts)"
check "upgrade: a drop-in already as it should be is not rewritten (no daemon-reload)" 0 "$(reloads)"
if [ "$(cat "$DROPIN")" = "$(cat "$T/dropin.written")" ]; then pass "upgrade: the drop-in is unchanged"; else fail "upgrade: the drop-in is unchanged"; fi
postrm 1
check "upgrade: the old package's postremove leaves the drop-in in place" yes "$(has_dropin)"
check "upgrade: the old package's postremove does not reload systemd" 0 "$(reloads)"
check "upgrade: ...nor restart the daemon" 0 "$(restarts)"
# It used to end every upgrade with "snippet removed.  remember to: sudo nginx
# -s reload" -- of a snippet that was still there.
check "upgrade: ...and has nothing to say about a removal" "" "$(cat "$T/out")"

# The same on Debian: the old package's postrm is called with "upgrade".
postrm upgrade
check "deb upgrade: the drop-in stays" yes "$(has_dropin)"

# Removal: rpm $1 = 0.
postrm 0
check "rpm erase: the drop-in is removed" no "$(has_dropin)"
check "rpm erase: systemd is told" 1 "$(reloads)"
check "rpm erase: the emptied drop-in directory is removed" no "$([ -d "$T/etc/systemd/system/unmask.service.d" ] && echo yes || echo no)"
# What the removal leaves is uninstall_test.sh's; here, that it asks nginx and
# leaves it alone.
check "rpm erase: nginx -t is run, and its answer printed" "1 1" "$(called '^nginx -t$') $(grep -c "unmask-web-nginx: 'nginx -t' passes." "$T/out")"
check "rpm erase: nginx is not reloaded" 0 "$(called '^nginx -s|^systemctl .*nginx')"
rm -rf "$T"

# --- a drop-in from an earlier version is brought up to date ---------------------
new_root Enforcing chcon 252
mkdir -p "$(dirname "$DROPIN")"
printf '[Service]\nExecStartPost=+/bin/true\n' > "$DROPIN"
post 2
check "outdated drop-in: rewritten" 1 "$(grep -c 'chcon -R -t httpd_var_run_t' "$DROPIN")"
check "outdated drop-in: systemd is told" 1 "$(reloads)"
check "outdated drop-in: the daemon is not restarted" 0 "$(restarts)"
rm -rf "$T"

# --- dpkg purge removes it too ------------------------------------------------
new_root Enforcing chcon 252
post configure
postrm purge
check "dpkg purge: the drop-in is removed" no "$(has_dropin)"
rm -rf "$T"

# --- semanage available: the policy rule replaces the drop-in -------------------
new_root Enforcing "semanage chcon" 252
mkdir -p "$(dirname "$DROPIN")"
printf '[Service]\nExecStartPost=+/bin/true\n' > "$DROPIN"
post 2
check "semanage: the fcontext rule is added" 1 "$(called '^semanage fcontext -a -t httpd_var_run_t ')"
check "semanage: the running daemon's directory is relabelled" 1 "$(called "^restorecon -RF $T/run/unmask\$")"
check "semanage: an earlier chcon drop-in is removed" no "$([ -f "$DROPIN" ] && echo yes || echo no)"
check "semanage: systemd is told the drop-in went" 1 "$(reloads)"
check "semanage: the daemon is not restarted" 0 "$(restarts)"
post 2
check "semanage, again: nothing to tell systemd" 0 "$(reloads)"
rm -rf "$T"

# --- systemd too old for ExecStartPost=+ (RHEL 7) --------------------------------
new_root Enforcing chcon 219
post 2
check "systemd 219: the directory is labelled now" 1 "$(called '^chcon -R -t httpd_var_run_t ')"
check "systemd 219: no drop-in (it cannot be expressed)" no "$(has_dropin)"
check "systemd 219: the operator is told the label will not last" 1 "$(grep -c 'systemd is too old for the drop-in' "$T/out")"
check "systemd 219: the daemon is not restarted" 0 "$(restarts)"
rm -rf "$T"

# --- SELinux not enforcing: nothing of this happens -----------------------------
new_root Permissive chcon 252
post 1
check "permissive: no relabel" 0 "$(called '^chcon ')"
check "permissive: no drop-in" no "$(has_dropin)"
check "permissive: systemd is not touched" 0 "$(called '^systemctl ')"
rm -rf "$T"

# --- the setup banner ----------------------------------------------------------
new_root Permissive "" 252
printf 'f00dfacecafe\n' > "$T/var/lib/unmask/.setup-token"
post 1
check "a new install: the setup banner" 1 "$(grep -c 'unmask — initial setup' "$T/out")"
check "a new install: the token, from where the unmask package writes it" 1 "$(grep -c 'Setup token:       f00dfacecafe' "$T/out")"
rm -f "$T/var/lib/unmask/.setup-token"
post 2
check "an upgrade after the setup: no banner" 0 "$(grep -c 'initial setup' "$T/out")"
check "an upgrade after the setup: the script still ends well" 0 "$(grep -c 'nginx -t. did NOT pass' "$T/out")"
printf 'legacytoken\n' > "$T/etc/unmask/.setup-token"
post 2
check "a token at the pre-0.1.9 path: the banner, with it" 1 "$(grep -c 'Setup token:       legacytoken' "$T/out")"
rm -rf "$T"

# --- the banner names the include that works on this host ----------------------
# Without the module: the native module is what to install, and the
# forward-auth include is the way in until then.
new_root Permissive "" 252
printf 'f00dfacecafe\n' > "$T/var/lib/unmask/.setup-token"
post 1
check "no module: [1] is the native module" 1 "$(grep -c '\[1\] Recommended — the native nginx module' "$T/out")"
check "no module: the native include is named" 1 "$(grep -c "include $T/var/lib/unmask/nginx/server.inc;" "$T/out")"
check "no module: the forward-auth include is the way in meanwhile" 1 "$(grep -c "include $T/etc/unmask/forward-auth/server.inc;" "$T/out")"
check "no module: the protect line is forward-auth's" 1 "$(grep -c "include $T/etc/unmask/forward-auth/protect.inc;  # fires" "$T/out")"
rm -rf "$T"
# With the module (unmask-plugin-nginx placed its .so): the native include is
# [1], and forward-auth is named once as the other path.
new_root Permissive "" 252
printf 'f00dfacecafe\n' > "$T/var/lib/unmask/.setup-token"
: > "$T/modules/ngx_http_unmask_module.so"
post 1
check "module: [1] adds the native include" 1 "$(grep -c '\[1\] Recommended — add 1 line' "$T/out")"
check "module: the native include comes first" 1 "$(grep -c "^            include $T/var/lib/unmask/nginx/server.inc;" "$T/out")"
check "module: forward-auth is named once, as the other way" 1 "$(grep -c "include $T/etc/unmask/forward-auth/server.inc;" "$T/out")"
check "module: the protect line is the native one" 1 "$(grep -c "include $T/var/lib/unmask/nginx/protect.inc;  # fires" "$T/out")"
check "module: no line calls forward-auth recommended" 0 "$(grep -c 'Recommended.*forward-auth' "$T/out")"
rm -rf "$T"

# --- a host without nginx ----------------------------------------------------
# The rpm and deb packages install none, so the script meets this state: it
# wires where a packaged nginx reads, says so, and claims nothing about a
# module it has no nginx to look in for.
new_root Permissive "" 252
rm -f "$T/stub/nginx"
printf 'f00dfacecafe\n' > "$T/var/lib/unmask/.setup-token"
post 1; rc=$?
check "no nginx: the script ends well" 0 "$rc"
check "no nginx: it says so" 1 "$(grep -c 'unmask-web-nginx: no nginx command on this host yet' "$T/out")"
check "no nginx: the upstream is wired where a packaged nginx reads it" "$T/var/lib/unmask/nginx/upstream.conf" "$(readlink "$T/etc/nginx/conf.d/00-unmask-upstream.conf" 2>/dev/null)"
check "no nginx: http.inc is left unwired (nothing loads the module yet)" no "$([ -e "$T/etc/nginx/conf.d/00-unmask.conf" ] && echo yes || echo no)"
check "no nginx: nothing is said about forward-auth mode" 0 "$(grep -c 'forward-auth mode (http.inc left unwired)' "$T/out")"
check "no nginx: the banner says what [1] waits for" 1 "$(grep -c 'No nginx command on this host yet' "$T/out")"
check "no nginx, no plugin: [1] is the native module" 1 "$(grep -c '\[1\] Recommended — the native nginx module' "$T/out")"
rm -rf "$T"
# With unmask-plugin-nginx installed (its placer is there) the module follows
# the nginx, so the native include is the one the banner names.
new_root Permissive "" 252
rm -f "$T/stub/nginx"
printf 'f00dfacecafe\n' > "$T/var/lib/unmask/.setup-token"
mkdir -p "$T/usr/share/unmask/plugin" && : > "$T/usr/share/unmask/plugin/place-module.sh"
post 1; rc=$?
check "no nginx, plugin installed: the script ends well" 0 "$rc"
check "no nginx, plugin installed: [1] adds the native include" 1 "$(grep -c '\[1\] Recommended — add 1 line' "$T/out")"
check "no nginx, plugin installed: the protect line is the native one" 1 "$(grep -c "include $T/var/lib/unmask/nginx/protect.inc;  # fires" "$T/out")"
rm -rf "$T"
# With an nginx, the banner says nothing of the kind.
new_root Permissive "" 252
printf 'f00dfacecafe\n' > "$T/var/lib/unmask/.setup-token"
post 1
check "with an nginx: no word about a missing one" 0 "$(grep -ci 'no nginx command on this host' "$T/out")"
rm -rf "$T"

echo
if [ "$fails" -gt 0 ]; then
    echo "postinstall-web-nginx_test: $fails FAILED"
    exit 1
fi
echo "postinstall-web-nginx_test: all passed"
