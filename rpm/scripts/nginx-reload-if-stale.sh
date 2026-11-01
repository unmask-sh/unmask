#!/bin/sh
# nginx-reload-if-stale.sh -- reload nginx when the daemon rendered a changed
# configuration that nginx has not loaded yet.
#
# unmask never reloads a running nginx on its own: a settings save renders
# the configuration to disk, and the admin shows a notice until the operator
# reloads.  This script is that reload, for an operator who chooses to
# delegate it.  The package ships it with unmask-nginx-reload.timer, which
# runs it every five minutes -- installed DISABLED, enabled by the operator
# with `systemctl enable --now unmask-nginx-reload.timer`.  Without systemd,
# run it from cron.
#
# What it does:
#   - Nothing unless <output_dir>/.reload-needed exists.  The daemon writes
#     that file (one line, the render id) when a render changed a file, and
#     removes it once nginx logs under the new id.
#   - Nothing when the last reload from here was less than ten minutes ago:
#     the next run picks it up.
#   - Nothing, but a journal line asking for a restart, while the nginx
#     master still maps a shared library that an OS update has since replaced
#     on disk.  A reload keeps that master, and the workers it forks inherit
#     the stale mapping and crash on it; only a restart leaves it behind.
#   - `nginx -t`, and only when that passes, `systemctl reload nginx`
#     (`nginx -s reload` where there is no systemd).
#   - One line to the journal (logger) for every run that found the file.
#
# A changed module (.so) is not handled either: that takes a restart, and
# this script never restarts nginx.
#
# Environment (for a relocated install, and the test):
#   UNMASK_NGINX_DIR   the render output directory (default /var/lib/unmask/nginx)
#   UNMASK_RELOAD_MIN  minutes between two reloads from here (default 10)
#   UNMASK_NGINX_MAPS  the memory map read for replaced libraries (default
#                      /proc/<nginx master pid>/maps; the test names a file)

NGINX_DIR=${UNMASK_NGINX_DIR:-/var/lib/unmask/nginx}
MIN_MINUTES=${UNMASK_RELOAD_MIN:-10}
FLAG="$NGINX_DIR/.reload-needed"
# The time of the last reload: in the daemon's runtime directory while it
# exists (tmpfs, gone with a boot, when nothing is waiting either), else
# beside the rendered files.
if [ -d /run/unmask ] && [ -w /run/unmask ]; then
    STAMP=/run/unmask/.last-nginx-reload
else
    STAMP="$NGINX_DIR/.last-reload"
fi

say() {
    if command -v logger >/dev/null 2>&1; then
        logger -t unmask-nginx-reload -- "$*"
    fi
    echo "unmask-nginx-reload: $*"
}

# nginx_master_pid: the pid file nginx writes (its path differs by
# distribution), else the unit's main process under systemd, else the oldest
# nginx process.  Empty when none of them answers.
nginx_master_pid() {
    for f in /run/nginx.pid /var/run/nginx.pid /run/nginx/nginx.pid /var/run/nginx/nginx.pid; do
        [ -f "$f" ] || continue
        p=$(tr -cd '0-9' < "$f" 2>/dev/null)
        if [ -n "$p" ] && [ -d "/proc/$p" ]; then echo "$p"; return; fi
    done
    if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
        p=$(systemctl show -p MainPID nginx 2>/dev/null | sed 's/^MainPID=//' | tr -cd '0-9')
        if [ -n "$p" ] && [ "$p" != 0 ] && [ -d "/proc/$p" ]; then echo "$p"; return; fi
    fi
    if command -v pgrep >/dev/null 2>&1; then
        pgrep -o -x nginx 2>/dev/null | head -n 1
    fi
}

# replaced_libraries: the shared libraries the master maps whose file on disk
# has since been replaced -- "(deleted)" in its memory map -- one basename per
# line.  nginx's shared-memory zones appear there as "/dev/zero (deleted)",
# which is normal and not a library.  Empty when the map cannot be found or
# read: nothing is refused on a guess.
replaced_libraries() {
    maps=${UNMASK_NGINX_MAPS:-}
    if [ -z "$maps" ]; then
        pid=$(nginx_master_pid)
        [ -n "$pid" ] || return 0
        maps="/proc/$pid/maps"
    fi
    grep '(deleted)' "$maps" 2>/dev/null | awk '$6 ~ /\.so(\.|$)/ {print $6}' | sed 's|.*/||' | sort -u
}

[ -f "$FLAG" ] || exit 0
render_id=$(head -n 1 "$FLAG" 2>/dev/null | tr -cd '0-9a-f')

# Recently reloaded from here: wait for the next run.  The flag stays for
# it -- the daemon removes it when nginx logs the new render id.
if [ -f "$STAMP" ]; then
    last=$(stat -c %Y "$STAMP" 2>/dev/null || echo 0)
    now=$(date +%s)
    if [ "$now" -lt $((last + MIN_MINUTES * 60)) ]; then
        say "render $render_id is waiting; the last reload was $(( (now - last) / 60 )) min ago, next run"
        exit 0
    fi
fi

if ! command -v nginx >/dev/null 2>&1; then
    say "render $render_id is waiting but nginx is not installed here; nothing to reload"
    exit 0
fi
# A master on replaced libraries is a restart matter, which this script
# never does: it says so and leaves nginx as it is.  The flag stays, and the
# next run after the restart reloads if anything is still waiting.
libs=$(replaced_libraries)
if [ -n "$libs" ]; then
    n=$(printf '%s\n' "$libs" | wc -l | tr -d ' ')
    named=$(printf '%s\n' "$libs" | head -n 3 | tr '\n' ' ' | sed 's/ $//')
    say "render $render_id is waiting but nginx's master still maps $n shared library file(s) replaced on disk ($named): a reload would fork workers onto the old copies -- restart nginx instead (systemctl restart nginx)"
    exit 1
fi
if ! nginx -t >/dev/null 2>&1; then
    say "render $render_id is waiting but nginx -t fails; not reloaded (run nginx -t to see why)"
    exit 1
fi
if [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; then
    how="systemctl reload nginx"
    systemctl reload nginx
else
    how="nginx -s reload"
    nginx -s reload
fi
rc=$?
if [ "$rc" -ne 0 ]; then
    say "render $render_id: $how failed ($rc)"
    exit "$rc"
fi
: > "$STAMP"
say "render $render_id: nginx -t passed, nginx reloaded ($how)"
exit 0
