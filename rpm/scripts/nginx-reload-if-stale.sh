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
#   - `nginx -t`, and only when that passes, `systemctl reload nginx`
#     (`nginx -s reload` where there is no systemd).
#   - One line to the journal (logger) for every run that found the file.
#
# A changed module (.so) is not handled: that takes a restart, and this
# script never restarts nginx.
#
# Environment (for a relocated install, and the test):
#   UNMASK_NGINX_DIR   the render output directory (default /var/lib/unmask/nginx)
#   UNMASK_RELOAD_MIN  minutes between two reloads from here (default 10)

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
