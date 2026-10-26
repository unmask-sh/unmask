#!/bin/bash
# Test for nginx-reload-if-stale.sh, the script unmask-nginx-reload.timer runs:
# nothing without the daemon's .reload-needed flag, no reload while nginx -t
# fails, a reload through systemctl (nginx -s reload without systemd) when it
# passes, no second reload within ten minutes, and never a restart.
#
# The script is run for real against a throwaway directory, with a PATH that
# holds recording stand-ins for nginx, systemctl and logger.  No root, no nginx.
#
# Run: bash rpm/scripts/nginx-reload-if-stale_test.sh
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT="$DIR/nginx-reload-if-stale.sh"
fails=0
pass() { printf 'PASS  %s\n' "$1"; }
fail() { printf 'FAIL  %s\n' "$1"; fails=$((fails+1)); }
check() { # <desc> <expected> <actual>
    if [ "$2" = "$3" ]; then pass "$1"; else fail "$1 (expected=\"$2\" got=\"$3\")"; fi
}

# new_root <nginx -t exit code> <with systemd: 1/0>
new_root() {
    T=$(mktemp -d)
    mkdir -p "$T/stub" "$T/nginx"
    : > "$T/calls.log"
    stub() { # <name> [body]
        printf '#!/bin/sh\necho "%s $*" >> "%s/calls.log"\n%s\n' "$1" "$T" "${2:-exit 0}" > "$T/stub/$1"
        chmod +x "$T/stub/$1"
    }
    stub nginx "case \"\$1\" in -t) exit $1 ;; esac; exit 0"
    stub systemctl
    stub logger
    SYSTEMD=$2
}
# run: the script with the throwaway root; systemd is detected through
# /run/systemd/system, which the test cannot create, so the no-systemd case
# is the one a developer machine without it gives, and the systemd case is
# asserted on the command the script picks when the directory is there.
run() {
    # The stand-ins first, then the system's own tools -- not /usr/sbin, so a
    # real nginx there is not found where the test removed the stand-in.
    PATH="$T/stub:/usr/bin:/bin" UNMASK_NGINX_DIR="$T/nginx" UNMASK_RELOAD_MIN=10 sh "$SCRIPT" >"$T/out" 2>&1
    echo $?
}
called() { grep -c "$1" "$T/calls.log"; }
# The reload commands alone: the journal lines say "reloaded" too.
reloads() { grep -cE '^(systemctl reload nginx|nginx -s reload)$' "$T/calls.log"; }
has_systemd() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

# --- 1. no flag: nothing happens, nothing is logged -------------------------
new_root 0 1
check "no flag: exit 0" 0 "$(run)"
check "no flag: nginx not called" 0 "$(called '^nginx')"
check "no flag: nothing logged" 0 "$(called '^logger')"
rm -rf "$T"

# --- 2. flag, nginx -t fails: no reload, exit 1, one journal line -----------
new_root 1 1
echo "0123456789ab" > "$T/nginx/.reload-needed"
check "nginx -t fails: exit 1" 1 "$(run)"
check "nginx -t fails: nginx -t was run" 1 "$(called '^nginx -t')"
check "nginx -t fails: no reload" 0 "$(reloads)"
check "nginx -t fails: one journal line" 1 "$(called '^logger')"
check "nginx -t fails: the line names the render" 1 "$(grep -c '0123456789ab' "$T/calls.log")"
check "nginx -t fails: the flag is left for the daemon" 1 "$([ -f "$T/nginx/.reload-needed" ] && echo 1 || echo 0)"
rm -rf "$T"

# --- 3. flag, nginx -t passes: one reload, never a restart ------------------
new_root 0 1
echo "0123456789ab" > "$T/nginx/.reload-needed"
check "nginx -t passes: exit 0" 0 "$(run)"
if has_systemd; then
    check "nginx -t passes: systemctl reload nginx" 1 "$(called '^systemctl reload nginx$')"
    check "nginx -t passes: not nginx -s reload under systemd" 0 "$(called '^nginx -s reload')"
else
    check "nginx -t passes: nginx -s reload (no systemd here)" 1 "$(called '^nginx -s reload$')"
fi
check "nginx -t passes: no restart" 0 "$(called 'restart')"
check "nginx -t passes: one reload" 1 "$(reloads)"
check "nginx -t passes: one journal line" 1 "$(called '^logger')"
check "nginx -t passes: the flag is left for the daemon to clear" 1 "$([ -f "$T/nginx/.reload-needed" ] && echo 1 || echo 0)"
stamp="$T/nginx/.last-reload"; [ -d /run/unmask ] && [ -w /run/unmask ] && stamp=/run/unmask/.last-nginx-reload
check "nginx -t passes: the time of the reload is kept" 1 "$([ -f "$stamp" ] && echo 1 || echo 0)"

# --- 4. a second run within ten minutes waits ------------------------------
check "within ten minutes: exit 0" 0 "$(run)"
check "within ten minutes: no second reload" 1 "$(reloads)"
check "within ten minutes: says so once" 2 "$(called '^logger')"

# --- 5. ten minutes later the reload happens again -------------------------
touch -d '-11 minutes' "$stamp" 2>/dev/null || touch -t "$(date -d '-11 minutes' +%Y%m%d%H%M.%S)" "$stamp"
check "ten minutes later: exit 0" 0 "$(run)"
check "ten minutes later: a second reload" 2 "$(reloads)"
[ "$stamp" = /run/unmask/.last-nginx-reload ] && rm -f "$stamp"
rm -rf "$T"

# --- 6. no nginx on the host: nothing to reload, exit 0 --------------------
new_root 0 1
rm -f "$T/stub/nginx"
echo "0123456789ab" > "$T/nginx/.reload-needed"
if PATH="/usr/bin:/bin" command -v nginx >/dev/null 2>&1; then
    pass "no nginx: skipped (this host has nginx in /usr/bin)"
else
    check "no nginx: exit 0" 0 "$(run)"
    check "no nginx: no reload" 0 "$(reloads)"
    check "no nginx: one journal line" 1 "$(called '^logger')"
fi
rm -rf "$T"

echo "nginx-reload-if-stale: $fails failure(s)"
exit $fails
