#!/bin/sh
# unmask-web-nginx postinstall.
#
# Role:
#   1. Place upstream auto-load symlinks in /etc/nginx/conf.d/
#       00-unmask-upstream.conf -> /var/lib/unmask/nginx/upstream.conf
#         (= so proxy_pass http://unmask_admin; resolves in every server block. shared by both modes)
#       00-unmask.conf          -> /var/lib/unmask/nginx/http.inc
#         (= JA4 maps / log_format etc.  native-mode only.  In environments
#            without the plugin, the target is not rendered but nginx -t still
#            passes; include only emits a warning.)
#   2. Validate syntax with nginx -t and attempt reload
#   3. Print the setup wizard URL + token

echo "unmask-web-nginx: installing nginx integration..."

# upstream auto-load.  Forward-auth mode's server.inc does `proxy_pass
# http://unmask_admin;`, so that upstream must exist in http {} scope.  Native
# mode defines its own `upstream unmask` inside the rendered http.inc; for
# forward-auth (no plugin, no http.inc) `unmask render-nginx` renders
# `upstream unmask_admin` to /var/lib/unmask/nginx/upstream.conf and tracks
# server.bind / port there.  Write a default-port block here too so the upstream
# resolves before the first render (install order / pre-setup); render overwrites
# it on the first settings save.
UPSTREAM_SRC=/var/lib/unmask/nginx/upstream.conf
[ -d /var/lib/unmask/nginx ] || mkdir -p /var/lib/unmask/nginx
# Follow server.port from config.yml (default 9477) so the upstream tracks a
# non-default admin port instead of hard-coding it.  Scoped to the top-level
# `server:` block so an unrelated `port:` (e.g. mariadb) is never picked up.
UNMASK_PORT=$(awk '
    /^server:/        { s=1; next }
    /^[^[:space:]]/   { s=0 }
    s && /^[[:space:]]+port:/ { v=$2; gsub(/[^0-9]/,"",v); if (v != "") { print v; exit } }
' /etc/unmask/config.yml 2>/dev/null)
[ -n "$UNMASK_PORT" ] || UNMASK_PORT=9477
if [ ! -e "$UPSTREAM_SRC" ] || ! grep -q 'upstream unmask_admin' "$UPSTREAM_SRC" 2>/dev/null; then
    cat > "$UPSTREAM_SRC" <<UPSTREAM
# unmask admin upstream for forward-auth mode (install-time default).
# Port read from server.port in /etc/unmask/config.yml (= $UNMASK_PORT here;
# default 9477).  'unmask render-nginx' overwrites this from server.bind / port
# on the next settings save, so re-rendering after a port change keeps it in sync.
upstream unmask_admin {
    server 127.0.0.1:$UNMASK_PORT;
    keepalive 16;
}
UPSTREAM
fi
# Pick the include dir that lands inside http {}.  On RHEL / Debian the stock
# nginx.conf has `include /etc/nginx/conf.d/*.conf;` inside http {}, so conf.d/
# is the right place.  Alpine inverts this: conf.d/ is included in main scope
# and http.d/ is included in http {}.  Our upstream / map files contain
# directives that only belong in http {}, so route by what the host nginx.conf
# actually does.
NGINX_INCDIR=/etc/nginx/conf.d
if [ -d /etc/nginx/http.d ] \
   && [ -r /etc/nginx/nginx.conf ] \
   && awk '
       /^[[:space:]]*http[[:space:]]*\{/ { in_http=1 }
       in_http && /include[[:space:]]+\/etc\/nginx\/http\.d\// { found=1 }
       /^\}/ { in_http=0 }
       END { exit !found }
     ' /etc/nginx/nginx.conf; then
    NGINX_INCDIR=/etc/nginx/http.d
fi
mkdir -p "$NGINX_INCDIR"
UPSTREAM_LINK=$NGINX_INCDIR/00-unmask-upstream.conf
# (Re)point our symlink at the current source -- this also migrates an older
# install whose link still points at /etc/unmask/upstream.conf to the
# /var/lib/unmask/nginx location.  Created if absent; a real file an operator
# dropped in (not a symlink) is left untouched.
if [ -L "$UPSTREAM_LINK" ] || [ ! -e "$UPSTREAM_LINK" ]; then
    ln -sf "$UPSTREAM_SRC" "$UPSTREAM_LINK"
    echo "unmask-web-nginx: symlinked $UPSTREAM_LINK -> $UPSTREAM_SRC"
fi

# forward-auth LB-trust gate.  forward-auth/server.inc forwards X-Client-JA4 =
# $unmask_fa_ja4, which `unmask render-nginx` fills from nginx.trusted_lb_presets
# (the JA4 is honored only from a trusted LB source IP).  Lay down a no-op
# default (always "") so the variable resolves and `nginx -t` passes before the
# first render; render overwrites it on the first settings save.  Wired in BOTH
# modes -- it is plugin-var-free, and a hybrid native+forward-auth vhost needs it
# too.
#
# Load-order note: this file carries `geo`/`map` blocks, and nginx pins
# map_hash_bucket_size the moment it parses the FIRST map/geo block -- after which
# a later explicit `map_hash_bucket_size` (http.inc emits one at its top to size
# the community-bans maps) is a fatal "directive is duplicate" that the plugin's
# place-module fail-safe then reacts to by stripping ALL unmask wiring.  So this
# gate MUST load AFTER http.inc: the symlink is named "zz-..." to sort last in
# the include dir (http.inc is "00-unmask.conf"), so http.inc's sizing is parsed
# first regardless of native/forward-auth mode or postinstall order.
FA_GATE_SRC=/var/lib/unmask/nginx/forward-auth-lbtrust.conf
[ -d /var/lib/unmask/nginx ] || mkdir -p /var/lib/unmask/nginx
if [ ! -e "$FA_GATE_SRC" ]; then
    cat > "$FA_GATE_SRC" <<'FAGATE'
# unmask forward-auth LB-trust gate (no-op default; overwritten by `unmask render-nginx`).
geo $realip_remote_addr $unmask_fa_lb_vendor { default ""; }
map $unmask_fa_lb_vendor $unmask_fa_ja4 { default ""; }
FAGATE
fi
# Migrate the pre-fix name: 00-unmask-fa-lbtrust.conf sorted BEFORE http.inc and
# tripped the map_hash duplicate, so drop it in both candidate include dirs.
rm -f /etc/nginx/conf.d/00-unmask-fa-lbtrust.conf /etc/nginx/http.d/00-unmask-fa-lbtrust.conf
FA_GATE_LINK=$NGINX_INCDIR/zz-unmask-fa-lbtrust.conf
if [ -L "$FA_GATE_LINK" ] || [ ! -e "$FA_GATE_LINK" ]; then
    ln -sf "$FA_GATE_SRC" "$FA_GATE_LINK"
    echo "unmask-web-nginx: symlinked $FA_GATE_LINK -> $FA_GATE_SRC"
fi

# JA4 maps auto-load -- NATIVE mode only.  http.inc emits C-module directives
# (unmask_bv_secret / unmask_ban_file / ...) and maps over plugin-provided
# variables ($client_ja4 / $unmask_bv_kind), so loading it WITHOUT the plugin
# makes `nginx -t` abort with "unknown directive".  unmask-web-nginx depends
# only on unmask+nginx (forward-auth is the advertised default), so wire http.inc
# ONLY when the native plugin .so is actually installed; the unmask-plugin-nginx
# postinstall also creates this symlink, so install order does not matter.
PLUGIN_MODPATH=$(nginx -V 2>&1 | tr " " "\n" | sed -n "s|^--modules-path=||p" | head -1)
if [ -n "$PLUGIN_MODPATH" ] && [ -e "$PLUGIN_MODPATH/ngx_http_unmask_module.so" ]; then
    RENDERED_SRC=/var/lib/unmask/nginx/http.inc
    RENDERED_LINK=$NGINX_INCDIR/00-unmask.conf
    [ -d /var/lib/unmask/nginx ] || mkdir -p /var/lib/unmask/nginx
    [ -e "$RENDERED_SRC" ] || : > "$RENDERED_SRC"
    rm -f /etc/nginx/conf.d/00-unmask-rendered.conf /etc/nginx/http.d/00-unmask-rendered.conf
    if [ ! -L "$RENDERED_LINK" ] && [ ! -e "$RENDERED_LINK" ]; then
        ln -sf "$RENDERED_SRC" "$RENDERED_LINK"
        echo "unmask-web-nginx: symlinked $RENDERED_LINK -> $RENDERED_SRC"
    elif [ -L "$RENDERED_LINK" ] && [ "$(readlink "$RENDERED_LINK")" != "$RENDERED_SRC" ]; then
        ln -sf "$RENDERED_SRC" "$RENDERED_LINK"
        echo "unmask-web-nginx: repointed $RENDERED_LINK -> $RENDERED_SRC"
    fi
else
    # forward-auth mode (no native plugin): http.inc would fail nginx -t, so
    # leave it unwired and clear any stale symlink from a prior native install.
    rm -f /etc/nginx/conf.d/00-unmask.conf /etc/nginx/http.d/00-unmask.conf
    echo "unmask-web-nginx: native plugin not installed -> forward-auth mode (http.inc left unwired)"
fi

# map_hash sizing for the community-bans maps is no longer injected into
# nginx.conf.  It now lives at the top of http.inc, emitted by the admin's render
# (= nginxconf.Render), which probes nginx.conf read-only and emits
# map_hash_bucket_size / map_hash_max_size only for the directives the host has
# not already set -- so this package never edits nginx.conf for map sizing.  Drop
# any leftover snippet an older package version left in the include dirs.
rm -f /etc/nginx/conf.d/00-unmask-maphash.conf /etc/nginx/http.d/00-unmask-maphash.conf

# SELinux: nginx defaults to the httpd_t domain on RHEL-family distros, where
# the nginx auth_request directive / proxy_pass to 127.0.0.1:9477 is kernel-blocked unless the
# httpd_can_network_connect bool is on.  Without this the bot challenge never
# fires -- the visitor lands on the backend as if unmask were absent.  Auto-
# enable so install-and-go works; opt out by setting UNMASK_SKIP_SETSEBOOL=1
# before install.  Bool is persistent (-P) so it survives reboots.
# Scope note: httpd_can_network_connect is HOST-WIDE -- it lets every httpd_t
# process make outbound connections, not just unmask's nginx.  A custom policy
# module scoped to the admin port would be tighter (= v0.2 hardening); the
# conditional + opt-out here keeps this broad grant operator-visible.
if [ -z "${UNMASK_SKIP_SETSEBOOL:-}" ] \
   && command -v getenforce >/dev/null 2>&1 \
   && [ "$(getenforce 2>/dev/null)" = "Enforcing" ] \
   && command -v setsebool >/dev/null 2>&1 \
   && command -v getsebool >/dev/null 2>&1; then
    if getsebool httpd_can_network_connect 2>/dev/null | grep -q ' --> off'; then
        if setsebool -P httpd_can_network_connect 1 2>/dev/null; then
            echo "unmask-web-nginx: SELinux setsebool -P httpd_can_network_connect 1 applied"
            echo "  (= nginx can now proxy_pass to unmask.  set UNMASK_SKIP_SETSEBOOL=1 to opt out)"
        else
            echo "unmask-web-nginx: WARNING -- setsebool failed."
            echo "  -> run manually: sudo setsebool -P httpd_can_network_connect 1"
        fi
    fi
fi

# SELinux: the native log socket /run/unmask/log.sock is created by the daemon
# under var_run_t, but nginx (httpd_t) writing a var_run_t sock_file has no allow
# rule -> the dashboard cookie/crawler/countries cards silently zero and the
# error_log spams "connect() failed (13: Permission denied)" (the same denial
# 502s the opt-in unix:/run/unmask/http.sock).  Relabel the runtime dir
# httpd_var_run_t so httpd_t may write the socket; the fcontext rule is permanent
# so the daemon's socket inherits the label after a reboot recreates tmpfs /run.
if [ -z "${UNMASK_SKIP_SETSEBOOL:-}" ] &&
   command -v getenforce >/dev/null 2>&1 &&
   [ "$(getenforce 2>/dev/null)" = "Enforcing" ] &&
   command -v semanage >/dev/null 2>&1 &&
   command -v restorecon >/dev/null 2>&1; then
    if semanage fcontext -a -t httpd_var_run_t '/run/unmask(/.*)?' 2>/dev/null ||
       semanage fcontext -m -t httpd_var_run_t '/run/unmask(/.*)?' 2>/dev/null; then
        [ -d /run/unmask ] && restorecon -RF /run/unmask 2>/dev/null || true
        echo "unmask-web-nginx: SELinux fcontext httpd_var_run_t set on /run/unmask (native log socket)"
    else
        echo "unmask-web-nginx: WARNING -- semanage fcontext for /run/unmask failed."
        echo "  -> run: sudo semanage fcontext -a -t httpd_var_run_t '/run/unmask(/.*)?' && sudo restorecon -RF /run/unmask"
    fi
fi

if command -v nginx >/dev/null 2>&1; then
    # Alpine creates the /run/nginx pid dir in the openrc service's start_pre,
    # so on a fresh box where nginx has never been started the validation
    # `nginx -t` below fails on open(/run/nginx/nginx.pid) even though the
    # config is valid -- producing a misleading warning.  Create it first.
    [ -d /run/nginx ] || mkdir -p /run/nginx 2>/dev/null || true
    # Native mode: after (re)wiring http.inc above, let the picker re-test and
    # fail-safe-disable the unmask wiring if *unmask* (not a pre-existing host
    # error) breaks `nginx -t`, so a bad render never blocks reload/start.  This
    # also covers install order: plugin and web-nginx each run --verify after
    # their own wiring, so whichever lands last leaves the correct state.  No-op
    # in forward-auth mode (no picker shipped).
    [ -f /usr/share/unmask/plugin/place-module.sh ] && sh /usr/share/unmask/plugin/place-module.sh --verify
    if nginx -t >/dev/null 2>&1; then
        # Do NOT reload/restart nginx here -- touching the running web server is
        # the operator's call (predictable blast radius).  We render + validate
        # the config only; the operator applies it when they choose.
        echo "unmask-web-nginx: config rendered, 'nginx -t' OK -- nginx NOT reloaded."
        echo "  → apply when you choose:  sudo nginx -s reload  (config), or"
        echo "    sudo service nginx restart  (REQUIRED to load a new plugin .so)."
    else
        echo "unmask-web-nginx: WARNING — 'nginx -t' did NOT pass."
        echo "  → check the conflict (often duplicate 'upstream' or 'server' definitions)."
        echo "  → run 'sudo nginx -t' to see the error, fix, then 'sudo nginx -s reload'."
    fi
else
    echo "unmask-web-nginx: nginx binary not found — install nginx first, then 'nginx -s reload'."
fi

# setup wizard URL + token hint (= the main package creates .setup-token on first install).
TOKEN_FILE=/etc/unmask/.setup-token
host=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo localhost)
echo ""
echo "================================================================"
echo "  unmask — initial setup"
echo "  ================================================================"
echo "  Setup wizard URL:  /unmask/admin/setup/"
if [ -r "$TOKEN_FILE" ]; then
    token=$(cat "$TOKEN_FILE" 2>/dev/null || true)
    if [ -n "$token" ]; then
        echo "  Setup token:       $token"
        echo "  (re-display:        sudo cat $TOKEN_FILE)"
    fi
fi
echo ""
echo "  How to reach the setup wizard:"
echo ""
echo "  [1] Recommended — add 1 line to your existing nginx vhost"
echo "        Edit a server { } block in /etc/nginx/conf.d/ and add:"
echo ""
echo "            include /etc/unmask/forward-auth/server.inc;"
echo ""
echo "        (native mode with unmask-plugin-nginx: use /var/lib/unmask/nginx/server.inc)"
echo "        then:  sudo nginx -t && sudo nginx -s reload"
echo "        open:  https://<your-domain>/unmask/admin/setup/"
echo ""
echo "  [2] Direct port (= dev / lab, or private network)"
echo "        Edit /etc/unmask/config.yml → server.bind: 0.0.0.0:9477"
echo "        sudo systemctl restart unmask"
echo "        open:  http://${host}:9477/unmask/admin/setup/"
echo ""
echo "  [3] SSH tunnel (= universal fallback, no nginx setup needed)"
echo "        \$ ssh -L 9477:127.0.0.1:9477 ${host} -N &"
echo "        open:  http://localhost:9477/unmask/admin/setup/"
echo ""
echo "  After setup, add protection to your location { } block:"
echo "        include /etc/unmask/forward-auth/protect.inc;  # fires the bot challenge"
echo ""
if [ ! -r "$TOKEN_FILE" ]; then
    echo "     The setup token is at /etc/unmask/.setup-token (= view with sudo cat)."
fi
echo "================================================================"
echo ""

exit 0
