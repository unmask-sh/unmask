#!/bin/sh
# unmask-web-nginx postinstall.
#
# Role:
#   1. Place upstream auto-load symlinks in /etc/nginx/conf.d/
#       00-unmask-upstream.conf -> /etc/unmask/upstream.conf
#         (= so proxy_pass http://unmask_admin; resolves in every server block. shared by both modes)
#       00-unmask.conf          -> /etc/unmask/http.inc
#         (= JA4 maps / log_format etc.  native-mode only.  In environments
#            without the plugin, the target is not rendered but nginx -t still
#            passes; include only emits a warning.)
#   2. Validate syntax with nginx -t and attempt reload
#   3. Print the setup wizard URL + token

echo "unmask-web-nginx: installing nginx integration..."

# upstream auto-load.  Forward-auth mode's server.inc does `proxy_pass
# http://unmask_admin;`, so that upstream must exist in http {} scope.  Native
# mode defines its own `upstream unmask` inside the rendered http.inc; this
# separate block is what forward-auth (no plugin, no rendered http.inc) relies
# on.  The render path that once emitted it was retired, so write the
# default-port block here.  Operators who change server.port in config.yml
# update the server line to match.
UPSTREAM_SRC=/etc/unmask/upstream.conf
[ -d /etc/unmask ] || mkdir -p /etc/unmask
if [ ! -e "$UPSTREAM_SRC" ] || ! grep -q 'upstream unmask_admin' "$UPSTREAM_SRC" 2>/dev/null; then
    cat > "$UPSTREAM_SRC" <<'UPSTREAM'
# unmask admin upstream for forward-auth mode.  Default admin bind is
# 127.0.0.1:9477 (= server.bind / server.port in /etc/unmask/config.yml).
# Keep the server line below in sync if you change that.
upstream unmask_admin {
    server 127.0.0.1:9477;
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
if [ ! -L "$UPSTREAM_LINK" ] && [ ! -e "$UPSTREAM_LINK" ]; then
    ln -sf "$UPSTREAM_SRC" "$UPSTREAM_LINK"
    echo "unmask-web-nginx: symlinked $UPSTREAM_LINK -> $UPSTREAM_SRC"
fi

# JA4 maps auto-load (= native-mode only).  Meaningful only with the
# unmask-plugin-nginx + admin combination.  Even without the plugin, keep the
# symlink alive by pointing it at an empty placeholder that is still rendered.
# NOTE: render-nginx writes the flat path /etc/unmask/http.inc (the legacy
# /etc/unmask/native/ layout was retired); the symlink must track it or nginx
# loads an empty placeholder and `unknown log format unmask_minimal` aborts -t.
RENDERED_SRC=/etc/unmask/http.inc
RENDERED_LINK=$NGINX_INCDIR/00-unmask.conf
[ -d /etc/unmask ] || mkdir -p /etc/unmask
[ -e "$RENDERED_SRC" ] || : > "$RENDERED_SRC"
# cleanup of the legacy symlink (= whichever include dir applies on this host)
rm -f /etc/nginx/conf.d/00-unmask-rendered.conf /etc/nginx/http.d/00-unmask-rendered.conf
if [ ! -L "$RENDERED_LINK" ] && [ ! -e "$RENDERED_LINK" ]; then
    ln -sf "$RENDERED_SRC" "$RENDERED_LINK"
    echo "unmask-web-nginx: symlinked $RENDERED_LINK -> $RENDERED_SRC"
fi

# SELinux: nginx defaults to the httpd_t domain on RHEL-family distros, where
# the nginx auth_request directive / proxy_pass to 127.0.0.1:9477 is kernel-blocked unless the
# httpd_can_network_connect bool is on.  Without this the bot challenge never
# fires -- the visitor lands on the backend as if unmask were absent.  Auto-
# enable so install-and-go works; opt out by setting UNMASK_SKIP_SETSEBOOL=1
# before install.  Bool is persistent (-P) so it survives reboots.
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

if command -v nginx >/dev/null 2>&1; then
    if nginx -t >/dev/null 2>&1; then
        nginx -s reload >/dev/null 2>&1 || true
        echo "unmask-web-nginx: nginx reload requested."
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
echo "        (native mode with unmask-plugin-nginx: use /etc/unmask/server.inc)"
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
