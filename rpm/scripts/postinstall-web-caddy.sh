#!/bin/sh
# unmask-web-caddy postinstall.


CONF=/etc/caddy/conf.d/unmask-web.caddy
echo "unmask-web-caddy: installed snippet at $CONF"
echo "  → edit the host name (= 'example.com') in the snippet, then:"
echo "    sudo systemctl reload caddy"

# Caddy's conf.d include must be declared in the default Caddyfile.  If not yet
# present, prompt the user.
if [ -f /etc/caddy/Caddyfile ]; then
    if ! grep -q 'import.*conf.d' /etc/caddy/Caddyfile 2>/dev/null; then
        echo "unmask-web-caddy: NOTE — /etc/caddy/Caddyfile does not import conf.d."
        echo "  -> append this line at the end of /etc/caddy/Caddyfile:"
        echo "    import /etc/caddy/conf.d/*.caddy"
    fi
fi

if command -v caddy >/dev/null 2>&1; then
    if caddy validate --config /etc/caddy/Caddyfile >/dev/null 2>&1; then
        systemctl reload caddy >/dev/null 2>&1 || true
    else
        echo "unmask-web-caddy: WARNING — 'caddy validate' did NOT pass."
        echo "  → check /etc/caddy/conf.d/unmask-web.caddy and the host name placeholder."
    fi
fi

# setup wizard URL + token hint.
TOKEN_FILE=/etc/unmask/.setup-token
host=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo localhost)
echo ""
echo "================================================================"
echo "  unmask web (Caddy) — initial setup"
echo "  ================================================================"
echo "  open in your browser (= after replacing the host name in the snippet):"
echo "    https://${host}/unmask/admin/setup/"
if [ -r "$TOKEN_FILE" ]; then
    token=$(cat "$TOKEN_FILE" 2>/dev/null || true)
    if [ -n "$token" ]; then
        echo ""
        echo "  setup token:"
        echo "    $token"
        echo ""
        echo "  later:  sudo cat $TOKEN_FILE   (= show again)"
    fi
else
    echo ""
    echo "  setup token is at /etc/unmask/.setup-token (= sudo cat to print)."
fi
echo "================================================================"
echo ""

exit 0
