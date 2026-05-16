#!/bin/sh
# unmask-web-apache postinstall.
# RHEL: /etc/httpd/conf.d/unmask-web.conf, Debian: /etc/apache2/conf-available/unmask-web.conf
#
#  1. apachectl configtest validates syntax (= fails if required modules are missing)
#  2. If SELinux is enforcing, prints a hint about httpd_can_network_connect
#  3. On pass, runs apachectl graceful (= reload).  Failures are not treated as errors.


# RHEL pattern.
RHEL_CONF=/etc/httpd/conf.d/unmask-web.conf
DEBIAN_CONF=/etc/apache2/conf-available/unmask-web.conf
DEBIAN_LINK=/etc/apache2/conf-enabled/unmask-web.conf

if [ -f "$RHEL_CONF" ]; then
    echo "unmask-web-apache: installed snippet at $RHEL_CONF"
elif [ -f "$DEBIAN_CONF" ]; then
    echo "unmask-web-apache: installed snippet at $DEBIAN_CONF"
    if [ ! -e "$DEBIAN_LINK" ] && command -v a2enconf >/dev/null 2>&1; then
        a2enconf unmask-web >/dev/null 2>&1 || true
        echo "unmask-web-apache: enabled via a2enconf"
    fi
fi

# SELinux hint (= httpd needs the bool to connect to 127.0.0.1:9477).
if command -v getenforce >/dev/null 2>&1; then
    if [ "$(getenforce 2>/dev/null)" = "Enforcing" ]; then
        if command -v getsebool >/dev/null 2>&1; then
            if getsebool httpd_can_network_connect 2>/dev/null | grep -q ' --> off'; then
                echo "unmask-web-apache: SELinux is Enforcing AND httpd_can_network_connect is OFF."
                echo "  → run: sudo setsebool -P httpd_can_network_connect 1"
            fi
        fi
    fi
fi

if command -v apachectl >/dev/null 2>&1; then
    if apachectl configtest >/dev/null 2>&1; then
        apachectl graceful >/dev/null 2>&1 || true
        echo "unmask-web-apache: httpd graceful reload requested."
    else
        echo "unmask-web-apache: WARNING — 'apachectl configtest' did NOT pass."
        echo "  → likely missing modules. Try:"
        echo "    sudo yum install mod_lua    (RHEL)"
        echo "    sudo a2enmod proxy proxy_http lua headers   (Debian)"
    fi
elif command -v httpd >/dev/null 2>&1; then
    echo "unmask-web-apache: please run 'sudo systemctl reload httpd'"
elif command -v apache2ctl >/dev/null 2>&1; then
    echo "unmask-web-apache: please run 'sudo systemctl reload apache2'"
else
    echo "unmask-web-apache: Apache binary not found — install httpd / apache2 first."
fi

# setup wizard URL + token hint.
TOKEN_FILE=/etc/unmask/.setup-token
host=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo localhost)
echo ""
echo "================================================================"
echo "  unmask web (Apache) — initial setup"
echo "  ================================================================"
echo "  open in your browser:"
echo "    https://${host}/unmask/admin/setup/"
if [ -r "$TOKEN_FILE" ]; then
    token=$(cat "$TOKEN_FILE" 2>/dev/null || true)
    if [ -n "$token" ]; then
        echo ""
        echo "  setup token:"
        echo "    $token"
        echo ""
        echo "  later:  sudo cat $TOKEN_FILE   (= reprint)"
    fi
else
    echo ""
    echo "  The setup token is stored at /etc/unmask/.setup-token (= view with sudo cat)."
fi
echo "================================================================"
echo ""

exit 0
