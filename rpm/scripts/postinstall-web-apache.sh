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
    # The snippet uses ProxyPass/ProxyPassReverse (= mod_proxy + mod_proxy_http),
    # RequestHeader (= mod_headers) and the opt-in LuaHookAccessChecker
    # (= mod_lua).  Debian's apache2 enables NONE of these by default, so a bare
    # `a2enconf unmask-web` would arm a config that fails the next
    # `systemctl restart apache2`.  Enable the modules first (= deb-only path;
    # RHEL httpd loads mod_proxy itself, and a2enmod does not exist there anyway).
    if command -v a2enmod >/dev/null 2>&1; then
        a2enmod proxy proxy_http headers lua >/dev/null 2>&1 || true
    fi
    # Resolve a configtest command (= Debian ships apache2ctl; apachectl is an alias).
    CONFIGTEST=""
    if command -v apache2ctl >/dev/null 2>&1; then
        CONFIGTEST=apache2ctl
    elif command -v apachectl >/dev/null 2>&1; then
        CONFIGTEST=apachectl
    fi
    if [ ! -e "$DEBIAN_LINK" ] && command -v a2enconf >/dev/null 2>&1; then
        # Gate on a passing configtest so we never enable the conf when Apache's
        # base config (now with the modules loaded) is already broken.  After
        # a2enconf, re-validate and roll back with a2disconf if the conf broke
        # anything — that guarantees the next restart cannot fail because of us.
        if [ -z "$CONFIGTEST" ] || "$CONFIGTEST" configtest >/dev/null 2>&1; then
            a2enconf unmask-web >/dev/null 2>&1 || true
            if [ -n "$CONFIGTEST" ] && ! "$CONFIGTEST" configtest >/dev/null 2>&1; then
                a2disconf unmask-web >/dev/null 2>&1 || true
                echo "unmask-web-apache: WARNING — config invalid after a2enconf; reverted (a2disconf)."
                echo "  → ensure mod_proxy/mod_proxy_http/mod_lua are installed, then: sudo a2enconf unmask-web"
            else
                echo "unmask-web-apache: enabled via a2enconf"
            fi
        else
            echo "unmask-web-apache: WARNING — 'apache2ctl configtest' failed; not enabling unmask-web."
            echo "  → fix the existing Apache config, then: sudo a2enconf unmask-web"
        fi
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
