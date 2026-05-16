#!/bin/sh
# Runs after the first install / upgrade.
#   - Fix permissions on /etc/unmask/ (= so the unmask user can write from the web)
#   - Generate /etc/unmask/config.yml via `unmask-admin config-init`
#   - Apply the schema
#   - Generate nginx-rendered*.conf
#   - systemd reload + enable
#
# Note: do NOT `set -eu` here.  This postinstall has no abort requirement
# (= even when one step fails we want to reach "next init system detection
# + symlink installation").  In particular, apk-tools v3 hooks run inside
# memfd + sanitized env + chroot, and any unexpected failure in an earlier
# step like `unmask-admin config-init` can `set -e` abort the whole
# script and prevent the OpenRC symlink from being created (= reported on
# 2026-05-10 22:14 JST [B]).  Silence failures per-step with
# `|| true` or `|| echo "WARNING"`.

CONFIG_DIR=/etc/unmask
CONFIG=$CONFIG_DIR/config.yml

# Permissions: 0755 unmask:unmask.  config.yml is 0640 to protect secrets.
# nginx runs as a different user but traverses /etc/unmask/ to read the
# rendered conf.
chown -R unmask:unmask "$CONFIG_DIR" 2>/dev/null || true
chmod 0755 "$CONFIG_DIR" 2>/dev/null || true

if [ ! -f "$CONFIG" ]; then
    /usr/sbin/unmask-admin config-init -out "$CONFIG" || \
        echo "unmask: WARNING: config-init failed (= run sudo /usr/sbin/unmask-admin config-init -out $CONFIG manually later)"
    chown unmask:unmask "$CONFIG" 2>/dev/null || true
    chmod 0640 "$CONFIG" 2>/dev/null || true
    [ -f "$CONFIG" ] && echo "unmask: generated $CONFIG with random secrets"
fi
chown unmask:unmask "$CONFIG" 2>/dev/null || true
chmod 0640 "$CONFIG" 2>/dev/null || true

# Setup token (= protects against a third party racing through the wizard
# first).  Skip if a user already exists in the user table (= idempotent
# across upgrades).
TOKEN_FILE=$CONFIG_DIR/.setup-token
# Generate the token only on the initial install (= $1 == 1 for rpm /
# configure for deb).
if [ "${1:-}" = "1" ] || [ "${1:-}" = "configure" ]; then
    if [ ! -f "$TOKEN_FILE" ]; then
        token=$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')
        echo "$token" > "$TOKEN_FILE"
        chown unmask:unmask "$TOKEN_FILE"
        chmod 0600 "$TOKEN_FILE"
        # The admin listens on localhost:9477.  External access is intended
        # to go through a web server at https://host/unmask/admin/setup/.
        # That's why the user is expected to install one of the next
        # `unmask-web-{nginx,apache,caddy}` packages.
        host=$(hostname -f 2>/dev/null || hostname 2>/dev/null || echo your-host)
        echo ""
        echo "================================================================"
        echo "  unmask install — initial setup wizard"
        echo "  ================================================================"
        echo "  next step: install web integration to expose the admin UI"
        echo "    sudo dnf install unmask-web-nginx     (= /etc/nginx/conf.d/ snippet)"
        echo "    sudo dnf install unmask-web-apache    (= /etc/httpd/conf.d/ snippet)"
        echo "    sudo dnf install unmask-web-caddy     (= /etc/caddy/conf.d/ snippet)"
        echo "  -> once done, open https://${host}/unmask/admin/setup/ to launch the wizard."
        echo ""
        echo "  setup token (= enter in the wizard):"
        echo "    $token"
        echo ""
        echo "  later:  sudo cat $TOKEN_FILE   (= reprint)"
        echo "  The token file is deleted automatically when setup completes."
        echo "================================================================"
        echo ""
    fi
fi

# Note: schema migration is unified to run as the **DB step of the install
# wizard**.  Don't migrate from this postinstall (= driver / connection
# info are not yet known until the wizard).  CLI users running migration
# manually after rpm install should do:
#   sudo /usr/sbin/unmask-admin migrate -config $CONFIG
# before moving on to the user-create commands.

# Generate nginx-rendered*.conf (= so `nginx -t` passes on first start).
# Changes via the web auto-render, but the user hasn't opened the web yet
# right after install, so do it once here.
/usr/sbin/unmask-admin render-nginx -config "$CONFIG" || \
    echo "unmask: WARNING: render-nginx failed (= nginx-rendered.conf not generated. Please verify manually.)"
chown unmask:unmask "$CONFIG_DIR"/nginx-rendered*.conf 2>/dev/null || true
chmod 0644 "$CONFIG_DIR"/nginx-rendered*.conf 2>/dev/null || true

# init system detection: systemd > OpenRC > SysVinit in that order.
# init.d/unmask-admin is symlinked per OS (= the body is picked from
# unmask-admin.sysv / unmask-admin.openrc shipped under
# /usr/share/unmask/init/).
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    # systemd environment (= RHEL 7+ / Ubuntu 16.04+ / Debian 8+ / Arch / etc.)
    #
    # The nginx group name differs by distro (= `nginx` on rpm-family,
    # `www-data` on deb-family, `http` on Arch, old `httpd`).  The unit
    # file's `SupplementaryGroups=nginx` works on rpm/Arch but on deb the
    # `nginx` group does not exist, causing setgroups() to fail and
    # leaving the service in **status=216/GROUP** activating loop (= root
    # cause confirmed by [B] on 2026-05-11 00:50).  Reset and re-set
    # SupplementaryGroups= dynamically via a drop-in.
    NGINX_GROUP=""
    for grp in nginx www-data http httpd; do
        getent group "$grp" >/dev/null 2>&1 && NGINX_GROUP="$grp" && break
    done
    DROP_IN=/etc/systemd/system/unmask-admin.service.d
    mkdir -p "$DROP_IN"
    {
        echo "[Service]"
        echo "# nginx-family group resolved dynamically (= rpm 'nginx' / deb 'www-data' etc.)."
        echo "# Reset and re-set the unit file's SupplementaryGroups=nginx."
        echo "# (= prevents systemd setgroups() failure (= 216/GROUP) when the group does not exist)"
        echo "SupplementaryGroups="
        if [ -n "$NGINX_GROUP" ]; then
            echo "SupplementaryGroups=$NGINX_GROUP"
        fi
    } > "$DROP_IN/10-group.conf"

    systemctl daemon-reload || true
    if [ "${1:-}" = "1" ] || [ "${1:-}" = "configure" ]; then
        systemctl enable --now unmask-admin.service || true
        systemctl enable --now unmask-aggregate.timer || true
    else
        systemctl try-restart unmask-admin.service || true
    fi
    INIT_KIND=systemd
elif command -v rc-service >/dev/null 2>&1 || [ -x /sbin/openrc-run ]; then
    # OpenRC (= Alpine 3.x / Gentoo).  symlink the OpenRC variant to /etc/init.d/unmask-admin.
    ln -sf /usr/share/unmask/init/unmask-admin.openrc /etc/init.d/unmask-admin
    rc-update add unmask-admin default 2>/dev/null || true
    if [ "${1:-}" = "1" ]; then
        rc-service unmask-admin start || true
    else
        rc-service unmask-admin restart || true
    fi
    INIT_KIND=openrc
elif command -v chkconfig >/dev/null 2>&1 && [ -d /etc/rc.d/init.d ]; then
    # SysVinit (= RHEL 6 / CentOS 6).  symlink the SysV variant that depends on the functions library.
    ln -sf /usr/share/unmask/init/unmask-admin.sysv /etc/init.d/unmask-admin
    chkconfig --add unmask-admin || true
    chkconfig unmask-admin on || true
    if [ "${1:-}" = "1" ]; then
        service unmask-admin start || true
    else
        service unmask-admin condrestart || true
    fi
    INIT_KIND=sysvinit
else
    INIT_KIND=manual
fi

echo "unmask: install complete (init: ${INIT_KIND:-unknown})."
echo "  next steps (= on the nginx side):"
echo "    1. add 'load_module /usr/lib/nginx/modules/ngx_http_unmask_module.so;' to nginx.conf"
echo "    2. add 'include /etc/unmask/nginx-rendered.conf;'         inside the http {} block"
echo "    3. add 'include /etc/unmask/nginx-rendered-server.conf;'  inside protected server {} blocks"
if [ "$INIT_KIND" = "systemd" ]; then
    echo "    4. nginx -t && systemctl reload nginx"
elif [ "$INIT_KIND" = "sysvinit" ]; then
    echo "    4. nginx -t && service nginx reload"
else
    echo "    4. nginx -t && reload nginx (= the service-management command depends on the environment)"
fi
echo ""
echo "  edit configuration from the web UI:  https://<your-host>/unmask/admin/settings/"
if [ "$INIT_KIND" = "systemd" ]; then
    echo "  after saving, run  systemctl reload nginx  to apply (= unmask-admin itself does not need a restart)."
elif [ "$INIT_KIND" = "sysvinit" ]; then
    echo "  after saving, run  service nginx reload  to apply (= unmask-admin itself does not need a restart)."
fi
