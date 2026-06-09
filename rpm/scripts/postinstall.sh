#!/bin/sh
# Runs after the first install / upgrade.
#   - Fix permissions on /etc/unmask/ (= so the unmask user can write from the web)
#   - Generate /etc/unmask/config.yml via `unmask config-init`
#   - Apply the schema
#   - Generate /etc/unmask/{http.inc,server.inc,protect.inc} (= render-nginx)
#   - systemd reload + enable
#
# Note: do NOT `set -eu` here.  This postinstall has no abort requirement
# (= even when one step fails we want to reach "next init system detection
# + symlink installation").  In particular, apk-tools v3 hooks run inside
# memfd + sanitized env + chroot, and any unexpected failure in an earlier
# step like `unmask config-init` can `set -e` abort the whole
# script and prevent the OpenRC symlink from being created (= reported on
# 2026-05-10 22:14 JST [B]).  Silence failures per-step with
# `|| true` or `|| echo "WARNING"`.

CONFIG_DIR=/etc/unmask
CONFIG=$CONFIG_DIR/config.yml

# Permissions: 0755 unmask:unmask.  config.yml is 0640 to protect secrets.
# nginx runs as a different user but traverses /etc/unmask/ to read the
# rendered conf.
#
# -h: do NOT follow symlinks.  GNU chown's default is to follow file symlinks
# and change the target's ownership, so a compromised unmask user could plant
# /etc/unmask/foo -> /etc/shadow before a re-install and re-run the post-install
# to flip the target's owner.  -h leaves symlink targets alone.
chown -h -R unmask:unmask "$CONFIG_DIR" 2>/dev/null || true
chmod 0755 "$CONFIG_DIR" 2>/dev/null || true

if [ ! -f "$CONFIG" ]; then
    /usr/sbin/unmask config-init -out "$CONFIG" || \
        echo "unmask: WARNING: config-init failed (= run sudo /usr/sbin/unmask config-init -out $CONFIG manually later)"
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
# Generate the token only on a fresh install (= $1 == "1" for rpm /
# "configure" for deb).  apk passes the package version string as $1 (never
# "1" / "configure"), so detect Alpine via /lib/apk and treat it as a fresh
# install too -- otherwise /etc/unmask/.setup-token is never created on Alpine
# and the setup wizard's anti-hijack token check is bypassable (= the first
# visitor could create the admin account).  The inner `[ ! -f "$TOKEN_FILE" ]`
# guard keeps this idempotent across apk upgrades.
# deb's "configure" fires on UPGRADES too, not just fresh installs; gate it on
# an empty $2 (the previous version, set only on upgrade) so `apt upgrade`
# doesn't re-mint the token and re-lock the admin UI behind the wizard.  (The
# daemon also clears a stale token at runtime once an admin user exists.)
if [ "${1:-}" = "1" ] || { [ "${1:-}" = "configure" ] && [ -z "${2:-}" ]; } || [ -d /lib/apk ]; then
    if [ ! -f "$TOKEN_FILE" ]; then
        token=$(head -c 18 /dev/urandom | od -An -tx1 | tr -d ' \n')
        # Write the token inside a `umask 077` subshell so the file is born
        # 0600 -- the prior shape created it under the default umask (= 0644)
        # and only chmod'd it on the next line, briefly exposing the secret
        # to any local reader who raced the chmod.
        ( umask 077; printf '%s\n' "$token" > "$TOKEN_FILE" )
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
#   sudo /usr/sbin/unmask migrate -config $CONFIG
# before moving on to the user-create commands.

# Render the nginx snippets (= so `nginx -t` passes on first start).
# render-nginx writes to nginx.output_dir, default /var/lib/unmask/nginx (FHS:
# /etc is the hand-edited config.yml, /var/lib the admin-rendered files).
# Changes via the web auto-render, but the user hasn't opened the web yet right
# after install, so do it once here.
RENDER_DIR=/var/lib/unmask/nginx
/usr/sbin/unmask render-nginx -config "$CONFIG" || \
    echo "unmask: WARNING: render-nginx failed (= $RENDER_DIR/http.inc + server.inc not generated. Please verify manually.)"
# The render runs as root here, so the dir + files land root-owned; the daemon
# runs as unmask and must rewrite them (community-bans map files, web-UI
# re-render), so hand the whole render dir to unmask.
chown -R unmask:unmask "$RENDER_DIR" 2>/dev/null || true
chmod 0644 "$RENDER_DIR"/*.inc 2>/dev/null || true
# http.inc carries unmask_bv_secret -- not world-readable (a local user could
# otherwise read the key and forge _bv cookies).  nginx's master reads config
# as root, so 0640 unmask:unmask is sufficient.
chmod 0640 "$RENDER_DIR"/http.inc 2>/dev/null || true

# init system detection: systemd > OpenRC.  SysVinit (= CentOS 6 etc.) was
# retired since every supported distro is one of these two.
# init.d/unmask is symlinked from /usr/share/unmask/init/unmask.openrc on
# apk hosts.
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
    DROP_IN=/etc/systemd/system/unmask.service.d
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
    if [ "${1:-}" = "1" ] || { [ "${1:-}" = "configure" ] && [ -z "${2:-}" ]; }; then
        # Fresh install only: rpm $1=1, or deb "configure" with an empty $2.
        # deb "configure" ALSO fires on upgrades, where enable --now is a no-op
        # on the already-running unit so the NEW binary never loads -- gate on
        # an empty $2 so those fall through to try-restart below instead.
        systemctl enable --now unmask.service || true
    elif [ -d /lib/apk ]; then
        # apk passes the package version as $1 (not "1"/"configure"), so a fresh
        # Alpine install would otherwise fall through to `try-restart` and never
        # get enabled or started.  Enable for boot, then restart -- restart
        # starts a stopped service and reloads a running one, so this is correct
        # for both fresh-install and upgrade on the (rare) systemd-on-Alpine host.
        systemctl enable unmask.service || true
        systemctl restart unmask.service || true
    else
        systemctl try-restart unmask.service || true
    fi
    INIT_KIND=systemd
elif command -v rc-service >/dev/null 2>&1 || [ -x /sbin/openrc-run ]; then
    # OpenRC (= Alpine 3.x / Gentoo).  symlink the OpenRC variant to /etc/init.d/unmask.
    ln -sf /usr/share/unmask/init/unmask.openrc /etc/init.d/unmask
    # rc-update add is unconditional, so boot-enable happens on every packager
    # including apk (= which passes the version string as $1, never "1").
    rc-update add unmask default 2>/dev/null || true
    if [ "${1:-}" = "1" ]; then
        rc-service unmask start || true
    else
        # Covers apk (= version-string $1) and any upgrade: `restart` starts a
        # stopped service (= fresh Alpine install) and reloads a running one
        # (= upgrade).  Do NOT narrow this to `start` for apk -- `start` on an
        # already-running service is a no-op, so an apk upgrade would keep the
        # old binary loaded.
        rc-service unmask restart || true
    fi
    INIT_KIND=openrc
elif command -v chkconfig >/dev/null 2>&1 && [ -d /etc/rc.d/init.d ]; then
    # SysVinit (= RHEL 6 / CentOS 6: no systemd, no OpenRC).  Install the init
    # script, register it for boot, and start it on a fresh install (= parity
    # with the systemd `enable --now` branch above).  The matching uninstall
    # cleanup lives in preremove.sh.
    cp -f /usr/share/unmask/init/unmask.sysv /etc/rc.d/init.d/unmask
    chmod 0755 /etc/rc.d/init.d/unmask
    chkconfig --add unmask 2>/dev/null || true
    chkconfig unmask on 2>/dev/null || true
    if [ "${1:-}" = "1" ]; then
        # Fresh rpm install ($1=1): start it now.
        service unmask start 2>/dev/null || /etc/rc.d/init.d/unmask start || true
    else
        # Upgrade: restart only if it was running, so the new binary loads.
        service unmask condrestart 2>/dev/null || /etc/rc.d/init.d/unmask condrestart || true
    fi
    INIT_KIND=sysvinit
else
    INIT_KIND=manual
fi

# Optional one-shot mmdb fetch.  Off by default to keep package install
# 100% offline-friendly.  When the operator sets UNMASK_AUTO_INSTALL_MMDB=1
# (= "I am online and want geo features to work immediately") fire a quick
# install-ipgeo as the unmask user.  Failure is non-fatal (= bad
# connectivity should never abort an rpm install).
if [ "${UNMASK_AUTO_INSTALL_MMDB:-0}" = "1" ]; then
    echo "unmask: UNMASK_AUTO_INSTALL_MMDB=1 detected — fetching DB-IP Country Lite ..."
    install -d -o unmask -g unmask -m 0750 /var/lib/unmask/ipgeo 2>/dev/null || true
    if command -v runuser >/dev/null 2>&1; then
        runuser -u unmask -- /usr/sbin/unmask install-ipgeo -quiet 2>&1 \
            || echo "unmask: WARNING: install-ipgeo failed (offline? run \`unmask install-ipgeo\` later)"
    else
        # Alpine / minimal systems may lack runuser; fall back to su.
        su unmask -c "/usr/sbin/unmask install-ipgeo -quiet" 2>&1 \
            || echo "unmask: WARNING: install-ipgeo failed (offline? run \`unmask install-ipgeo\` later)"
    fi
fi

echo "unmask: install complete (init: ${INIT_KIND:-unknown})."
echo "  next steps (= on the nginx side):"
echo "    1. add 'load_module /usr/lib/nginx/modules/ngx_http_unmask_module.so;' to nginx.conf"
echo "    2. add 'include /var/lib/unmask/nginx/http.inc;'    inside the http {} block"
echo "       (= the unmask-web-nginx package auto-symlinks this as /etc/nginx/conf.d/00-unmask.conf)"
echo "    3. add 'include /var/lib/unmask/nginx/server.inc;'  inside protected server {} blocks"
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
    echo "  after saving, run  systemctl reload nginx  to apply (= unmask itself does not need a restart)."
elif [ "$INIT_KIND" = "sysvinit" ]; then
    echo "  after saving, run  service nginx reload  to apply (= unmask itself does not need a restart)."
fi
