#!/bin/sh
# postinstall for unmask-plugin-nginx (fat).  Thin wrapper around the on-disk
# module placer:
#   1. Run /usr/share/unmask/plugin/place-module.sh -- picks the bundled .so
#      matching the host nginx (or fail-safe-disables the module if none
#      matches).  The SAME script is wired into nginx.service as an
#      ExecStartPre drop-in, so a host nginx UPGRADE re-picks the module too --
#      this is what closes the host-nginx-upgrade .so orphan (= a routine
#      `yum/apt upgrade` of nginx no longer leaves an ABI-incompatible .so that
#      kills nginx on next start).
#   2. daemon-reload so the shipped nginx.service.d drop-in takes effect.

PLACER=/usr/share/unmask/plugin/place-module.sh
if [ -r "$PLACER" ]; then
    sh "$PLACER"
    # Placing the module unlinks the .so a running nginx still has mapped, so a
    # reload is not enough here: `nginx -s reload` re-reads the config but does
    # not re-exec the master, leaving it on the old (now deleted) module image.
    # Say so at the moment the new module lands -- unmask-web-nginx draws the
    # same distinction for its own step.
    echo "unmask-plugin-nginx: module placed -- nginx NOT touched."
    echo "  → a NEW plugin .so needs a RESTART to load (a reload keeps the old one):"
    echo "    sudo systemctl restart nginx   (or: sudo service nginx restart)"
else
    echo "unmask-plugin-nginx: $PLACER missing -- module not placed." >&2
fi

# Pick up the ExecStartPre drop-in (= /usr/lib/systemd/system/nginx.service.d/
# 10-unmask-repick.conf, shipped by this package) so the next nginx (re)start
# re-runs the placer and a host nginx UPGRADE is re-picked automatically.
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload 2>/dev/null || true
else
    # Non-systemd hosts have no nginx unit to attach an ExecStartPre re-pick to
    # (Alpine ships no nginx OpenRC service at all; SysV nginx scripts are
    # package-owned), and nfpm cannot emit an apk trigger that fires on a nginx
    # upgrade.  The install-time pick above is done, but a LATER host nginx
    # upgrade is NOT re-picked automatically -- an ABI-mismatched .so would then
    # fail `nginx -t`.  Point the operator at the manual / pre-start re-pick.
    echo "unmask-plugin-nginx: no systemd here -- the module was placed for the current"
    echo "  nginx, but a future host nginx UPGRADE needs a re-pick."
    echo "  After upgrading nginx, run:  sh $PLACER"
    echo "  (or call it from your nginx service's pre-start hook -- e.g. an OpenRC"
    echo "   start_pre -- so every nginx start re-picks the matching module)."
fi

exit 0
