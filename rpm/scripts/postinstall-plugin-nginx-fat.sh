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
else
    echo "unmask-plugin-nginx: $PLACER missing -- module not placed." >&2
fi

# Pick up the ExecStartPre drop-in (= /usr/lib/systemd/system/nginx.service.d/
# 10-unmask-repick.conf, shipped by this package) so the next nginx (re)start
# re-runs the placer.  No-op on non-systemd (= Alpine OpenRC): the placer still
# ran above for the install-time pick; Alpine's host-nginx-upgrade re-pick is a
# known follow-up (OpenRC start_pre / apk trigger).
if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl daemon-reload 2>/dev/null || true
fi

exit 0
