#!/bin/sh
# preinstall for unmask-plugin-nginx.
#
# Verify ABI compatibility for the nginx native module (.so) at install time:
#   - the host has the nginx command
#   - the version reported by nginx -v matches the __NGINX_VERSION__ stamped at build time
#
# On mismatch, abort and guide the user to obtain a version-specific plugin
# or rebuild.
# Note: do not use `set -e` / `set -u` (= same thinking as the fat preinst).
# The single-nginx-version variant aborts explicitly with `exit 1` on
# mismatch, so set -e is unnecessary.
# Test via a variable to avoid the busybox ash `set -e + if !` interaction.

EXPECTED_NGINX="__NGINX_VERSION__"

nginx_path=$(command -v nginx 2>/dev/null || true)
if [ -z "$nginx_path" ]; then
    cat >&2 <<'EOF'
================================================================
ERROR: nginx command not found.
================================================================

unmask-plugin-nginx is the plugin that loads a dynamic module into the
nginx binary.  Install it only on hosts where nginx is already present.

(= the plugin is not required if you run only the unmask main package in
auth_request mode)

================================================================
EOF
    exit 1
fi

ACTUAL=$(nginx -v 2>&1 | sed -n 's|.*nginx/\([0-9.]*\).*|\1|p')

case "$EXPECTED_NGINX" in
    __*)
        # __NGINX_VERSION__ was not substituted (= a dev build) → skip the check.
        echo "WARNING: plugin was built without nginx version stamp.  ABI mismatch may occur." >&2
        ;;
    *)
        if [ -n "$ACTUAL" ] && [ "$ACTUAL" != "$EXPECTED_NGINX" ]; then
            cat >&2 <<EOF
================================================================
ERROR: unmask-plugin-nginx was built for nginx ${EXPECTED_NGINX},
       but host has nginx ${ACTUAL}.
================================================================

The unmask dynamic module (.so) can only be loaded by an nginx whose
version exactly matches the build-time version (= ABI compatibility).

How to fix:
  (1) Obtain a plugin built for the host's nginx version.  Example:
       unmask-plugin-nginx-X.Y.Z-nginx_${ACTUAL}.x86_64.rpm

  (2) Rebuild on another host:
       make build-module      NGINX_VERSION=${ACTUAL}
       make package-plugin-nginx NGINX_VERSION=${ACTUAL}

  (3) Give up the plugin and run in auth_request mode (= unmask main
      package alone is enough).  You lose the JA4 fingerprint, but every
      other feature still works.

================================================================
EOF
            exit 1
        fi
        ;;
esac
