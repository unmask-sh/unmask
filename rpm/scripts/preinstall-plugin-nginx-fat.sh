#!/bin/sh
# preinstall for unmask-plugin-nginx (fat).
#
# The fat package bundles .so files for multiple nginx versions, so we do
# NOT abort on nginx version mismatch (postinstall picks the best match).
# Installing the plugin on a host without nginx is pointless, so just warn.
#
# Note: do NOT use `set -e` / `set -u`.  This preinst has no abort path.
# dash / busybox ash `if ! cmd` interaction and `set -u` unset-var checks
# have caused preinst to flip to exit 1 (reproduced 2026-05-10 on deb12 e2e).
# Unified to warn-and-continue → explicit success via trailing `exit 0`.

nginx_path=$(command -v nginx 2>/dev/null || true)
if [ -z "$nginx_path" ]; then
    # Avoid heredoc (= old dash + dpkg context tripped on it; reported 2026-05-11 [B]).
    # Use multiple echos to emit the warning to stderr.
    echo "WARNING: nginx command not found." >&2
    echo "  unmask-plugin-nginx is the plugin that loads the dynamic module" >&2
    echo "  into nginx itself.  If you install nginx later, reinstall the plugin" >&2
    echo "  (rpm -e + rpm -ivh) so postinstall detects nginx and places the" >&2
    echo "  module in the right path." >&2
    echo "" >&2
    echo "  (= If running forward-auth mode with only the unmask main package, the plugin is not needed.)" >&2
fi
exit 0
