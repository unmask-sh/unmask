#!/bin/sh
if command -v caddy >/dev/null 2>&1; then
    echo "unmask-web-caddy: snippet removed.  remember to:"
    echo "  sudo systemctl reload caddy"
fi
exit 0
