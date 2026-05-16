#!/bin/sh
if command -v apachectl >/dev/null 2>&1; then
    echo "unmask-web-apache: snippet removed.  remember to:"
    echo "  sudo apachectl graceful"
fi
exit 0
