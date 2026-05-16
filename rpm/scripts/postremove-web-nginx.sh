#!/bin/sh
# unmask-web-nginx postremove.  After the conf.d snippet is removed, prompt to reload nginx.
# We do NOT auto-reload (= the file may still exist via rpm/deb type=config|noreplace).

# Remove the symlinks the postinstall created (= prevents dangling links).
for link in /etc/nginx/conf.d/00-unmask.conf \
            /etc/nginx/conf.d/00-unmask-upstream.conf \
            /etc/nginx/conf.d/00-unmask-rendered.conf; do
    if [ -L "$link" ]; then
        rm -f "$link"
    fi
done

if command -v nginx >/dev/null 2>&1; then
    echo "unmask-web-nginx: snippet removed.  remember to:"
    echo "  sudo nginx -s reload"
fi

exit 0
