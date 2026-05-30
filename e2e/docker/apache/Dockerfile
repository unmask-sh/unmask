# Apache httpd + mod_lua running the unmask forward-auth snippet.
#
# This container exercises the *real* shipped Apache integration —
#   snippets/apache-forward-auth.conf + snippets/apache-unmask.lua
# — on a real Apache httpd.  Every request goes through the mod_lua handler,
# which does an internal /_unmask/check subrequest to the admin container and
# branches pass / challenge / block.  A tiny DocumentRoot is served on "pass".
#
# The snippet ships pointing at 127.0.0.1:9477 (= same-host loopback, the
# production layout).  In compose the admin is a separate service, so the
# admin host:port is rewritten to admin:9477 at build time — exactly the
# documented "Change 127.0.0.1:9477 if needed" install step.

FROM debian:12-slim

# mod_lua.so ships inside apache2-bin (a dependency of apache2) on Debian 12 —
# there is no separate libapache2-mod-lua package, a2enmod lua is enough.
# lua-socket gives the mod_lua handler an HTTP client to reach unmask
# (mod_lua has none of its own); it installs into Lua 5.3's path, which is the
# version mod_lua links against on Debian 12.
RUN apt-get update && apt-get install -y --no-install-recommends \
        apache2 lua-socket curl ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && a2enmod proxy proxy_http lua headers rewrite remoteip

# e2e-only: trust X-Forwarded-For so scenario 14 can present a distinct source
# IP per case (= the same isolation scenarios 05/12/13 get by injecting
# X-Original-IP).  mod_remoteip rewrites r.useragent_ip, which the snippet's
# lua already reads — the shipped snippet is exercised unchanged.  Not part of
# the production snippet; this is the e2e equivalent of admin.yml's test knobs.
RUN printf 'RemoteIPHeader X-Forwarded-For\nRemoteIPTrustedProxy 172.16.0.0/12 10.0.0.0/8 192.168.0.0/16\n' \
        > /etc/apache2/conf-available/remoteip-e2e.conf \
    && a2enconf remoteip-e2e

# Apache listens on 8081 in this image (the e2e harness publishes 8081).
RUN sed -i 's/^Listen 80$/Listen 8081/' /etc/apache2/ports.conf \
    && sed -i 's/<VirtualHost \*:80>/<VirtualHost *:8081>/' \
        /etc/apache2/sites-available/000-default.conf

# Tiny origin served when unmask returns "pass".
RUN echo '[unmask e2e apache backend]' > /var/www/html/index.html

# Install the *real* shipped snippet + lua handler, then apply the two
# documented per-environment edits: point at the compose admin service and
# use the Debian lua path (the snippet's own note covers both).
COPY snippets/apache-forward-auth.conf /etc/apache2/conf-available/unmask.conf
COPY snippets/apache-unmask.lua        /etc/apache2/unmask.lua
RUN sed -i 's#127\.0\.0\.1:9477#admin:9477#g' \
        /etc/apache2/conf-available/unmask.conf /etc/apache2/unmask.lua \
    && sed -i 's#/etc/httpd/unmask.lua#/etc/apache2/unmask.lua#' \
        /etc/apache2/conf-available/unmask.conf \
    && a2enconf unmask

# Enable unmask on this VirtualHost (= opt-in per VirtualHost — same single
# line the install page tells operators to drop into their <VirtualHost>).
# The snippet's LuaHookAccessChecker is commented out by default so installing
# the package does not silently auto-protect every VirtualHost; e2e exercises
# the documented opt-in step exactly as production operators would.
RUN sed -i 's|<VirtualHost \*:8081>|<VirtualHost *:8081>\n    LuaHookAccessChecker /etc/apache2/unmask.lua handle_request|' \
        /etc/apache2/sites-available/000-default.conf

EXPOSE 8081
CMD ["sh", "-c", ". /etc/apache2/envvars && mkdir -p \"$APACHE_RUN_DIR\" && exec apache2 -D FOREGROUND"]
