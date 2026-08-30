# unmask nginx image: the official nginx image plus the unmask dynamic module.
#
#   docker build -f docker/nginx/Dockerfile -t ghcr.io/unmask-sh/nginx:1.28.3 .
#
# Two ways to run it:
#
#   module-only  Bring your own nginx.conf / conf.d, exactly as on a host
#                install: `include /etc/unmask/http.inc;` etc. in http scope,
#                `include /etc/unmask/server.inc;` in the vhost.  The admin
#                container renders those files into the shared /etc/unmask
#                volume.
#
#   gateway      Set UNMASK_UPSTREAM=http://app:3000 (plus TLS cert / key on
#                /etc/unmask/tls) and this container terminates TLS on :443,
#                classifies with JA4, and proxies what passes to the upstream.
#                Any HTTP server behind it -- nothing to install on the app.
#                See docker/nginx/10-unmask-gateway.sh.
#
# The module is built from source against the exact nginx version of the
# runtime image, with --with-compat, so the signature matches the official
# binary.  NGINX_VERSION must be a tag that exists at nginx.org AND on Docker
# Hub (1.28.3 is the stable line at the time of writing; 1.30.x mainline works
# the same way).
ARG NGINX_VERSION=1.28.3

# --- build stage: compile only the module -------------------------------------
FROM debian:bookworm-slim AS build
ARG NGINX_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libssl-dev libpcre2-dev zlib1g-dev curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
RUN curl -fsSL "https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz" | tar -xz
COPY nginx-module/ /src/nginx-module/
RUN cd "nginx-${NGINX_VERSION}" \
    && ./configure --with-compat \
                   --with-http_ssl_module \
                   --with-http_realip_module \
                   --with-http_auth_request_module \
                   --add-dynamic-module=/src/nginx-module \
    && make -j"$(nproc)" modules

# --- runtime: the official image, untouched apart from the module -------------
FROM nginx:${NGINX_VERSION}
ARG NGINX_VERSION
LABEL org.opencontainers.image.source="https://github.com/unmask-sh/unmask" \
      org.opencontainers.image.description="nginx ${NGINX_VERSION} with the unmask JA4 bot-challenge module" \
      org.opencontainers.image.licenses="Apache-2.0"
COPY --from=build /src/nginx-${NGINX_VERSION}/objs/ngx_http_unmask_module.so \
                  /etc/nginx/modules/ngx_http_unmask_module.so
# The challenge page is served by nginx itself (the module rewrites to it), so
# it ships in this image, same path as the host packages use.
COPY admin/assets/static/challenge.html admin/assets/static/challenge.js /usr/share/unmask/challenge/
# load_module has to sit in main context; prepend it to the stock nginx.conf
# rather than replacing the file, so upstream changes to that file keep
# flowing through.  The rendered includes land in /etc/unmask (shared volume
# with the admin container); /run/unmask carries the access-log socket.
# The official image ships nginx's own ACME module (ngx_http_acme_module,
# nginx-module-acme); loading it costs nothing when unused and lets the
# gateway do automatic HTTPS with one variable (UNMASK_ACME_EMAIL).  Its
# state directory must be writable by the worker user and should persist.
RUN sed -i '1i load_module modules/ngx_http_unmask_module.so;\nload_module modules/ngx_http_acme_module.so;' /etc/nginx/nginx.conf \
    && mkdir -p /etc/unmask /run/unmask /etc/unmask/tls /var/cache/nginx/unmask-acme \
    && chown nginx:nginx /var/cache/nginx/unmask-acme \
    && nginx -t
VOLUME ["/var/cache/nginx/unmask-acme"]
# .envsh: the stock entrypoint sources it, so the defaults it exports reach
# the envsubst step that renders the gateway template (a .sh would run in a
# subprocess and lose them).
COPY --chmod=0755 docker/nginx/10-unmask-gateway.envsh /docker-entrypoint.d/10-unmask-gateway.envsh
COPY docker/nginx/gateway.conf.template /usr/share/unmask/gateway.conf.template
COPY docker/nginx/gateway-includes.sh /usr/share/unmask/gateway-includes.sh
COPY docker/nginx/gateway-http.conf.template /usr/share/unmask/gateway-http.conf.template
COPY docker/nginx/gateway-https.conf.template /usr/share/unmask/gateway-https.conf.template
# Reloads nginx when the admin container re-renders the includes, so a
# settings change applies without anyone running `nginx -s reload`.
COPY --chmod=0755 docker/nginx/30-unmask-autoreload.sh /docker-entrypoint.d/30-unmask-autoreload.sh
# The entrypoint skips a non-executable file even when it would only source it.
RUN test -x /docker-entrypoint.d/10-unmask-gateway.envsh && test -x /docker-entrypoint.d/30-unmask-autoreload.sh
