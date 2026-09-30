# unmask image: the gateway in one container -- the official nginx image with
# the unmask module, plus the unmask daemon, supervised by one entrypoint.
# Published per release as ghcr.io/unmask-sh/unmask:<version> and mirrored at
# unmask.sh/unmask.
#
#   docker run -d --name unmask -p 80:80 -p 443:443 \
#       --add-host host.docker.internal:host-gateway \
#       -v unmask-config:/etc/unmask -v unmask-data:/var/lib/unmask \
#       -v unmask-acme:/var/cache/nginx/unmask-acme \
#       unmask.sh/unmask:latest
#   docker logs unmask | grep "setup token"
#   -> https://<host>/unmask/admin/  (the install wizard; paste the token)
#
# Inside: the daemon (admin UI, challenge verification, ban list, stats)
# renders the nginx includes into /etc/unmask and listens on 127.0.0.1:9477;
# nginx terminates TLS (that is where JA4 comes from), classifies, and either
# serves the challenge or proxies to the upstream (Settings > Gateway).
# docker/gateway-entrypoint.sh starts the daemon, waits for it, starts nginx
# through the stock entrypoint, and keeps both up.
#
# The module is built from source against the exact nginx version of the
# runtime image, with --with-compat, so the signature matches the official
# binary.  NGINX_VERSION must be a tag that exists at nginx.org AND on Docker
# Hub.  Multi-arch: docker buildx build --platform linux/amd64,linux/arm64 .
ARG NGINX_VERSION=1.28.3

# -------------------------------------------------------------------------
# build stage: the Go static binary
# -------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
ARG UNMASK_VERSION=docker

WORKDIR /src
RUN apk add --no-cache git ca-certificates

# COPY module files first to leverage the go mod cache.
COPY admin/go.mod admin/go.sum ./admin/
RUN cd admin && go mod download

COPY admin/ ./admin/

RUN cd admin && \
    CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w -X main.Version=$UNMASK_VERSION" \
    -o /out/unmask ./cmd/unmask

# -------------------------------------------------------------------------
# module stage: compile only the module, against this nginx version
# -------------------------------------------------------------------------
FROM debian:bookworm-slim AS modbuild
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

# -------------------------------------------------------------------------
# runtime: the official nginx image + the module + the daemon
# -------------------------------------------------------------------------
FROM nginx:${NGINX_VERSION}
ARG NGINX_VERSION
LABEL org.opencontainers.image.source="https://github.com/unmask-sh/unmask" \
      org.opencontainers.image.description="unmask: the bot-challenge gateway (nginx ${NGINX_VERSION} with the JA4 module, plus the unmask daemon)" \
      org.opencontainers.image.licenses="Apache-2.0"

COPY --from=modbuild /src/nginx-${NGINX_VERSION}/objs/ngx_http_unmask_module.so \
                     /etc/nginx/modules/ngx_http_unmask_module.so
# The challenge page is served by nginx itself (the module rewrites to it),
# same path as the host packages use.
COPY admin/assets/static/challenge.html admin/assets/static/challenge.js /usr/share/unmask/challenge/
# load_module has to sit in main context; prepend it to the stock nginx.conf
# rather than replacing the file, so upstream changes to that file keep
# flowing through.  The official image ships nginx's own ACME module; loading
# it costs nothing when unused and lets the gateway do automatic HTTPS with
# one variable (UNMASK_ACME_EMAIL).  Its state directory must be writable by
# the worker user and should persist (a volume).
RUN sed -i '1i load_module modules/ngx_http_unmask_module.so;\nload_module modules/ngx_http_acme_module.so;' /etc/nginx/nginx.conf \
    && mkdir -p /etc/unmask /run/unmask /etc/unmask/tls /var/cache/nginx/unmask-acme \
    && chown nginx:nginx /var/cache/nginx/unmask-acme \
    && nginx -t
# .envsh: the stock entrypoint sources it, so the defaults it exports reach
# the envsubst step that renders the gateway template.
COPY --chmod=0755 docker/nginx/10-unmask-gateway.envsh /docker-entrypoint.d/10-unmask-gateway.envsh
COPY docker/nginx/gateway.conf.template /usr/share/unmask/gateway.conf.template
COPY docker/nginx/gateway-includes.sh /usr/share/unmask/gateway-includes.sh
COPY docker/nginx/gateway-http.conf.template /usr/share/unmask/gateway-http.conf.template
COPY docker/nginx/gateway-https.conf.template /usr/share/unmask/gateway-https.conf.template
# Reloads nginx when the daemon re-renders the includes, so a settings change
# applies without anyone running `nginx -s reload`.
COPY --chmod=0755 docker/nginx/30-unmask-autoreload.sh /docker-entrypoint.d/30-unmask-autoreload.sh
RUN test -x /docker-entrypoint.d/10-unmask-gateway.envsh && test -x /docker-entrypoint.d/30-unmask-autoreload.sh

# The daemon: a pure-Go static binary, its own user (the binary drops to it
# right after start, as under systemd), and the directories it owns.
RUN useradd --system --user-group --home-dir /var/lib/unmask --shell /usr/sbin/nologin unmask \
    && mkdir -p /var/lib/unmask /var/log/unmask \
    && chown -R unmask:unmask /var/lib/unmask /var/log/unmask /etc/unmask /run/unmask
COPY --from=build /out/unmask /usr/local/bin/unmask
# First boot: a minimal config.yml (the wizard fills in the rest), migrate,
# render; then the daemon.  The same script the daemon-only image used.
COPY --chmod=0755 docker/entrypoint.sh /usr/local/bin/unmask-daemon.sh
# Both processes, one PID 1: see the script for what it does when one dies.
COPY --chmod=0755 docker/gateway-entrypoint.sh /usr/local/bin/gateway-entrypoint.sh

# This image IS the gateway: on by default (UNMASK_GATEWAY=0 turns the
# container into nginx-with-module plus the daemon, your own conf.d applies).
# The daemon and nginx share the container, so the addresses are loopback.
ENV UNMASK_GATEWAY=1 \
    UNMASK_DAEMON_ADDR=127.0.0.1:9477 \
    UNMASK_GATEWAY_ADDR=127.0.0.1:443
EXPOSE 80 443
VOLUME ["/etc/unmask", "/var/lib/unmask", "/var/cache/nginx/unmask-acme"]
HEALTHCHECK --interval=10s --timeout=3s --start-period=30s --retries=6 \
    CMD curl -fsS -o /dev/null http://127.0.0.1:9477/unmask/healthz && test -f /run/nginx.pid
STOPSIGNAL SIGTERM
ENTRYPOINT ["/usr/local/bin/gateway-entrypoint.sh"]
