# Build nginx 1.26 + the unmask dynamic module in one go.
#
# Multi-stage: build stage produces nginx + module, then copies to the runtime stage.
# This is a minimal e2e build (not the distributed RPM), so only the required modules
# are included.

ARG NGINX_VERSION=1.26.2

FROM debian:12-slim AS build
ARG NGINX_VERSION
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential libssl-dev libpcre2-dev zlib1g-dev curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
# The tarball is checked against the sha256 pinned in the repo before it is
# unpacked, by the same script the Makefile and the builder containers use.
COPY tools/fetch-nginx-src.sh /src/tools/fetch-nginx-src.sh
COPY nginx-module/nginx-sha256sums.txt /src/nginx-module/nginx-sha256sums.txt
RUN /src/tools/fetch-nginx-src.sh "${NGINX_VERSION}" /src

COPY nginx-module/ /src/nginx-module/
COPY tools/check-so-hardening.sh /src/tools/check-so-hardening.sh

# Built with the options the shipped module is built with
# (nginx-module/hardening.sh), so the scenarios run the binary the packages
# carry in every respect but the nginx around it: a module that only loads
# or only works without them would otherwise pass here and fail on a host.
RUN cd nginx-${NGINX_VERSION} \
    && ./configure --with-compat --with-http_ssl_module \
                   --with-http_realip_module \
                   --with-http_auth_request_module \
                   --with-cc-opt="$(sh /src/nginx-module/hardening.sh cc)" \
                   --with-ld-opt="$(sh /src/nginx-module/hardening.sh ld)" \
                   --add-dynamic-module=/src/nginx-module \
    && make -j"$(nproc)" \
    && sh /src/tools/check-so-hardening.sh objs/ngx_http_unmask_module.so

# Runtime stage
FROM debian:12-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libpcre2-8-0 zlib1g openssl apache2-utils \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --no-create-home --shell /usr/sbin/nologin nginx \
    && mkdir -p /usr/sbin /usr/lib/nginx/modules /etc/nginx \
                /var/log/nginx /var/lib/nginx/body /var/lib/nginx/proxy \
                /var/lib/nginx/fastcgi /var/lib/nginx/uwsgi /var/lib/nginx/scgi \
                /run/unmask /etc/unmask/nginx /usr/share/unmask/challenge

ARG NGINX_VERSION
COPY --from=build /src/nginx-${NGINX_VERSION}/objs/nginx /usr/sbin/nginx
COPY --from=build /src/nginx-${NGINX_VERSION}/objs/ngx_http_unmask_module.so \
                  /usr/lib/nginx/modules/ngx_http_unmask_module.so

# Only the challenge HTML/JS lives inside the image.  nginx-rendered*.conf is
# generated at admin-container startup and shared with the nginx container via
# the /etc/unmask volume.
COPY admin/assets/static/challenge.html admin/assets/static/challenge.js /usr/share/unmask/challenge/
COPY e2e/docker/nginx/nginx.conf /etc/nginx/nginx.conf
# Stock config for the comparison service (scenario 55): same binary, no module.
COPY e2e/docker/nginx/stock.conf /etc/nginx/stock.conf
# Static content for /fo-dir/ and /fo-app/ (scenarios 35 / 62): a directory
# with an index file and a try_files fallback page.
RUN mkdir -p /srv/e2e/fo-dir /srv/e2e/fo-app \
    && printf '[unmask e2e index]\n' > /srv/e2e/fo-dir/index.html \
    && printf '[unmask e2e fallback]\n' > /srv/e2e/fo-app/fallback.html

# self-signed cert (= e2e only.  Clients are expected to skip verification with --insecure / -k)
RUN openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
    -keyout /etc/nginx/key.pem -out /etc/nginx/cert.pem \
    -subj "/CN=unmask-e2e/O=unmask"

EXPOSE 8443
# -c is required because we didn't pass --prefix at ./configure; the binary's
# compiled-in default conf path is /usr/local/nginx/conf/nginx.conf which is
# not where COPY landed it.
CMD ["/usr/sbin/nginx", "-c", "/etc/nginx/nginx.conf", "-g", "daemon off;"]
