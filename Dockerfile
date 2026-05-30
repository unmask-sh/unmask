# unmask: single image (= multi-stage Go build → minimal runtime).
#
# Use:
#   docker build -t unmask/admin:latest .
#   docker run -p 9477:9477 -v unmask-data:/var/lib/unmask unmask/admin:latest
#   → http://localhost:9477/unmask/admin/  for the install wizard.
#
# multi-arch:
#   docker buildx build --platform linux/amd64,linux/arm64 -t unmask/admin:latest .
#
# Note: this image is admin only.  Pair it with a separate nginx + unmask
# module image (= see e2e/docker/nginx/Dockerfile) or install the host nginx
# from rpm/deb.  docker-compose.example.yml shows a combined setup.

# -------------------------------------------------------------------------
# build stage: Go static binary
# -------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS build
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
# runtime stage: scratch + ca-certs + tzdata only.  Pure-Go binary, so no
# shell needed.  Alpine base allows `docker exec` for debugging.
# -------------------------------------------------------------------------
FROM alpine:3.20 AS runtime
RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S unmask && \
    adduser  -S -G unmask -H -h /var/lib/unmask -s /sbin/nologin unmask && \
    mkdir -p /var/lib/unmask /var/log/unmask /etc/unmask /run/unmask && \
    chown -R unmask:unmask /var/lib/unmask /var/log/unmask /etc/unmask /run/unmask

COPY --from=build /out/unmask /usr/local/bin/unmask

# If admin.yml is missing at startup, generate a minimal one (= install wizard
# captures the DB etc.).  No-op if it already exists.
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 0755 /usr/local/bin/entrypoint.sh

USER unmask
EXPOSE 9477
VOLUME ["/var/lib/unmask", "/etc/unmask"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["serve", "-config", "/etc/unmask/admin.yml"]
