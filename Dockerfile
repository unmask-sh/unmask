# unmask admin image (= multi-stage Go build → minimal runtime).
# Published per release as ghcr.io/unmask-sh/admin:<version>.
#
# Use:
#   docker build -t ghcr.io/unmask-sh/admin:latest .
#   docker run -p 9477:9477 -v unmask-data:/var/lib/unmask -v unmask-config:/etc/unmask \
#       ghcr.io/unmask-sh/admin:latest
#   → http://localhost:9477/unmask/admin/  for the install wizard (the setup
#     token is printed in the container log).
#
# multi-arch:
#   docker buildx build --platform linux/amd64,linux/arm64 -t ghcr.io/unmask-sh/admin:latest .
#
# This image is the admin daemon only.  The nginx side is a second image --
# the official nginx image with the unmask module (docker/nginx/Dockerfile,
# published as ghcr.io/unmask-sh/nginx:<nginx version>) -- or a host nginx
# from rpm/deb.  docker-compose.example.yml wires the two containers.

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
FROM alpine:3.21 AS runtime
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

# No USER here on purpose.  A named volume takes its ownership from whichever
# container first populates it; when that is the nginx sidecar, /etc/unmask
# arrives root-owned and a non-root entrypoint cannot write admin.yml (seen on
# the first compose bring-up).  The entrypoint starts as root, fixes the
# ownership of the three volumes, and hands over to the binary, which drops to
# the `unmask` user itself before doing anything else -- the same path a
# host install takes under systemd.
EXPOSE 9477
VOLUME ["/var/lib/unmask", "/etc/unmask", "/run/unmask"]

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["serve", "-config", "/etc/unmask/admin.yml"]
