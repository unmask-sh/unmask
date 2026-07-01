# unmask: build the pure-Go static binary in a multi-stage image.
#
# Uses the same build flags as the distributed dist/unmask.
# If you want to reuse `make build-admin` output from CI, switching to a
# host-build → COPY pattern is faster (= skips the in-image go install).

FROM golang:1.25-alpine AS build
WORKDIR /src
RUN apk add --no-cache git
# admin is a standalone module.  Bundles embed assets like crawler-user-agents.json.
COPY admin/go.mod admin/go.sum ./admin/
RUN cd admin && go mod download
COPY admin/ ./admin/
RUN cd admin && CGO_ENABLED=0 go build \
    -trimpath -ldflags="-s -w -X main.Version=docker-e2e" \
    -o /out/unmask ./cmd/unmask

# Runtime stage is alpine, not scratch (= shell required / for debugging)
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/unmask /usr/local/bin/unmask
RUN mkdir -p /var/lib/unmask /run/unmask /etc/unmask
COPY e2e/docker/admin/admin.yml /etc/unmask/admin.yml
# Trust the e2e Web Bot Auth test CA (scenario 34): the daemon fetches the
# fake operator's JWK directory over TLS from the nginx container.  System
# trust store, exactly how a production operator would provision a private CA
# — the product itself never embeds one.
COPY e2e/docker/wba/ca.crt /usr/local/share/ca-certificates/unmask-e2e-wba-ca.crt
RUN update-ca-certificates

# admin listens on 9477 (= reachable as http://admin:9477/ from the nginx container in compose).
EXPOSE 9477
ENTRYPOINT ["/usr/local/bin/unmask"]
CMD ["serve", "-config", "/etc/unmask/admin.yml"]
