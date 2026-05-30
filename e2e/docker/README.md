# e2e docker stack

Docker-compose version of the bare-metal e2e suite (= `make e2e BASE_URL=https://...`).
Lets GitHub Actions or any other host run the full check with a single
`make e2e-docker`.

## Layout

```
e2e/docker/
├── docker-compose.yml      # admin + nginx + apache + tmpfs socket volume
├── admin/
│   ├── Dockerfile          # golang build → alpine
│   └── admin.yml           # fixed e2e secret
├── nginx/
│   ├── Dockerfile          # nginx 1.26 + unmask.so build
│   ├── nginx.conf          # minimal config (demo-equivalent)
│   └── secret.conf         # bv_secret synced with admin
├── apache/
│   └── Dockerfile          # httpd + mod_lua running the forward-auth snippet
└── README.md               # this file
```

The `apache` service runs the real shipped snippet (`snippets/apache-forward-auth.conf`
+ `apache-unmask.lua`) and is exercised by scenario 14. It talks HTTP to the
admin container, so it needs no shared volume. Published on `localhost:8081`.

## Running

```sh
# Uses the host build cache (subsequent runs are fast)
make e2e-docker
```

What happens internally:

1. `docker compose build` builds the admin + nginx images.
2. `docker compose up -d` starts them and waits on healthcheck.
3. `BASE_URL=https://localhost:8443 ./e2e/run.sh` runs all scenarios.
4. `docker compose down` tears it all down.

## tmpfs socket volume

unmask binds a Unix datagram socket at `/run/unmask/log.sock`, and the
nginx worker writes via `access_log syslog:server=unix:/run/unmask/log.sock`.
Both containers share a named volume called `unmask-run`. The socket file lives
on tmpfs, so no stale file is left behind across restarts.

## CI integration

Add this to `.github/workflows/ci.yml` to run automatically on PR:

```yaml
- name: e2e
  run: make e2e-docker
```

## Notes

- The self-signed cert is generated with openssl during image build. CN is
  fixed since this is e2e-only.
- Fixed values like `e2e-docker-bv-secret-do-not-use-in-prod` are baked into
  both the docker and nginx images. (In production, generate via
  `unmask config-init`.)
- Initial `make e2e-docker` image build takes 5–10 minutes (nginx compile + go
  module download). Subsequent runs are under a minute thanks to image cache.
