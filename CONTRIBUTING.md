# Contributing

Thanks for your interest in unmask. Bug reports, documentation fixes, and
small focused PRs are all welcome.

## Reporting bugs

Open an issue with:

- distro / version (`cat /etc/os-release`)
- nginx version (`nginx -v`) or web server you use
- relevant log lines (`journalctl -u unmask` — `/var/log/unmask.log` on SysVinit, `docker logs unmask` for the container — and your web server's error log)
- reproduction steps

For suspected security issues, **please do not open a public issue** —
follow [SECURITY.md](SECURITY.md) (report privately through GitHub's
vulnerability report form).

## Development setup

unmask is three components in one repo:

- `admin/` — Go static binary (`unmask`). Requires the Go version in `admin/go.mod` (1.27+).
- `nginx-module/` — C plugin (`ngx_http_unmask_module`). Built against
  matching nginx source.
- `admin/assets/static/challenge.{html,js}` — plain JavaScript challenge
  page. No build step.

```sh
# admin binary
cd admin && go build -o unmask ./cmd/unmask

# rpm/deb/apk packages (= nfpm)
make package
```

End-to-end tests live in `e2e/` and run against the dockerized stack.

## Running the tests

What CI runs, and how to run each part here before a push:

```sh
# Go: unit tests (the handlers package takes a few minutes), vet, gofmt.
cd admin && go test ./... && go vet ./... && gofmt -l .
# The i18n catalogs: parity of ja / en, no mixed-up locale, every key a
# template uses.  Run whenever i18n.go or a template changes.
cd admin && go test ./internal/i18n/
# The same tests against MariaDB (they skip without a server): starts a
# throwaway mariadb container, so it needs docker.
make test-mariadb
# A real nginx over what the renderer writes: builds the oldest nginx
# supported (NGINX_TEST_VERSION=1.30.6 for the newest) with the module and
# runs `nginx -t` on a table of configurations.  Run whenever a template or
# the renderer changes; needs a C compiler and the OpenSSL / PCRE headers.
make test-nginx-accepts
# golangci-lint, exactly as CI runs it (pins the Go version from go.mod).
make lint
# The C parsers: unit tests, the same under ASan/UBSan, and the fuzzers.
make test-plugin-parser test-plugin-parser-san fuzz-plugin
# The package scripts (install, upgrade, removal, against a throwaway root).
for t in rpm/scripts/*_test.sh; do bash "$t"; done
# Production figures and node names must not reach public text.
./tools/check-public-text.sh
# The docker e2e stack: nginx + the module + the daemon, 70-odd scenarios.
make e2e-docker
# The packages, through install, upgrade and removal on Ubuntu, AlmaLinux and
# Alpine containers, each with its package manager and nginx (docker, nfpm).
make e2e-lifecycle-modern
# The admin UI in a browser (node + a Chromium; `npm ci` in e2e/ui first).
# UI_E2E_ONLY=<substring> runs the matching test files alone.
make e2e-ui
cd e2e/ui && UI_E2E_ONLY=crawler-modes ./run.sh
```

A change to a template is covered by the handlers tests and the UI
tests; a change to the module or its build also runs the module-matrix
workflow in CI (every nginx version the plugin ships).

## Pull request guidelines

- One logical change per PR. Split unrelated changes.
- Match the existing code style — Go uses `gofmt`; C follows the nginx
  source style.
- Update `CHANGELOG.md` under `[Unreleased]` with a brief entry.
- Run `go test -timeout 20m ./...` from `admin/` before submitting (the
  handlers package can take longer than go test's default ten minutes on a
  slow machine).
- forward-auth mode is frozen: its decision path
  (`admin/internal/handlers/auth_check.go`, reached through `auth_request` or
  Apache `mod_lua`) takes bug and security fixes only.  Wire a new feature into
  the nginx module path (the `nginxconf` templates and the module); it needs no
  forward-auth counterpart.

## Release gate

CI runs on every push: Go lint, vet and tests (the MariaDB ones against a
server of their own), the C parsers' unit tests and a sanitizer fuzz, the module built against a few recent nginx versions,
the container images, the docker e2e stack (`make e2e-docker`, which
anyone can run), and the packages through install, upgrade and removal on
three distributions (`make e2e-lifecycle-modern`).  When the module or its build changes, a second workflow
(`module-matrix`) builds the .so against every nginx version the plugin
package ships -- fifteen, from 1.10.3 to the current stable -- against
OpenSSL 3 and, in containers whose recipes are under `build-docker/`,
OpenSSL 1.1, OpenSSL 1.0 and glibc 2.12; every .so in the plugin package
can be rebuilt from this tree.  Every build reads its hardening back out of
the .so, and one .so of each container-built set is loaded into an nginx of
that ABI (`make module-load-test`).  Before a release the
maintainer also installs the packages on a lab of real distributions
(`make distro-check`: the official install path on ten distributions,
CentOS 6 among them, through to `nginx -t`, the module loading and a
challenged request), which needs the lab and is not part of CI.

## Clean-room reimplementation

The JA4 parser in `nginx-module/` is implemented from the public JA4
specification (https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md)
alone.  FoxIO's reference nginx module is published under the Business
Source License: do not consult its source while working on the parser, and
do not copy from it.  A PR that lifts code from it is not merged.
`THIRD-PARTY-NOTICES.md` records what the tree does bundle and the license
of each piece; keep it, and `NOTICE`, in step with `admin/go.mod` when a
dependency changes.

## Commit messages

- Subject line: imperative, under ~70 chars, prefixed by area
  (`admin:`, `nginx:`, `challenge:`, `docs:`, `rpm:`, etc.).
- Body: explain the *why*, not the *what*.
- English only for new commits (the historical log contains Japanese for
  pre-OSS history).

## Code language policy

All files in the repository must be written in English — including comments,
log messages, and identifiers.

Exceptions (preserved as Japanese):

- `admin/internal/i18n/i18n.go` Japanese locale values
- `admin/assets/static/challenge.js` Japanese i18n maps
- The `<option value="ja">日本語</option>` picker native name

## Developer Certificate of Origin (DCO)

Every commit must carry a `Signed-off-by:` trailer that asserts you have
the right to submit the change under the project's license.  We follow
the [Developer Certificate of Origin 1.1](https://developercertificate.org/).

The trailer is one line at the bottom of the commit message:

```
Signed-off-by: Your Name <you@example.com>
```

`git commit -s` adds it automatically.  By including it you are stating
the four conditions in the DCO 1.1 text (= roughly: you wrote it, or you
have permission from whoever did, and you are OK with it being open-source
under the project's license).

A simple lightweight alternative to a CLA — no separate document to sign,
the assertion is in the commit history itself.

## License

By contributing, you agree that your contributions will be licensed under
the Apache License 2.0 (see `LICENSE`).
