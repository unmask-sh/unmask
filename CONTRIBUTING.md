# Contributing

Thanks for your interest in unmask. Bug reports, documentation fixes, and
small focused PRs are all welcome.

## Reporting bugs

Open an issue with:

- distro / version (`cat /etc/os-release`)
- nginx version (`nginx -v`) or web server you use
- relevant log lines (`/var/log/unmask/` and your web server's error log)
- reproduction steps

For suspected security issues, **please do not open a public issue** —
follow [SECURITY.md](SECURITY.md) (report privately to oss@unmask.sh).

## Development setup

unmask is three components in one repo:

- `admin/` — Go static binary (`unmask`). Requires Go 1.25+.
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

## Pull request guidelines

- One logical change per PR. Split unrelated changes.
- Match the existing code style — Go uses `gofmt`; C follows the nginx
  source style.
- Update `CHANGELOG.md` under `[Unreleased]` with a brief entry.
- Run `go test ./...` from `admin/` before submitting.

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
