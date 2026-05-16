# Contributing

Thanks for your interest in unmask. This is a small project — bug reports,
documentation fixes, and small focused PRs are all welcome.

## Reporting bugs

Open an issue with:

- distro / version (`cat /etc/os-release`)
- nginx version (`nginx -v`) or web server you use
- relevant log lines (`/var/log/unmask/` and your web server's error log)
- reproduction steps

For suspected security issues, **please do not open a public issue.**
Email the maintainer instead (address listed in commit metadata).

## Development setup

unmask is three components in one repo:

- `admin/` — Go static binary (`unmask-admin`). Requires Go 1.25+.
- `nginx-module/` — C plugin (`ngx_http_unmask_module`). Built against
  matching nginx source.
- `admin/assets/static/challenge.{html,js}` — plain JavaScript challenge
  page. No build step.

```sh
# admin binary
cd admin && go build -o unmask-admin ./cmd/unmask-admin

# rpm/deb/apk packages (= nfpm)
make packages
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

## License

By contributing, you agree that your contributions will be licensed under
the Apache License 2.0 (see `LICENSE`).
