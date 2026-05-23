# unmask

> **The bot challenge that respects search engines.**
> JA4 TLS fingerprint + behavioral checks.

Website: **https://unmask.sh/**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--release-orange.svg)](#status)

**unmask** is a self-hosted bot management gateway for nginx and Apache.
It combines JA4 TLS fingerprinting with behavioral checks to distinguish
legitimate search / AI crawlers from disguised scrapers, with search-bot
preservation as the default posture.

## Features

- **Two-stage search-bot rescue** — UA list + official IP range double-check. Designed not to break Googlebot / GPTBot / ClaudeBot.
- **JA4 fingerprint** — Computed from the TLS handshake. Exposes headless Chromium / Puppeteer / Playwright through their UA disguise.
- **Behavioral CAPTCHA** — 5-axis score from mouseTrail / scroll / window-size. Harder to defeat than a plain checkbox or PoW.

## Install

Official install guide: **https://unmask.sh/install/**

rpm / deb / apk packages, per-HTTP-server snippets, and an install wizard — step by step.

## Docs

Official docs: **https://unmask.sh/docs/**

Mode selection (native / auth_request), JA4 via load balancer, per-server config examples, FAQ.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Status

**pre-release (v0.1)** — Packages, install wizard, and per-HTTP-server support are complete.

Security reports (see [SECURITY.md](SECURITY.md)) get priority response.
Bug reports, documentation fixes, and PRs are reviewed regularly.

## License

Apache 2.0. See [LICENSE](LICENSE) / [NOTICE](NOTICE).
