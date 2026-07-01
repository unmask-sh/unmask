# unmask

> **The bot challenge that respects search engines.**
> JA4 TLS fingerprint + behavioral checks.

Website: **https://unmask.sh/**

[![CI](https://github.com/unmask-sh/unmask/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/unmask-sh/unmask/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Status](https://img.shields.io/badge/status-pre--release-orange.svg)](#status)
[![Go](https://img.shields.io/badge/go-1.25-00ADD8.svg)](https://go.dev/)
[![Distros](https://img.shields.io/badge/distros-RHEL%20%7C%20Debian%20%7C%20Ubuntu%20%7C%20Alpine-success.svg)](https://unmask.sh/install/)

**unmask** is a self-hosted bot management gateway for nginx and Apache.
It combines JA4 TLS fingerprinting with behavioral checks to distinguish
legitimate search / AI crawlers from disguised scrapers, with search-bot
preservation as the default posture.

## Features

- **Two-stage search-bot rescue** — UA list + official IP range double-check. Designed not to break Googlebot / GPTBot / ClaudeBot.
- **JA4 fingerprint** — Computed from the TLS handshake. Exposes headless Chromium / Puppeteer / Playwright through their UA disguise.
- **Behavioral CAPTCHA** — 5-axis score from mouseTrail / scroll / window-size. Harder to defeat than a plain checkbox or PoW.
- **Community Bans** — Anonymous BAN feed shared across installs. 5-tier confidence score combines heuristic + AI judge. Pulling the shared list is ON by default (CAPTCHA-only enforcement, so a mismatched human still passes; flip `subscribe_mode` off to disconnect); submitting your own reports is opt-in (country is tagged by default — opt out in settings). GDPR by design (= per-day salted IP hashes, 30-day prune, raw IPs never stored).
- **Built-in admin UI** — dashboard / hunt / abuse signals / settings. bcrypt + cookie session + CSRF + per-IP login rate-limit.
- **Two deploy modes** — native nginx dynamic module (~0.05 ms post-cookie) or forward-auth fallback with a shipped example for Apache (the check endpoint speaks the standard forward-auth contract, so any HTTP server can wire it the same way).
- **Web Bot Auth + Privacy Pass (opt-in)** — RFC 9421 HTTP Message Signatures (ed25519 / RSA-PSS) and Privacy Pass / Apple PAT (RFC 9577/9578). Signed AI agents (Anthropic / OpenAI / etc.) and attested clients pass through without a challenge. Off by default behind an Advanced switch, since the ecosystem is still small.

## Install

Official install guide: **https://unmask.sh/install/**

rpm / deb / apk packages, per-HTTP-server snippets, and an install wizard — step by step.

## Docs

Official docs: **https://unmask.sh/docs/**

Mode selection (native / forward-auth), JA4 via load balancer, per-server config examples, FAQ.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## Status

**pre-release (v0.1)** — Packages (x86_64 + arm64), install wizard, and per-HTTP-server support are complete.

Security reports (see [SECURITY.md](SECURITY.md)) get priority response.
Bug reports, documentation fixes, and PRs are reviewed regularly.

## License

Apache 2.0. See [LICENSE](LICENSE) / [NOTICE](NOTICE).
