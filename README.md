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
- **Web Bot Auth (RFC 9421)** — ed25519 + RSA-PSS HTTP Message Signature verify with JWK thumbprint dedup. Signed AI agents (Anthropic / OpenAI / etc.) pass through without challenge.
- **Community Bans (opt-in)** — Anonymous BAN feed shared across installs. 5-tier confidence score combines heuristic + AI judge. GDPR by design (= per-day salted IP hashes, 30-day prune, raw IPs never stored).
- **Built-in admin UI** — dashboard / hunt / abuse signals / settings. bcrypt + cookie session + CSRF + per-IP login rate-limit.
- **Two deploy modes** — native nginx dynamic module (~0.05 ms post-cookie) or forward-auth fallback for Apache / Caddy / Traefik / Envoy / HAProxy.

## Quickstart

```sh
# rpm (= AlmaLinux / RHEL / Rocky / CentOS)
sudo dnf install -y https://unmask.sh/dl/rpm/unmask-release-latest.noarch.rpm
sudo dnf install -y unmask unmask-web-nginx unmask-plugin-nginx

# deb (= Debian / Ubuntu)
sudo apt install -y https://unmask.sh/dl/deb/unmask-release-latest.deb
sudo apt update
sudo apt install -y unmask unmask-web-nginx unmask-plugin-nginx

# apk (= Alpine): add the signing key + repo first
sudo wget -O /etc/apk/keys/oss@unmask.sh-260509.rsa.pub https://unmask.sh/dl/keys/oss@unmask.sh-260509.rsa.pub
echo "https://unmask.sh/dl/apk/main" | sudo tee -a /etc/apk/repositories
sudo apk add unmask unmask-web-nginx unmask-plugin-nginx

# Open https://your-host/unmask/admin/setup/ to finish the install wizard.
```

Full install guide: **https://unmask.sh/install/**

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
