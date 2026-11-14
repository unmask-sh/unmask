# unmask

> **The bot challenge that respects search engines.**
> Proof-of-work first, a CAPTCHA only when it looks automated.

Website: **https://unmask.sh/**

[![CI](https://github.com/unmask-sh/unmask/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/unmask-sh/unmask/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/unmask-sh/unmask?color=brightgreen)](https://github.com/unmask-sh/unmask/releases)
[![Go](https://img.shields.io/badge/go-1.27-00ADD8.svg)](https://go.dev/)
[![Distros](https://img.shields.io/badge/distros-RHEL%20%7C%20Debian%20%7C%20Ubuntu%20%7C%20Alpine-success.svg)](https://unmask.sh/install/)

![unmask in a minute: a first visit clears a short proof-of-work on a page carrying the site's own logo; a scraper gets the challenge instead of the page; Googlebot, Bingbot, GPTBot and ClaudeBot pass by their published IP ranges; one click denies AI training crawlers while AI search fetches still pass; the dashboard and the log show every challenged request and why](https://unmask.sh/static/demo/unmask-demo.gif)

**unmask** is a self-hosted bot management gateway for nginx: a dynamic
module in the nginx you already run, or a gateway container in front of any
other HTTP server.  It layers signals -- the JA4 TLS fingerprint, the
network (ASN), the country, the request rate, honeypot paths and a shared
ban list -- and answers with a challenge that grows with suspicion: a
proof-of-work that runs by itself for ordinary visitors, its own behavioral
CAPTCHA when a visit looks automated or matches a rule you set, and a block
only where you choose one.  Search and AI crawlers pass by default, verified
by their published IP ranges wherever the vendor publishes them.

## Features

- **Challenges that grow with suspicion** — Ordinary visitors clear a proof-of-work in the background, with no click; a visit that looks automated, or matches a rule you set, gets the built-in behavioral CAPTCHA (no third-party service, no site key), or Cloudflare Turnstile, hCaptcha or reCAPTCHA v3 in its place. Blocking is opt-in. The challenge page carries your logo and speaks 18 languages.
- **Two-stage search-bot rescue** — A User-Agent list double-checked against the vendors' published IP ranges, so Googlebot, GPTBot or ClaudeBot pass and a look-alike User-Agent alone does not. One click refuses AI training crawlers while AI search fetches still pass.
- **Layered signals** — The JA4 TLS fingerprint (ban a tool, not just an address), network (ASN), country, request rate, honeypot paths and User-Agent rules.
- **Community Bans** — An anonymous ban list shared across installs, scored in five confidence tiers. Pulling it is on by default and enforced as a challenge (a block only if you choose one), and it can be switched off; sending your own reports is opt-in. The hub keeps reporting installs' addresses only as per-day salted hashes, scrubbed after 30 days.
- **Built-in admin UI** — Dashboard, bot hunt, abuse signals and settings. argon2id password hashes, CSRF protection and a per-address login rate limit.
- **Two ways to deploy** — The native nginx dynamic module, or the gateway container: nginx with the module in front of any HTTP server (Apache, Node, anything).
- **Web Bot Auth and Privacy Pass (opt-in)** — Signed AI agents (RFC 9421 HTTP Message Signatures) and attested clients (Privacy Pass, RFC 9577/9578) pass without a challenge. Off by default behind an Advanced switch.

## Install

The install guide takes you through either way, step by step: **https://unmask.sh/install/**

- **Running nginx?** Use the native module — the recommended setup. Signed rpm / deb / apk packages for x86_64 and arm64 put it into the nginx you already run, and an install wizard does the rest.
  → https://unmask.sh/install/
- **Apache, Node or anything else — or you would rather run a container?** The gateway image, `unmask.sh/unmask`, is the official nginx image with the module plus the daemon in one container, placed in front of your server (served from unmask.sh, mirrored on GHCR).
  → https://unmask.sh/install/#gateway

### Requirements

- **nginx**, one of the versions the plugin package bundles a module for
  (1.10.3 up to 1.30.6), built `--with-compat`: the distributions' packages
  are (Alpine's own from 3.23 on), and so are nginx.org's.  The plugin places
  the module built for exactly the version `nginx -v` reports; when there is
  none, it says so and leaves nginx running without unmask
  ([FAQ](https://unmask.sh/docs/faq/#nginx-version)).  An nginx built from
  source, by hand or by a hosting panel, also needs
  `--with-http_realip_module`, and gets two `include` lines to add to its
  `nginx.conf` (the install guide has them).  The rpm and deb packages
  install no nginx: install it first.
- **OS**: RHEL / Rocky / AlmaLinux, Debian, Ubuntu and Alpine, on x86_64 and
  arm64; the packages are installed on ten distributions before each
  release.  Anything else runs the gateway container.
- **Database**: SQLite by default, nothing to set up; or MariaDB
  (`db.driver: mariadb`).  PostgreSQL is not supported.
- **Behind a load balancer or a CDN**, nginx must see the visitor's address:
  enable the vendor's preset under Settings › Network › Trusted LB / CDN and
  "Take the visitor's address from X-Forwarded-For (realip)".  Otherwise
  every visitor shares the proxy's address, and so do the rate limits and
  bans.
- **HTTP/3** connections carry a JA4 fingerprint only on nginx 1.29.0 or
  newer with OpenSSL 3.5.1 or newer (or quictls)
  ([details](https://unmask.sh/docs/ja4/)).
- **Cost**: about 0.05 ms per request that carries a pass, and 10 MB of
  shared memory for each rate-limit zone (five by default).

### Quick start (nginx, native module)

About ten minutes from a shell on a host that runs nginx.

1. Install `unmask-release`, the repository definition and the signing keys:
   - RHEL / Rocky / AlmaLinux:
     `sudo dnf install -y https://unmask.sh/dl/rpm/unmask-release-latest.noarch.rpm`
   - Debian / Ubuntu: download https://unmask.sh/dl/deb/unmask-release-latest.deb,
     then `sudo apt install ./unmask-release-latest.deb && sudo apt update`
   - Alpine: download https://unmask.sh/dl/apk/unmask-release-latest.apk, then
     `sudo apk add --allow-untrusted ./unmask-release-latest.apk && sudo apk update`
     (only this package, which carries the key, is installed unverified)
2. `sudo dnf install unmask unmask-plugin-nginx unmask-web-nginx` (`apt install` /
   `apk add`, same names): the daemon with the admin UI, the nginx module and
   the nginx snippets.  The plugin places the `load_module` line, or says
   where to add it.
3. Add `include /var/lib/unmask/nginx/server.inc;` to the site's `server { }`
   block, then `sudo nginx -t && sudo systemctl restart nginx` (a restart:
   nginx loads a module only when it starts).
4. Open `https://<your-host>/unmask/admin/setup/` and paste the setup token
   the install printed (`sudo cat /var/lib/unmask/.setup-token`).
5. Protect a location: `include /var/lib/unmask/nginx/protect.inc;` inside its
   `location { }`, then `sudo nginx -t && sudo systemctl reload nginx`.  In a
   regex location, read the path with a named capture
   (`location ~ ^/api/(?<rest>.+)$` and `$rest`): unmask's maps reset `$1`..`$9`.
6. Check: `curl -sS -o /dev/null -w '%{http_code}\n' https://<your-host>/<that path>`
   answers 403 (the challenge page), a browser clears the proof-of-work and
   gets the page, and the admin's Bot hunt page shows both requests and why.

The gateway container instead: `docker compose -f docker-compose.example.yml up -d`,
then the wizard at `https://localhost/unmask/admin/` (the token is in
`docker compose logs unmask`).  Upgrading an existing install:
[UPGRADING.md](UPGRADING.md).

### Uninstall

`sudo dnf remove unmask unmask-plugin-nginx unmask-web-nginx` (`apt remove` /
`apk del`) takes the module and its `load_module` out of nginx and lists the
lines of your own configuration that still include unmask's files.  Remove
those (nginx refuses its configuration while they are there), then
`sudo nginx -t && sudo systemctl restart nginx`.  `/etc/unmask` (config.yml,
with its secrets), `/var/lib/unmask` (the database) and the `unmask` user
stay for a reinstall; delete them by hand when they are no longer wanted.

### Package signing

Every rpm and every apk is signed, and so is the apt repository's index,
which carries the checksum of every deb (a deb has no signature of its own);
`unmask-release` installs the keys, and the package manager checks
everything it installs after it.  A file from a release page is checked
against that release's signed `checksums.txt`
(`gpg --verify checksums.txt.sig checksums.txt`, then `sha256sum`), and the
raw binaries, the SBOM and the container image also carry provenance
attestations (`gh attestation verify unmask-linux-amd64 --repo unmask-sh/unmask`).
Fingerprints, to cross-check with https://unmask.sh/keys/:

- OpenPGP, rpm / deb (`RPM-GPG-KEY-unmask`):
  `C03D D45E 28C4 446F DDC4  8EFC 34A3 20B5 44B2 8158`
- Alpine RSA, apk (`unmask.rsa.pub`), SHA-256 of the DER public key:
  `63:77:6a:f3:57:b7:be:aa:db:2a:83:67:9d:ae:46:42:ac:78:6d:ad:49:95:9b:7c:1f:cb:3d:16:5c:c9:a5:dc`

## Docs

The install guide, the FAQ and the JA4 / load balancer page:
**https://unmask.sh/docs/**.  What this README leaves out:

- Settings and editing `config.yml`: [FAQ](https://unmask.sh/docs/faq/#config-yml)
- Several nodes behind a load balancer: [FAQ](https://unmask.sh/docs/faq/#several-nodes)
- Monitoring -- Prometheus metrics, health probes, a Grafana dashboard: [FAQ](https://unmask.sh/docs/faq/#prometheus-metrics)
- What the built-in CAPTCHA stops, and a provider in its place: [FAQ](https://unmask.sh/docs/faq/#builtin-captcha)
- A site Content-Security-Policy and the challenge page: [FAQ](https://unmask.sh/docs/faq/#content-security-policy)
- What each release asks and how to roll back: [UPGRADING.md](UPGRADING.md); the threat model: [SECURITY.md](SECURITY.md)

## What it stores

For every request it judges, the daemon records the address, the
User-Agent, the JA4 fingerprint, the host and path, and the verdict: raw
events for 7 days by default (`events_retention_days`; 0 keeps everything),
hourly aggregates for 32 days, bans until they expire or you lift them.
Everything stays on the host, in the database you chose.  On its own it
fetches from unmask.sh the update check, the shared ban list (with the
install's registration), the crawler IP ranges, the browser-version list and
the IP-geo database; each can be switched off
([FAQ](https://unmask.sh/docs/faq/#outbound-connections)).  Sending your own
reports to Community Bans and the AI advisor are opt-in.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).  Security reports
([SECURITY.md](SECURITY.md)) get priority response; bug reports,
documentation fixes and pull requests are reviewed regularly.

## Status

**Released**, and running in production on the author's own sites.  Still
0.x: a release can rename or remove a settings key, and most ask nginx for a
reload or a restart; [UPGRADING.md](UPGRADING.md) lists each one.

## License

Apache 2.0. See [LICENSE](LICENSE) / [NOTICE](NOTICE).
