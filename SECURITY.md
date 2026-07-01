# Security Policy

## Reporting a Vulnerability

**Please do not open a public issue for security vulnerabilities.**

Report security issues privately to **oss@unmask.sh**.

What we will do:

- Acknowledge your report within **48 hours** (best effort).
- Investigate and provide updates as we go.
- Coordinate a fix and a disclosure timeline with you.

If you do not hear back within 7 days, please escalate by opening a
public issue **without disclosing the vulnerability** (just say "I have
a security report awaiting acknowledgement"). PGP is not currently
required.

## Coordinated Disclosure

We follow a coordinated disclosure process:

- **90-day window** from the initial report to public disclosure.
- We may publish details earlier once a fix has shipped.
- We do not pursue legal action against good-faith researchers who:
  - report responsibly through the channel above,
  - do not access or modify data beyond what is necessary to demonstrate the issue,
  - do not run testing against production deployments of other users.

## Supported Versions

While unmask is pre-release (v0.x), we only provide security fixes for
the **latest released version**. After v1.0 we expect to support the
latest minor release; older releases will be best-effort.

## Out of Scope

The following are not in scope for this project's security advisories:

- Vulnerabilities in nginx, OpenSSL, MariaDB, or other upstream
  dependencies — please report those to the respective upstream.
- Operator misconfiguration of unmask (e.g. exposing the admin UI to
  the public internet without authentication).
- Issues that require running unmask on an end-of-life OS or with
  rate-limiting disabled.
- Denial-of-service attacks at the network layer (use Cloudflare /
  AWS Shield etc. upstream).

## Recognition

Reporters are credited in the release notes for the fix, unless they
ask to remain anonymous.
