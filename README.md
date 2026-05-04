# unmask

**Unmask the bots that pretend to be browsers.**

unmask is a JA4 TLS-fingerprint based bot challenge system for nginx.
It targets bots that lie about their UA (e.g. claim to be Chrome but
have a JA4 of headless Chromium / Puppeteer / Playwright), while letting
honest bots (curl, ClaudeBot, Googlebot...) pass through unchallenged.

## Why another bot challenge

There are excellent OSS challenge tools (Anubis, CrowdSec) and great
commercial bot managers (Cloudflare, DataDome). unmask aims for a niche
those don't fully cover:

- **TLS fingerprint as the primary signal**, not just JS heuristics
  (Anubis is JS-only; we add JA4 verdicts)
- **Search engine and AI crawler whitelist** baked in (UA + IP),
  so a Googlebot / GPTBot scraping spree never gets stuck on a PoW page
- **CAPTCHA fallback** when PoW alone is not enough, with a behavioral
  checkbox + math escape hatch
- **One RPM**: nginx module + challenge page + admin dashboard ship together,
  installed on a stock nginx with `yum install unmask`

## Status

🚧 **early development** — extracted from a production deployment as a
clean-room reusable distribution. C module compiles and loads but the
build matrix (per-nginx-version prebuilt `.so`) is not yet automated.

## Architecture

```
[client] ─TLS─▶ nginx
                 │
                 ├─ unmask JA4 module (.so)
                 │   • SSL_client_hello_cb
                 │   • compute JA4
                 │   • expose $client_ja4
                 │
                 ├─ unmask config snippet
                 │   • verdict map (bot_/suspect_/ok)
                 │   • final_challenge map (UA × verdict × bv cookie)
                 │   • rate_limit zone (100r/min)
                 │
                 ├─ /unmask/challenge.html  ─proxy_pass─▶ admin app
                 │                                          (PoW + CAPTCHA)
                 │
                 └─ /unmask/api/...         ─proxy_pass─▶ admin app
                                                            • PoW verify
                                                            • CAPTCHA verify
                                                            • debug beacons
                                                            • _bv cookie issue (HMAC-SHA1)

[admin app] (Python / FastAPI / uvicorn, systemd unit)
   • SQLite (default) / MariaDB (optional)
   • web UI with funnel, 30-day chart, IP popovers, country breakdown
```

## Components

| Path | Purpose |
|------|---------|
| `ja4-module/` | nginx dynamic module (C, Apache 2.0) computing JA4 from ClientHello |
| `challenge/`  | static `bot-challenge.html` (PoW + CAPTCHA UI) |
| `admin/`      | FastAPI app for verify endpoints + dashboard |
| `nginx/`      | conf snippets (verdict map, rate_limit, location blocks) |
| `sql/`        | SQLite / MariaDB schema for `unmask_event` (replaces `bot_challenge_debug`) |
| `rpm/`        | RPM spec, build scripts |
| `docs/`       | architecture / migration / spec docs |

## Heritage

This system was first developed inside a Mojolicious/Perl codebase. The
extraction documents (`docs/migration-from-mojo.md`) describe what was
ported and what was rewritten so newcomers can read the production-tested
ideas without needing the original Perl.

## License

Apache 2.0 (clean-room implementation; not derived from FoxIO's BSL-licensed
JA4 reference module).
