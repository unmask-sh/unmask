# Third-Party Notices

unmask is licensed under [Apache License 2.0](LICENSE).  Per Apache 2.0 §4 and
the upstream MIT / BSD / Apache attribution requirements, this file lists
notable third-party components that ship with the unmask packages or that the
unmask source pulls in at build time, along with the license of each.

The full text of each license is reproduced inline below where the license
requires reproduction.

----

## Go runtime dependencies (= compiled into `unmask`)

### Direct

| Module | Version | License |
|---|---|---|
| github.com/go-sql-driver/mysql | v1.8.1 | MPL-2.0 |
| github.com/oschwald/maxminddb-golang | v1.13.1 | ISC |
| gopkg.in/yaml.v3 | v3.0.1 | MIT + Apache-2.0 |
| modernc.org/sqlite | v1.34.5 | BSD-3-Clause |

### Indirect (= pulled in by the modules above)

| Module | Version | License |
|---|---|---|
| filippo.io/edwards25519 | v1.1.0 | BSD-3-Clause |
| github.com/dustin/go-humanize | v1.0.1 | MIT |
| github.com/google/uuid | v1.6.0 | BSD-3-Clause |
| github.com/mattn/go-isatty | v0.0.20 | MIT |
| github.com/ncruces/go-strftime | v0.1.9 | MIT |
| github.com/remyoudompheng/bigfft | (commit) | BSD-3-Clause |
| golang.org/x/crypto | v0.50.0 | BSD-3-Clause |
| golang.org/x/exp | (pre-release) | BSD-3-Clause |
| golang.org/x/sys | v0.43.0 | BSD-3-Clause |
| golang.org/x/term | v0.42.0 | BSD-3-Clause |
| modernc.org/libc | v1.61.4 | BSD-3-Clause |
| modernc.org/mathutil | v1.6.0 | BSD-3-Clause |
| modernc.org/memory | v1.8.0 | BSD-3-Clause |

Run `go mod download && go mod why <module>` inside `admin/` for the live tree,
and `cat $(go env GOMODCACHE)/<module>@<ver>/LICENSE` for the verbatim license
text of any specific module.

----

## Data files embedded in the package

### crawler-user-agents.json

unmask embeds [monperrus/crawler-user-agents][cua] (a curated list of search /
AI / monitoring crawler User-Agent strings) into the admin binary at build
time.  Used for the `SearchBots` preset which makes Googlebot / GPTBot /
ClaudeBot / etc. bypass the challenge.

License: **MIT**.

[cua]: https://github.com/monperrus/crawler-user-agents

```
The MIT License (MIT)

Copyright (c) 2015 Martin Monperrus

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
```

----

## Optional runtime data (= NOT bundled, fetched on demand)

### DB-IP Lite (IP-geolocation database)

`unmask install-ipgeo` downloads DB-IP Lite (= `dbip-country.mmdb` /
`dbip-asn.mmdb`) from db-ip.com to `/var/lib/unmask/ipgeo/`.

License: **Creative Commons Attribution 4.0 International (CC BY 4.0)**.

Required attribution:

> IP Geolocation by DB-IP — <https://db-ip.com/>

Per CC BY 4.0 §3, an attribution copy is also placed at
`/usr/share/doc/unmask/IPGEO-ATTRIBUTION.txt` by the package's postinstall.

----

## nginx dynamic module (= `unmask-plugin-nginx`)

The C source under `nginx-module/` is original to this project.  It is built
against the public nginx headers and links against OpenSSL at runtime; the
unmask source does NOT reference FoxIO's BSL-licensed ja4-nginx-module
source (see CONTRIBUTING.md "Clean-room reimplementation").

The JA4 fingerprint specification itself is from FoxIO and is published
openly at <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md>.
Reading the spec to implement a compatible parser is fine; lifting code from
the BSL-licensed reference implementation is not, and we have not done so.

nginx itself: 2-clause BSD.  OpenSSL: dual OpenSSL / SSLeay (OpenSSL 1.x) or
Apache-2.0 (OpenSSL 3.x).  Both ship with the host distro, not with unmask.

----

## Visitor-side JavaScript (= `challenge.html` / `challenge.js`)

Plain hand-written JavaScript.  No external runtime library is loaded by
default.

3rd-party CAPTCHA support (= Cloudflare Turnstile / hCaptcha / Google
reCAPTCHA v3) is opt-in via the admin UI.  When enabled, the visitor's
browser fetches the respective provider's JS from the provider's CDN at
challenge time.  Those providers' terms apply to whatever data they collect.

----

## Reporting an attribution gap

If you spot a missing attribution, please open an issue or email
oss@unmask.sh — we will correct it in the next release.
