# Changelog

Change history for unmask.  Format follows [Keep a Changelog](https://keepachangelog.com/).
Versioning follows [Semantic Versioning](https://semver.org/).

## Conventions

- Each entry starts with `(YYYY-MM-DD HH:MM)` for the start time. For long-running
  work, use the completion time. Timezone is the host's local time (mostly JST).
  Short entries use minute precision.
- Within a release, entries are sorted by date descending (newest at top).

## [0.1.0] — 2026-05-25

### Added
- (2026-05-25) **Ubuntu 22.04 LTS in the verified install matrix**.  Closes
  the only remaining nginx version gap between alma8 (1.14.1) and
  alma9/centos7 (1.20.1) -- 22.04 ships nginx 1.18.0, which the fat
  plugin already bundles; the CI just wasn't exercising that .so against
  a real box.  Verified end-to-end: `apt install unmask-plugin-nginx` on
  a fresh box pulls in nginx + lands the matching 1.18.0 .so + the
  challenge page returns http=403 size=18297.

- (2026-05-25) **Shared `partial_events_table` for the overview + hunt
  recent-events tables**.  Both pages now render the same session-collapse
  logic (= group rows by beacon_token into one outcome row with a chain
  of phase pills), so the overview Recent Detections card matches the
  hunt log row-for-row with no separate maintenance path.

### Changed
- (2026-05-25) **`bypass_ips` switched to the `enabled_presets` opt-in
  schema** that `bypass_paths` and `protected_paths` already use.  The
  yaml field renames from `bypass_ip_disabled_presets` to
  `bypass_ip_enabled_presets`, and the in-memory `BypassIPEnabledPresets`
  is a list of IDs to turn ON.  Defaults() ships every shipped group ID
  in that list so the "search bot rescue" safety net is preserved; new
  presets in a later release stay OFF until the operator opts in via
  the existing SeenVersion / IsNew gate.  Existing config.yml files with
  the old `bypass_ip_disabled_presets` field have it dropped silently on
  load (= no compat code; the single operator re-toggles whatever they
  intentionally disabled).

- (2026-05-25) **Light-theme `info-popup` family across every admin
  page**.  The legacy slate-800 hover popup on hunt / dashboard /
  overview / settings is now a white card with a slate-300 border,
  matching the `[data-popover]` chip popovers already used in settings
  tabs.  Behaviour (hover / click-to-pin / drag / collapse / copy /
  ESC LIFO) is unchanged; 49 popovers across the admin app become a
  single visual component.

- (2026-05-25) **Pinned popup is portal'd out of the events table's
  scroll container** so the phase-help popup on the recent-events panel
  no longer clips against `.events-scroll`.  The same portal handles
  the `max-height: <viewport>-2rem` cap when the help body is long.

### Fixed
- (2026-05-25) **`unmask-plugin-nginx` now declares nginx as a hard
  install dependency** in the rpm / deb / apk metadata.  Without this,
  the documented install order (= unmask -> plugin -> web-nginx) ran the
  plugin's postinstall before nginx existed; postinstall would fall back
  to `nginx not installed, skipped placing the module` and never lay
  down `/usr/lib/nginx/modules/ngx_http_unmask_module.so`.  Subsequent
  steps installed nginx via `unmask-web-nginx` but did not re-trigger
  the plugin's placement, so `nginx -t` passed but the challenge
  silently never fired.  Adding `nginx` to Depends/Requires lets the
  package manager pull nginx in before the plugin postinstall runs, so
  the matching .so lands on the first install attempt regardless of
  package order.  Surfaced while adding Ubuntu 22.04 to the CI matrix:
  the existing distro test VMs all had nginx pre-installed at snapshot
  time, masking the order issue on fresh boxes.

- (2026-05-25) **Overview help tips no longer get shadowed by local
  CSS**.  `overview.html` carried a copy of the original dark
  `.info-popup` rule that won the cascade against the shared
  `popover-pin.css`, so help tips on the overview page stayed dark even
  after the global migration.  Removed the duplicate.

<!-- ============================================================
     Entries from 2026-05-24 and earlier follow.  All part of the
     same 0.1.0 release; date prefixes provide the timeline.
     ============================================================ -->

### Added
- (2026-05-24) **Alpine first-class native-mode support**: `apk add
  unmask unmask-plugin-nginx unmask-web-nginx` reaches `http=403 +
  challenge HTML` end-to-end on Alpine 3.x.  Three changes make this work:
  (a) `unmask-plugin-nginx` apk metadata depends on `gcompat`, which
  provides the glibc compat layer that lets Alpine's musl-linked nginx
  dlopen the bundled glibc-built .so; (b) postinstall-web-nginx detects
  Alpine's `http.d/` vs RHEL/Debian `conf.d/` by parsing nginx.conf for
  which dir is inside http {}, so upstream / map directives land in the
  right scope; (c) postinstall-plugin-nginx-fat branches on gcompat
  presence -- present means full native-mode install, absent means the
  old skip-with-hint fallback.  JA4 fingerprinting is available on
  Alpine too.  LP install page now lists Alpine without a "v0.1 only
  supports auth_request" caveat.  OpenRC init script symlink is set up
  automatically.

- (2026-05-24) **build-repo.sh apk latest alias**: the apk stage now writes
  `unmask-release-latest.apk` next to the versioned file, mirroring what
  rpm and deb stages already do, so install docs can link to a stable URL.

- (2026-05-23) **Challenge page branding feature**: optional logo, site
  name, footer text, copy preset (= friendly / neutral / minimal), and
  unmask credit toggle, all editable from the theme tab in the admin UI
  with a live preview iframe per theme × preset.

- (2026-05-23) **18-language preset translations** for the challenge copy
  (= ja / en + zh / zht / ko / es / pt / fr / de / ru / it / tr / pl / vi /
  th / id / ar / hi).  Preset switching takes effect regardless of the
  visitor's locale.

- (2026-05-23) **CAPTCHA box fade-in**: .25s opacity + translateY transition
  on captcha appearance, with `prefers-reduced-motion` disabling the
  animation entirely.

### Fixed
- (2026-05-24) **SELinux blocked the auth_request subrequest on RHEL family**:
  postinstall-web-nginx now auto-applies `setsebool -P
  httpd_can_network_connect 1` when SELinux is Enforcing, so nginx can
  proxy_pass to the unmask-admin loopback socket.  Opt out with
  `UNMASK_SKIP_SETSEBOOL=1`.  Fixes the "challenge silently does not fire"
  symptom on alma8 / alma9 / alma10 / centos7 (= the install-matrix run
  confirmed http=403 + challenge page on all 8 distros after the fix).

- (2026-05-24) **postinstall-web-nginx on Alpine**: `mkdir -p
  /etc/nginx/conf.d` so Alpine (= ships only http.d/ by default but
  still includes conf.d/*.conf in nginx.conf) accepts the existing
  conf.d/00-unmask*.conf symlinks without forking the install path.

- (2026-05-24) **install-test-official.sh centos6 quoting**: centos6 has
  been dropped from the default keys list -- the docker-bullseye legacy
  SSH proxy mangles `"`-literals in cleanup_rpm / fire_check bodies
  (`bash: +en: command not found`, `sh: 12: Syntax error: "then"
  unexpected`).  centos6 stays a manual-verify target per the
  centos6-support memory; pass `centos6` explicitly to opt in.

### Changed
- (2026-05-23) **Apache forward-auth is now explicit per-VirtualHost
  opt-in**: snippets/apache-forward-auth.conf ships with
  `LuaHookAccessChecker` commented out, matching nginx mode's per-server
  `include protect.inc;` mental model.  Installing the package no longer
  silently turns on auth on every VirtualHost; operators add the single
  LuaHook line inside the `<VirtualHost>` they want to protect.  The
  global `/unmask/*` ProxyPass stays in conf.d so the admin UI / challenge
  HTML / static assets remain reachable from every VirtualHost.

- (2026-05-23) **install page nginx config examples** are reorganised so
  the shared 3 elements (= `# unmask` + `include server.inc;` +
  `location @unmask_admin_down { ... }`) are fixed across all 3 scopes,
  and only `include protect.inc;` placement varies by scope -- outside
  any location for whole-site, inside the target location for path-only,
  inside the catch-all `location /` for the exclude pattern.

- (2026-05-24) **CI workflow** (= .github/workflows/ci.yml): Go 1.22 →
  1.25 to match go.mod and release.yml; push / pull_request triggers
  now include the multi-site branch (= the current v0.1 dev branch).

- (2026-05-23) **README + LP product tone sweep**: dropped "handled when
  time permits" hedge in README status; LP TOP use case 03 rewritten to
  "SaaS-non-outsourced"; competitor product names removed across LP / docs;
  "nginx" generalised to "httpd" where the message applies to multiple
  HTTP servers.

### Added
- (2026-05-19) **IP-geo (ipgeo) UX overhaul**: per-country geo rule axis,
  one-click DB-IP Lite install, network-tab radio (DB-IP / custom / none),
  Country/City vs ASN section split, mmdb vendor detection badges
  (MaxMind / DB-IP / IP2Location / Unknown).<br>
  - New CLI: `unmask-admin install-ipgeo [-kind country|asn] [-path PATH]`.<br>
  - New endpoint: `POST /admin/api/ipgeo/install?kind=country|asn` (= 1-click
    web button, reuses the same library).<br>
  - Default path: `/var/lib/unmask/ipgeo/{dbip-country,dbip-asn}.mmdb`.<br>
  - Postinstall opt-in: set `UNMASK_AUTO_INSTALL_MMDB=1` to fetch on first
    install.  Off by default (= offline-friendly).<br>
  - Attribution + cron sample shipped under `/usr/share/doc/unmask/`.<br>
  - Trademark distance: package + path naming renamed from `geoip` to
    `ipgeo` (MaxMind owns the GEOIP trademark; lowercase usage is common in
    OSS but we keep brand neutrality).<br>
  - DB-IP Lite is CC BY 4.0, redistribution allowed with attribution; we
    download on demand rather than bundling (= file size + freshness).

- (2026-05-19) **Per-country Geo rule axis** (`settings.geo`): rule list
  with autocomplete (250 countries × JP/EN names), per-row action
  (skip / pow_only / captcha_only / pow_then_captcha / deny), bulk
  toolbar (= multi-select + apply).  Decision lives in `auth_check.go`
  as a score-axis (= max severity).

- (2026-05-19) **max(severity) decision pipeline**: refactored auth_check
  to evaluate every score axis (geo / honeypot / ban / protected / ja4 /
  UA) and pick the harshest action.  Veto axes (bypass_ips, bypass_paths,
  `_bv` cookie pass) remain hard short-circuits.  Side-effects (= honeypot
  BAN add) fire regardless of who wins the max.  Reason carries
  suppressed runner-up axes for hunt-page transparency.

- (2026-05-19) **JA4-keyed rate-limit**: new `rate_limit.key` enum
  (`ip` / `ja4` / `ip+ja4`).  Composite keys reuse the same zones; nginx
  and admin-side accounting stay in sync.

- (2026-05-19) **Settings audit + 1-click rollback**: every settings_save
  captures full before/after yaml in `unmask_user_audit.detail`,
  computes a unified-diff text, and the audit page exposes a "Restore"
  button (superadmin only).  Manual snapshot via "Take snapshot" button
  uses the same storage.  Yaml export downloads the live config.

- (2026-05-19) **doctor SLO self-curl**: probes `/unmask/healthz` × 30
  samples and reports p50 / p95 / max latency.  Warns at p95 > 100 ms.

- (2026-05-19) **doctor mmdb age / vendor / geo-rule sanity**: each
  installed mmdb shows vendor + DatabaseType + build date + age (WARN at
  35+ days).  Geo rules with unknown ISO codes surface a WARN
  (= silently inactive otherwise).

- (2026-05-19) **AI traffic overview**: new card on `/admin/` aggregating
  upstream crawler-user-agents.json tags into 5 buckets (search /
  training / agent / scraper / collector).  Shows total / served /
  passed / pass-rate per category over the last 24h.

- (2026-05-19) **e2e scenarios 12 + 13** covering max-severity
  composition (= JP + JA4 bot, CN deny override etc.) and isolated
  geo-deny path.  `e2e/scenarios/11-bv-cookie-shadow.sh` guards against
  the duplicate `_bv` cookie regression.

### Fixed
- (2026-05-19) **`_bv` cookie iteration bug**: nginx C plugin and Go
  admin both returned the first `_bv` cookie only.  A stale invalid
  cookie shadowing the freshly-set one would loop visitors through
  challenge forever.  Both sides now iterate every `_bv` and accept
  the first that verifies.  challenge.js additionally evicts stale
  copies at every ancestor path before setting the new one.

- (2026-05-19) **Native-mode `@unmask_rate_challenge` undefined** in
  server.inc.tmpl: rate-limit 429 fell through to nginx's default 500
  page.  Added the named location matching the auth_request mode.

- (2026-05-19) **Audit page rendered only 1 row** due to template loop
  referencing `.Lang` instead of `$.Lang` (template-context shadowing).

- (2026-05-19) **`index out of range` panic** in protected / honeypot /
  ja4-verdicts settings tabs when `Extra*Action` parallel arrays were
  shorter than the canonical rule list.  Pad in handler before render.

- (2026-05-07 19:50) **Eliminated all `bot_*` / `suspect_*` prefix hardcoding from
  JA4 bot judgement**. Verdict names are user-defined (= the action enum is the
  source of truth), but the dashboard SQL and `classify.IsBot` still used
  <code>LIKE 'bot_%'</code> / <code>HasPrefix("bot_")</code>. When a user
  registered an extra rule like <code>verdict="my_internal_tool", action="bot"</code>
  in settings, **stealth counts / StealthRow / classify analytics dropped it**.<br>
  Fix:<br>
  - Added <code>dashboard.BotVerdictNames(settings.Nginx)</code> helper (collects
    verdict names with action=bot/suspect from all presets + extra rules).<br>
  - Changed <code>Funnel</code> / <code>StealthPassed</code> /
    <code>DailyServeByKind</code> / <code>rateLimitFunnelRow</code> SQL to
    <code>IN (?, ?, ...)</code>, with the handler passing the bot-verdict list.<br>
  - Changed <code>classify.IsBot</code> signature to
    <code>(ua, ja4Action string)</code> (prefix check removed, direct comparison
    against the action enum's <code>"bot"</code> / <code>"suspect"</code>).
    Callers (auth_check / playground / queries) updated accordingly.<br>
  - Replaced the hardcoded <code>fixedVerdicts</code> array with dynamic
    generation from <code>nginxconf.JA4VerdictGroups</code>. Preset additions
    are picked up automatically.<br>
  - New shared helper <code>nginxconf.IsBotAction</code> (action-enum check).<br>
  Comments and docstrings that mentioned "judged as bot_*" were also corrected.

- (2026-05-07 16:55) **Fixed `admin_allow_from` IP restriction having no effect**.
  Until now the setting was only reflected in
  <code>nginx-rendered-server.conf</code>; in existing-site deploys (where only
  <code>unmask-locations.inc</code> is added to an existing nginx without
  including the rendered conf), the IP restriction was not enforced at all.<br>
  Fix: **added an equivalent check at the handler layer**
  (<code>AdminIPAllowMiddleware</code>). It runs at the start of AuthMiddleware
  and in front of login / logout, matching the remote IP from
  <code>X-Real-IP</code> / <code>X-Forwarded-For</code> against
  <code>AdminAllowFrom</code>. Both exact and CIDR are supported.<br>
  Also changed the settings default from <code>["127.0.0.1", "::1"]</code> to
  empty, to avoid unintentional lockouts on existing installs that suddenly
  become loopback-only. The install wizard and settings UI still require a
  non-empty value on save. An empty value is interpreted as "allow all"
  (preserving old behavior). The nginx render side keeps a separate
  <code>defaultAllow</code> loopback fallback, so the rendered conf behavior is
  unchanged.

- (2026-05-07 16:35) **Fixed JA4 / verdict always NULL in check-phase events**.
  In `auth_check.go`, `events.Insert` was missing the `JA4` / `JA4Verdict`
  fields (= the values were already extracted into local variables but not
  passed through). Now check events also record the JA4 hash and verdict, and
  rows that showed "-" in the bot-hunt verdict column are resolved.<br>
  Note: requests where the upstream LB does not provide X-Client-JA4 (= TLS
  resumption, some bot-specific handshakes) remain empty. That is an upstream
  concern.

- (2026-05-07 16:05) **Fixed UTC appearing under TZ picker "browser auto"**.
  The production server runs in UTC, and `events.Row.Date` was the server-local
  (= UTC) string. To reformat client-side using the picker's TZ, we needed unix
  seconds. Added an <code>Ts int64</code> field to Row. The hunt raw-log table,
  overview recent, and live-tail SSE now format via <code>data-ts</code> +
  <code>js-datetime</code> using the picker timezone (including browser
  default).

### Changed
- (2026-05-07 19:15) Show `check` phase entries on hunt / overview / live-tail
  as **`check(pass)` / `check(block)`**. The <code>action</code> value inside
  payload_json is extracted server-side (simple string search; JSON parse would
  be overkill) into Row.Action. Pill colors are
  <code>ph-check-pass</code> (green) / <code>ph-check-block</code> (red) for
  visibility. When you see just "check", you can now immediately tell whether
  the request was passed or blocked.

- (2026-05-07 18:50) Switched settings error messages to **flash cookies**.
  Long error text used to ride on the URL via <code>?err=...</code>, which
  looked ugly. Now it's written to a short-lived cookie (60s) on redirect, and
  the next GET's readFlash consumes and displays it. Applied to: settings /
  bans / users / hunt / profile.<br>
  Also **removed required validation** for <code>admin_allow_from</code> /
  <code>metrics_allow_from</code> (empty = allow all is already handled at the
  middleware). A missing setting no longer fails save outright; it falls
  through as "allow all, restrict later".

- (2026-05-07 18:30) Improved the dashboard 30-day stacked bar chart:<br>
  - Removed the hard cap (60px) on bar width; bars are now a constant
    <code>colW × 0.7</code> ratio. With few observed days (2 days / a few),
    bars expand to fill the column. Matches the feel of an internal reference
    dashboard.<br>
  - Legend chips are now **click-to-toggle kind visibility**. Hidden items get
    a strikethrough and gray swatch. State persists in <code>localStorage</code>
    per canvas (reload preserves which kind is hidden). Hidden kinds are
    excluded from the y-axis max calculation and the popover, so the scale
    adjusts cleanly.

### Performance
- (2026-05-07 17:10) **Resolved frequent "(connection error)" on SSE**.<br>
  - Heartbeat 30s → 20s: the default backend response timeout on GCP HTTPS LB
    is 30s, so 30s heartbeats race with LB cutoff. 20s comfortably keeps
    keepalive.<br>
  - In JS onerror, added <code>readyState</code> check: 0 (CONNECTING / auto
    retry) is shown discreetly as "(reconnecting)". Only 2 (CLOSED / true end)
    shows "(SSE connection error)". EventSource auto-retry is normal behavior;
    users shouldn't think it's broken.

- (2026-05-07 16:25) **Live-tail lightening, round 2**, on the hunt tab. Three
  improvements:<br>
  - **SSE poll 1s → 2s**: server-side SQLite query + client-side JSON.parse +
    DOM update halved. Perceived live-tail latency is unchanged.<br>
  - **IntersectionObserver pauses tail when off-screen**: scroll down past the
    live tail and EventSource disconnects instantly. Resumes when it comes
    back. Most of the "events keep flowing in the background" cost came from
    here.<br>
  - **Auto-pause after 5min idle**: no mouse / keyboard / scroll for 5
    minutes, SSE disconnects. Saves tabs left open.<br>
  - Made the scroll listener passive, discretized the pulse animation with
    `steps(2,end)` (compositor-only).

- (2026-05-07 15:50) **Lightened live tail under high traffic** on the hunt
  tab. Three improvements:<br>
  - **rAF batch insert**: SSE events queue up and the next frame builds a
    DocumentFragment and inserts the DOM once. Reflow capped at 60/sec.<br>
  - **Page Visibility**: when the tab is inactive, EventSource disconnects and
    the queue is cleared. Reconnects on return only if the user had the tail
    started. Prevents the background DOM from growing forever.<br>
  - **Scroll-aware pause**: while the user scrolls up to read past entries,
    new events are buffered and not inserted until they return to top. Status
    shows "N pending while scrolled up".<br>
  Queue / buffer is capped at MAX_BUFFER=1000. innerHTML construction has
  escape applied (defense in depth).

### Added
- (2026-05-07 21:25) Install guide's **mode comparison cards are now clickable**.
  Cards carry a <code>data-pick</code> attribute and click handler that
  updates the mode dropdown and toggles the related section. The selected
  card gets a "Selected" badge + blue border. The recommended option (nginx
  native) has a star prefix on the heading (a green border conflicted with
  "selected", so it was removed). A small italic hint below each card says
  "click to select xxx".

- (2026-05-07 21:10) Added an **unmask main install section** to the install
  guide, plus an **existing-environment skip callout**.<br>
  - Section 2 = unmask main package (= dnf / apt / apk install from
    <code>unmask.sh/dl/...</code>). The same section appears across all 4
    modes (nginx native / auth / apache / caddy).<br>
  - Section 3 = HTTP server install. The opening callout says "if nginx /
    Apache / Caddy is already installed, skip to section 4" with verification
    commands (<code>nginx -v</code> etc.).<br>
  - Renumbered sections 2→3, 3→4, verify 4→5.<br>
  Existing hosts (= readers of this page) can keep the same section for
  another-server installs / disaster recovery.

- (2026-05-07 20:50) **Tabbed the docs page** (= overview / install / help /
  faq). The install guide moved out of the standalone nav into the
  <code>/admin/docs/?tab=install</code> sub-tab. The help tab has a shortcut
  grid to other tabs / settings; the faq tab has 8 Q&amp;A items ("JA4
  empty?", "what's stealth?", "are verdict names free-form?" etc.). More
  help / faq items planned.<br>
  The old <code>/admin/install/</code> URL 301-redirects to
  <code>/admin/docs/?tab=install</code>. The "Install" link in all-page nav
  was removed (one less link is one less link).

- (2026-05-07 20:30) Added an **install guide screen** (= /admin/install/).
  A conversational doc for users whose unmask-admin is already running but
  who want to wire it into an HTTP server. Pick OS (RHEL/Rocky 9 / 8 / 6,
  Debian/Ubuntu, Alpine) and HTTP server (nginx native module / nginx
  auth_request / Apache forward-auth / Caddy forward_auth) from dropdowns,
  and the matching dnf / apt commands plus config snippet appear
  dynamically. Every <code>pre.cmd</code> has a "copy" button (clipboards
  the body only, excluding comment lines). Selections persist via
  localStorage.<br>
  - At the top, a "native module vs auth_request" comparison card.
    Native's advantages (= **~0.05ms per req / JA4 capture available** /
    self-contained in nginx) are made explicit.<br>
  - At the bottom, an operations check plus 4 common gotchas (= 403 / JA4
    empty / module ABI mismatch / challenge not served).<br>
  Added "Install" link to all-page nav.

- (2026-05-07 17:55) Added an **mmdb candidate path scanner** to the settings
  GeoIP section. Below the input fields, it scans typical mmdb paths under
  `/usr/share/GeoIP/`, `/var/lib/GeoIP/`, and `/etc/unmask/geoip/`, showing
  **only files that exist** with a folder button + size + mtime (UTC).
  Clicking the button populates the input above. Helps spot stale mmdb
  files (a few years old) and time updates. If nothing matches, the list is
  hidden.

- (2026-05-07 17:30) Added a **GeoIP database section** to the settings
  network tab. <code>mmdb_path</code> (City / Country) and
  <code>mmdb_asn_path</code> (ASN) are editable from the web. On save, paths
  are validated by trying <code>maxminddb.Open</code> (rejected on invalid).
  After save, <code>geoip.Reader.Reload</code> hot-reloads (no server
  restart, cache flushed). Current load state (loaded / not loaded) is shown
  at the end of the section. Installs without a <code>geoip:</code> section
  in config.yml can complete setup entirely from the web.

- (2026-05-07 15:35) Added a **self password-change screen** for logged-in
  users (= GET/POST `/admin/profile/`). Available to all roles (superadmin /
  admin / viewer). Current password required. Added "Change password" link
  to the user_menu dropdown. Separate from the superadmin-only
  `reset_password` op on `/admin/users/` (confirmation step + audit log
  `user_change_own_password`).

### Fixed
- (2026-05-07 15:35) Fixed broken header layout on the playground (right
  side: language / TZ picker + user_menu). The inline `<style>` was missing
  the CSS (`.picker` / `.user-menu`) for the `lang_tz_picker` / `user_menu`
  partial templates.
- (2026-05-07 15:30) Fixed **right-aligned numbers not taking effect** in
  dashboard / stats tables. `.bcd-table th, .bcd-table td { text-align:left }`
  specificity (0,1,1) was overriding `.bcd-num` (0,1,0), so even cells with
  `bcd-num` rendered left-aligned. Changed the selector to
  `.bcd-table th.bcd-num, .bcd-table td.bcd-num` for specificity (0,2,1)
  that wins.

### Changed
- (2026-05-07 15:20) **Right-aligned values** in overview KPI cards. Numbers
  line up cleanly even as digit counts grow.
- (2026-05-07 15:15) Added **thousands separators** to overview hero / KPI
  values (via the `comma` template func). Improves readability past 4
  digits.
- (2026-05-07 15:15) Cleaned up faint-cell styling in dashboard funnel
  tables. Removed <code>n-zero</code> (extra-faint gray for 0) on rl,
  <code>n-muted</code> on uniq IP, and <code>n-faint</code> on silent in
  favor of normal coloring. Alert highlighting remains:
  <code>n-warn</code> orange for rl > 0, <code>n-stealth</code> red bold for
  stealth > 0.
- (2026-05-07 15:10) Reordered dashboard funnel-table columns to prioritize
  the main flow. New order:
  `verdict / serve / load / pow / captcha / verify_ok / verify_ng / cookie_err /
  JS error / pow_rate / captcha_rate / rl / uniq IP / silent / stealth`.
  rl / uniq IP / silent / stealth are auxiliary observation metrics and
  moved to the end.

### Fixed
- (2026-05-07 14:55) Fixed **`action=bot` JA4 verdicts going through the PoW
  path**. Cause: `ServeChallenge` required the `X-JA4-Action` header, but
  deploys whose nginx snippet only forwards the verdict ended up with
  `ja4_hit_flag=0`. Added a fallback so that when X-JA4-Action is absent, the
  action is resolved from X-Client-JA4 via settings (preset / extra rule).
  Verdict labels are free-form strings; the Action enum (bot / suspect / ok)
  should be the source of truth instead of prefix checks.<br>
  Verified on production: after deploy, bot-classified JA4 traffic proceeds
  `serve.hit=1` → load → captcha, with zero pow events.

### Changed
- (2026-05-07 14:30) **Install wizard DB step keeps form values on connection
  failure**. The failure redirect's query string now embeds
  <code>driver / sqlite_path / mariadb_host / mariadb_port /
  mariadb_database / mariadb_user</code>, which <code>AdminSetupIndex</code>
  overlays. Only the password is wiped (re-entered each time).
- (2026-05-07 13:50) **Removed bootstrap admin auto-seed; introduced setup
  wizard token auth**. Post-rpm/deb/apk install behavior now follows the
  cacti / zabbix / nextcloud convention:<br>
  - <code>bootstrapInitialAdmin</code> deleted (no more random password
    written to logs).<br>
  - First step of the install wizard is now "enter token". `postinstall.sh`
    creates <code>/etc/unmask/.setup-token</code> (0600 unmask:unmask); the
    user obtains it via <code>sudo cat</code> and pastes into the wizard.<br>
  - A correct token issues a cookie, after which db / user steps proceed.<br>
  - Wizard completion auto-deletes the token file (no re-running wizard).<br>
  - Without the token file (dev / docker / manual install), the step is
    skipped (open setup).<br>
  CLI users can still bypass the wizard:
  <code>unmask-admin user create &lt;name&gt; -role superadmin -password
  &lt;pw&gt;</code>.<br>
  `postinstall.sh`'s automatic <code>migrate</code> invocation was also
  removed (migration runs at the wizard's DB step after driver selection).
- (2026-05-07 12:30) Rewrote the README "Operating modes" section.
  - Documented that with an LB (GCP / Cloudflare etc.) that supplies the
    <code>X-Client-JA4</code> header, auth_request mode also gets full
    functionality including JA4 verdict.<br>
  - Added a "functionality vs performance" comparison table. After a
    `_bv` cookie is set, requests cost **native = 0.01 ms / auth_request =
    0.5–2 ms** — a ~50–200x difference.<br>
  - Added a recommended-mode matrix: "nginx-heavy + high traffic = native /
    Apache etc. + LB JA4 = auth_request + LB JA4 / Docker / trial =
    auth_request".
- (2026-05-07 11:35) Extended the **IP / UA / JA4 rankings** on the bot-hunt
  tab to show a badge in place of a button for already-registered items.<br>
  - IP: "BAN'd" if in <code>unmask_ban</code>, "bypass" if in
    <code>bypass_ips</code>.<br>
  - UA: "search_ai: &lt;group&gt;" (ok color) on <code>search_bots</code>
    hit, group name (bot color) on <code>challenge_targets</code> hit.<br>
  - JA4: same verdict badge as before.<br>
  Implementation: added <code>lookupUAListed</code> in
  <code>auth_check.go</code>; the hunt handler now resolves IP / UA already-
  registered status too.
- (2026-05-07 11:25) On the bot-hunt tab's JA4 ranking, JA4s already in
  preset / extra now show a **verdict badge + source tooltip**
  ("preset:rotating_proxy" etc.) in place of the "Register JA4 as bot"
  button. Prevents duplicate registration; clear at-a-glance "already
  registered". Implementation: wrapped <code>auth_check.go</code>'s
  <code>matchJA4</code> with <code>lookupJA4Verdict</code> (with source
  info), shared by the hunt handler.

### Performance
- (2026-05-07 11:45) Improved `/admin/stats/` dashboard response time from
  **8s → 0.6s** (13x). Cause: <code>DailyServeByKind</code>'s 30-day ×
  distinct UA × verdict aggregation (10,890 rows) ran <code>classify.IsBot</code>'s
  647-alternation big regex per row (~7,000,000 regex evaluations).<br>
  Mitigations:<br>
  1. Added a memoize cache on the <code>(ua, verdict)</code> tuple.<br>
  2. Expanded SQLite connection pool <code>SetMaxOpenConns(1) → 8</code>
     (WAL mode allows parallel readers) + <code>cache_size 20MB</code> +
     <code>mmap_size 256MB</code> + <code>busy_timeout 5s</code>.<br>
  3. The stats handler now uses per-query timeouts in independent contexts,
     so heavy queries don't drag down the others.

### Fixed
- (2026-05-07 12:20) Fixed cookie-traffic card **mixing bv (CAPTCHA pass) and
  bp (PoW pass)**. The earlier (11:55) fix that made 4-segment PoW cookies
  valid caused everything to count under bv. Fix: split cookie format into
  3-segment (HMAC / CAPTCHA path) and 4-segment (djb2 / PoW path) reasons
  (<code>bv-captcha</code> / <code>bv-pow</code>), so Bump routes to the
  correct column. The funnel-captcha 0 vs cookie-bv 11 discrepancy is
  resolved.
- (2026-05-07 11:55) Fixed auth_request mode **unable to verify the `_bv`
  cookie for the PoW path**. challenge.js sets <code>_bv</code> in
  <code>day.djb2hash.target.flags</code> (4-segment / djb2 hash) on PoW
  completion, but server-side <code>cookies.Verify</code> only recognized
  the HMAC format (3-segment) and always returned false → PoW-passing
  users got re-challenged on the next request → effectively an infinite
  loop. Fix: <code>cookies.Verify</code> now also recognizes the
  4-segment format, recomputing the djb2 hash via <code>verifyPoW</code>
  and validating on match. PoW-passing users now have a valid
  <code>_bv</code>, and the cookie-traffic card's bv column carries a
  value.
- (2026-05-07 11:50) Fixed auth_request mode's <code>NginxLog.Bump</code>
  always passing **`bp` (= _br cookie present) as false**. Now classifies
  based on the actual presence of <code>_br</code>.
- (2026-05-07 11:30) Fixed auth_request mode ignoring settings'
  **ChallengeTargetGroups** (= UA filter / target UA preset). With
  <code>known_browser</code> ON by default, Chrome UAs passed through (zero
  load/PoW events on verdict=ok). The final branch of human classify now
  calls <code>lookupUAListed</code> and routes to challenge if listed +
  category=challenge.
- (2026-05-07 11:20) Fixed the challenge HTML's
  `<script src="../static/challenge.js">` **relative path** that worked
  only under narrow conditions. In auth_request mode, when challenge HTML
  is delivered via error_page internal redirect (URL bar shows the
  original path), the browser fetched `/static/...` instead of
  `/unmask/static/...` → flows to the backend, 404 / wrong file → JS does
  not run → no load / PoW events. Switched to absolute path
  `/unmask/static/challenge.js`.
- (2026-05-07 11:15) Bot-hunt / SSE / dashboard event datetime: the SQLite
  driver sometimes returns ISO 8601 `2026-05-06T19:55:14Z`. Normalized
  at `events.Row.Date` construction to a unified `2026-05-06 19:55:14`
  format (space separator, no TZ, truncate ms).
- (2026-05-07 11:10) Auth_request mode event duplication: one request
  produced two events, `check` (AuthCheck) and `serve` (ServeChallenge).
  Since ServeChallenge always records a serve event for challenge actions,
  AuthCheck now skips the check event on challenge actions (records only
  when action != "challenge"). Pass / block still record the check event
  (no serve follows). Bot-hunt tab now shows one row per request.
- (2026-05-07 11:05) Dashboard popover (help text) not showing. Cause:
  the html/template `<script>` context was double-quoting the `safeHTML`
  string as a JS literal (state: `"{\"flags.flags\":\"..."`). Fix:
  wrapped `helpJSON`'s return in `template.JS` and removed `| safeHTML`
  from dashboard.html.
- (2026-05-07 11:00) Added logic to read X-Client-JA4 / X-Original-JA4
  headers in auth_request mode and judge JA4 verdict. With GCP LB etc.,
  JA4 fingerprint-based bot judgement now works without nginx-module.

## [0.1.0-pre] — 2026-05-07

Initial OSS commit (= pre-tag).  Rolled forward into 0.1.0 above with
the 2026-05-07 ~ 2026-05-24 polish work in between.

### Added — bot detection
- **JA4 fingerprint** computed from the TLS handshake via an nginx dynamic
  module (= `ngx_http_unmask_module.so`). Implemented from the public
  specification only, without referencing FoxIO's BSL-licensed source.
- **JA4 verdict** presets (= `bot_chrome_fake_h1` / `bot_chrome_fake_noalpn` /
  `suspect_*` etc.) + custom pattern UI.
- **UA classify** across 5 categories (= `search_ai` / `user_dev` / `service` /
  `old_ua` / `human`). crawler-user-agents.json embedded.
- **Honeypot path** detection + persistent BAN list.
- **Protected paths** (= forced CAPTCHA gate on specific paths). Preset
  bundled (= unmask itself + generic admin paths).
- **Whitelist IP / whitelist path** managed from the web for misclassified
  bypass targets.
- **Two-stage search-bot rescue** (= UA preset + official IP range
  double-check).

### Added — challenge
- **Behavioral CAPTCHA**: 5-axis score on checkbox click (mouseTrail / scroll /
  window-size / clickAt / keys). Threshold 0.5.
- **3rd-party CAPTCHA**: Cloudflare Turnstile / hCaptcha / Google reCAPTCHA v3.
  Switch provider in the settings UI + enter site_key/secret_key + test send.
- **PoW (Proof of Work)**: djb2 hash search. Difficulty auto-adjusts.
- **Numeric-addition fallback**: rescue path when the behavioral check fails.

### Added — operating modes
- **native mode**: nginx dynamic module + admin server.
- **auth_request mode**: HTTP-server-agnostic forward-auth pattern.
  Supports nginx 1.5+ / Apache 2.4+ / Caddy v2 / Traefik / Envoy / HAProxy.
  All functionality works except JA4 fingerprint.
- 4 snippets bundled (= nginx-auth-request.conf / apache-forward-auth.conf +
  apache-unmask.lua / Caddyfile-forward-auth / traefik-forward-auth.yml).

### Added — distribution
- **Install wizard** (cacti / zabbix / nextcloud style). First launch routes
  to `/admin/setup/` → pick DB driver (SQLite / MariaDB) → connection test +
  schema migration → create admin user. No re-setup after completion.
- **rpm / deb / apk** all supported (via nfpm). amd64 + arm64.
- **Fat plugin** (one package bundles `.so` files for 9 nginx versions). The
  postinstall detects the host nginx and auto-copies the best match:
  exact match → same minor-branch fallback → no match → friendly error.
- **Docker image** (multi-stage Go build → alpine runtime, multi-platform
  buildx) + docker-compose.example.yml.
- **CentOS 6 / RHEL 6 support**: SysVinit script bundled. Postinstall auto-
  detects systemd / SysVinit. Helps legacy-OS deployments.
- **Module path auto-resolution**: postinstall parses the actual path from
  `nginx -V`'s `--modules-path=` (RHEL `/usr/lib64/`, Debian `/usr/lib/`,
  custom build paths etc.).

### Added — observability / notifications
- **Dashboard**: 30-day trend chart / cookie pass rate / funnel chart /
  per-country chart (GeoIP) / live tail (SSE).
- **Bot-hunt tab**: rankings (top 30 IPs / JA4s / UAs) + raw event paging +
  1-click action buttons (BAN / UA blacklist / register JA4 as bot) + SSE
  realtime.
- **JA4 / UA playground**: input → instant judgement + reason debug screen.
- **Webhook notifications**: Slack / Discord / generic JSON. Two events:
  ban_created and challenge_burst (= 5min threshold). Flap protection +
  test-send button.
- **Multi-site**: one admin manages events across multiple sites
  independently.

### Added — operations / CLI
- **doctor**: self-check immediately after install / upgrade. Reports
  config / DB / GeoIP / various permissions as ✅ ⚠️ ❌ one-liners. Exits 1
  on any ❌.
- **migrate / aggregate / config-init / render-nginx** sub-commands.
- **events / analyze**: event search / aggregation from the CLI.

### Added — UI / i18n
- English and Japanese provided in parallel.
- Timezone switching (picker, per session).
- Three roles (superadmin / admin / viewer) + audit log.

### Architecture
- Pure-Go static binary (CGO_ENABLED=0). No glibc dependency; runs on
  kernel 2.6.32+.
- SQLite (modernc.org/sqlite, pure Go) default. MariaDB optional.
- Only 3 third-party Go deps (sqlite / mysql driver / yaml).
- nginx module written in C as a dynamic module. `--with-compat` supported.

[0.1.0]: https://github.com/unmask-sh/unmask/releases/tag/v0.1.0
[0.1.0-pre]: https://github.com/unmask-sh/unmask/commits/main/?until=2026-05-07
