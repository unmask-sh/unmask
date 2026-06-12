# Changelog

Change history for unmask.  Format follows [Keep a Changelog](https://keepachangelog.com/).
Versioning follows [Semantic Versioning](https://semver.org/).

## Conventions

- Each entry starts with `(YYYY-MM-DD HH:MM)` for the start time. For long-running
  work, use the completion time. Timezone is the host's local time (mostly JST).
  Short entries use minute precision.
- Within a release, entries are sorted by date descending (newest at top).

## [Unreleased]

### Changed
- (2026-06-12 17:16) **Non-systemd plugin installs now tell the operator how to
  re-pick the module after a host nginx upgrade.**  On systemd, the shipped
  `nginx.service` drop-in re-runs the module placer before every nginx start,
  so a `yum/apt upgrade` of nginx is followed automatically.  Non-systemd hosts
  have no equivalent hook — Alpine ships no nginx OpenRC service at all, SysV
  nginx scripts are package-owned, and nfpm can't emit an apk trigger that
  fires on a nginx upgrade — so the fat-plugin postinstall now prints a clear
  reminder (re-run `place-module.sh`, or wire it into the nginx service's
  pre-start) instead of staying silent, and `place-module.sh` documents the
  same.  The placer's fail-safe (it strips the module so nginx still starts
  when no bundled `.so` matches) means the worst case is a visible, recoverable
  `nginx -t` failure, not the silent systemd-era outage this guards.
- (2026-06-12 15:44) **The web / plugin sub-packages now pin the `unmask`
  daemon to the exact build version.**  Every sub-package
  (`unmask-web-nginx` / `-apache` / `-caddy`, `unmask-plugin-nginx` and the
  fat variant) declared an UNVERSIONED `depends: unmask`, so a snippet or the
  native `.so` could be installed or upgraded against a mismatched daemon —
  and the `.so` verifies `_bv` / computes JA4 against the daemon's contract,
  while the web snippets carry the version-coupled `/unmask/*` + forward-auth
  routing.  Each now pins `unmask = <build version>` in its packager-native
  syntax (rpm `=`, deb `(= )`, apk `=`), so the suite can only move in
  lockstep.  All packages already share one `${UNMASK_VERSION}` and ship from
  a single `make release`, so a normal `dnf upgrade` / `apt full-upgrade`
  resolves the whole set in one transaction; only a partial daemon-only
  upgrade is now (intentionally) held until the matching components publish.
- (2026-06-11 23:10) **doctor and the daemon now self-check three operator
  mistakes that previously stayed silent**.  `unmask doctor` gained — and the
  daemon now also warns about at startup — a **bv_secret desync**: when the
  rendered http.inc carries a different `unmask_bv_secret` than the running
  config, the native plugin verifies _bv against the stale secret and loops
  every visitor on the challenge (the 2026-06-08 incident's root cause, which
  went unnoticed for ~14h because nothing surfaced it).  The startup WARNING
  makes a deploy that re-rendered but forgot the nginx RESTART obvious in the
  journal.  doctor also flags a **cleartext admin bind** (the admin API is
  HTTP, so a non-loopback/unix bind exposes it without TLS) and **reminds about
  real_ip** when a trusted LB is configured (without set_real_ip_from every
  visitor resolves to the LB IP, so challenge / ban / rate-limit hit all
  clients at once), and it now suggests `sudo` when config.yml is unreadable
  instead of a bare "permission denied".  The over-block breaker still catches
  the challenge-loop *symptom*; these name the *cause* up front.

- (2026-06-11 12:30) **Removed the UI-hidden built-in UA whitelist presets so
  the search/AI rescue has a single, operator-controllable source**.  The
  ua-filter tab rescued search bots via two independent paths: the upstream
  crawler-user-agents.json categories (white/none/black in the UI) AND a
  legacy hand-maintained preset list (Googlebot / Bingbot / ...) whose
  checkboxes were `display:none` "for backwards-compatible YAML" — invisible,
  always-on, and impossible to switch off.  An operator who set the
  `search-engine` category to `none` to stop UA-spoof pass-through found
  Googlebot still rescued by the hidden presets, so the documented "turn it
  off" did nothing.  The hidden presets are gone (render path, both decision
  modes, the settings card, the `search_bots.disabled_presets` config key,
  and the data.go table); search/AI rescue now flows only through the
  upstream categories plus the operator's own Extra UA rules.  Verified every
  brand the presets covered (Googlebot / Bingbot / Yahoo / Yandex / Naver /
  Baidu / GPTBot / ClaudeBot / ... — 31 cases) still classifies as search_ai
  through the upstream path alone (new regression test), and that setting
  `search-engine` to `none` now actually drops Googlebot from the rendered
  `is_search_bot` map while ai-training (GPTBot) stays under its own category.
  e2e 05/15 (native + forward-auth search-bot rescue) green.  Pre-GA, no
  compat shim: a leftover `disabled_presets:` key is ignored on load.

- (2026-06-11 11:30) **Native daemon-down fail-open trips fast when the daemon
  is unreachable on another host**.  The `/unmask/*` proxy locations had no
  `proxy_connect_timeout`, so a TCP upstream that became unreachable (= admin
  on a separate host that went down, as opposed to a same-host ECONNREFUSED
  which is instant) hung on nginx's default 60s connect timeout before
  `@unmask_daemon_down` could fail open — visitors waited seconds for the
  original page.  Capped at 2s; read/send stay at the default so slow
  challenge renders and the SSE stream are unaffected.  Completes the native
  fail-open added earlier this cycle; e2e scenario 35 exercises the
  container-stop path end-to-end.

- (2026-06-11 10:30) **JS-error card separates foreign-script noise from
  challenge failures**.  Mobile pages are full of scripts unmask did not
  ship — in-app webview bridges, extensions, carrier-injected JS — and
  their failures landed on the challenge page's global error hook as
  indistinguishable `js_exception` rows ("Script error." being the masked
  message browsers emit for cross-origin scripts).  challenge.js now
  classifies by the reported source (`js_foreign` when it is neither the
  challenge document nor an /unmask/ asset), and the dashboard card lists
  challenge-code errors as before while collapsing foreign rows behind a
  count toggle (rows ingested before the classification are caught by the
  "Script error." message).  Raw events stay verbatim either way; the
  funnel's JS-error column still counts both, and its popover says so.

- (2026-06-11) **`admin_allow_from` renamed to `admin_allowed_ips`, and the
  admin access-control settings split into two cards**.  The old combined
  card mixed two different axes — WHO may connect (source IP) and THROUGH
  WHICH hostname the UI is exposed — under near-identical field names, and
  its labels never said "allowlist"; in practice the IP list got read as a
  deny list.  Each card now states the direction (allowlist), the
  empty-semantics (empty = open), and a live effective state — including a
  warning when a `/0` entry makes the list look restrictive while admitting
  everyone.  The yaml key renames symmetrically to pair with
  `admin_allowed_hosts` (pre-GA, no compat shim: an old `admin_allow_from`
  key is dropped on load = no IP restriction, the shipped default).  The
  rendered-conf copies of the admin/metrics allowlists were deleted — no
  template ever consumed them; enforcement lives in the admin HTTP layer,
  and the help text now says so instead of claiming nginx-side enforcement.

- (2026-06-11 00:50) **Native mode now fails open automatically when the admin
  daemon is down** — no operator config required.  Previously an unreachable
  daemon meant every not-yet-passed visitor got a raw 502 from the challenge
  proxy (effectively a site outage for new visitors), and the only escape was
  an operator-supplied named location that the native render never even
  referenced.  Now the `/unmask/*` proxy locations carry
  `error_page 502 503 504 = @unmask_daemon_down`; the named location replays
  the visitor's original request through the vhost's own locations
  (`$unmask_orig_path` / `$unmask_orig_args` saved at the challenge gate,
  `$unmask_failopen` suppresses the gate on the replay pass so it cannot
  loop).  The site behaves as if unmask were not installed until the daemon
  returns.  Scope guards: BAN deny entries keep returning 403 (no daemon
  involved), challenge-type ban rewrites land on 503 + Retry-After instead of
  a free pass, rate-limit overflow during an outage answers a plain 429, and
  direct `/unmask/*` requests (admin UI, mid-challenge asset / verify calls)
  answer 503 + Retry-After.  Matches forward-auth mode, whose gate already
  failed open (204) by default.  Covered end-to-end by e2e scenario 35
  (stops/restarts the admin container and asserts original content with no
  challenge, query-string survival, the 503 + Retry-After branch, and that
  protection resumes on recovery).

### Fixed
- (2026-06-12 16:42) **The cookie_minute v1→kind/cnt migration is now safe to
  re-run, so an interrupted MariaDB upgrade can't double historical stats.**
  The copy INSERTs run in a transaction, but the table rename and the final
  `DROP TABLE …_v1` are DDL, which auto-commits OUTSIDE that transaction on
  MariaDB — so a dropped connection in the gap between COMMIT and DROP left the
  v1 table in place, and the next startup re-ran the copy on top of the
  already-committed rows, doubling every cookie_minute bucket the dashboard
  aggregates.  The copy now clears the destination inside its transaction
  before re-inserting (safe: the migration runs at startup before the daemon
  serves, and Migrate aborts on error, so a lingering v1 means the table holds
  only migration output).  Covered by a re-run test that doubles the rows
  without the guard.
- (2026-06-12 15:24) **The English community-bans "not applied" tooltip no
  longer shows raw `%d` / `%s`.**  Two catalog strings
  (`community_bans.below_threshold_title` / `reports_only_title`) carried
  `fmt.Sprintf` placeholders, but the badge renders them through the plain
  (non-formatting) `t` template helper, so English readers saw the literal
  `currently %d` and a bogus `href="%s"` link in the hover popover; the
  Japanese strings were already placeholder-free.  Rewrote the English to be
  self-contained.  A new locale test (`TestLocaleFormatVerbParity`) now fails
  the build if any key's ja/en strings carry mismatched format verbs, so this
  class of drift can't return.
- (2026-06-12 14:37) **The live settings hot-swap is now race-free.**  The web
  save handlers published a new `settings.Settings` by assigning the whole
  struct value to a Handler field under a mutex, but every request read that
  field lock-free — so a request in flight during a save could observe a torn
  struct (some fields old, some new), which the race detector flags and which
  could momentarily mis-evaluate a challenge / bypass / ban decision.  The
  field is now an `atomic.Pointer[settings.Settings]`: writers publish a fresh
  snapshot with `Store` (still serialized by settingsMu so concurrent saves
  don't clobber), readers `Load` a stable pointer via a `cfg()` accessor and
  always see one consistent snapshot.  No behaviour change for operators; a new
  concurrency test drives 8 readers against 2 writers under `go test -race`.
- (2026-06-11 23:45) **A config that omits secret.bv_secret no longer passes
  doctor while silently breaking the site.**  Load() fills an empty bv_secret
  with a per-process random key that is never persisted, so render-nginx and
  the daemon sign / verify _bv with different keys and every visitor loops on
  the challenge — yet `unmask doctor` checked the post-Load value (a
  healthy-looking 24-byte string) and reported a false green.  Load() now logs
  a loud WARNING when it has to fabricate the key, and doctor reads the RAW
  config so a missing secret is an [ERR], not an [OK].  Only hand-rolled
  configs are affected (package install runs config-init; docker persists one).
- (2026-06-11 23:30) **A fresh box no longer contacts the hub before setup is
  finished.**  community-bans register / pull and the managed-mmdb auto-fetch
  fired on the first daemon start whenever a config path was set — before the
  operator had opened the install wizard — so an unconfigured box POSTed its
  public IP + version + publish-country flag to unmask.sh/api/feed/register,
  and an air-gapped box logged alarming register / fetch failures, both
  contradicting the README's opt-in framing.  All three are now gated on setup
  completion (an admin user existing); the wizard's post-completion auto
  re-exec starts them on the next boot.  The default subscribe mode is
  unchanged — only the timing of the first contact moves to after the operator
  has actually set the box up.  Verified: a DB-connected box with no admin user
  makes zero hub calls; creating the admin user and restarting starts them.
- (2026-06-11 23:00) **Event writes are no longer dropped on a transient DB
  error.**  The async event flusher logged an insertBulk failure and then
  cleared the batch, permanently losing those unmask_event rows on a brief
  SQLite-busy or MariaDB blip.  It now retains the batch and retries on the
  next tick (matching nginxlog's flushOnce), bounded so a persistent outage
  can't grow it without limit — overflow drops the oldest events and counts
  them in a droppedOnError metric kept distinct from the queue-full drop
  counter.
- (2026-06-11 22:50) **Saving settings on a dev / source build no longer
  NEW-badges every preset and drops them from the rendered conf.**  Every
  settings save stamps `seen_version: v<admin version>`; dev builds carry a
  git hash there (`v6f94983`), which the version parser mapped to v0.0
  (= oldest).  All preset groups (AddedIn >= v0.1) then counted as
  "not yet seen": forced-off NEW checkboxes on every preset tab (re-saving
  would wipe the enabled list), and enabled presets silently skipped at
  render time — the JA4 verdict map rendered empty and honeypot /
  bypass-path preset patterns vanished from http.inc.  An unparseable
  seen_version now means "runs tip" (= nothing is new) at all 10 gate
  sites (`PresetIsNew`), and saves keep the previous seen_version unless
  `v<version>` parses as a release number.
- (2026-06-10) **Web Bot Auth now actually works in native mode**.  The
  signed-route in server.inc had three fatal flaws: the server-scope
  header gate also fired inside the verification subrequest (nginx
  re-runs server rewrites for subrequests), rewriting it away from the
  admin proxy; the proxy target was a phantom endpoint
  (`/_unmask/check` — the daemon serves `/unmask/api/check`); and the
  success path served the original URI off the filesystem
  (`try_files ... =404`), which can't work on proxied vhosts.  Net
  effect: the daemon was never consulted and a signed request on a
  proxied site got 404/500 instead of content (the dlvr.it incident).
  Redesigned: the detour fires only for a signed main request that is
  about to be challenged (`$unmask_signed_gate`, volatile maps), every
  verification outcome converges on `@unmask_signed_continue` which
  re-enters the normal flow, and a daemon-verified pass skips the
  challenge via `$final_challenge_eff` in protect.inc.  Bans still fire
  first; a daemon outage degrades to the normal challenge instead of
  surfacing 5xx.  The plugin's `$unmask_has_signed_agent` now reports 0
  for subrequests, and the admin verifier reconstructs the signed
  components (`@authority` etc.) from `X-Original-*` instead of the
  auth hop's own Host/URI — without that, every signature failed with
  "signature mismatch" in both native and forward-auth modes.  Failed
  verifications now log their reason (they were silent).  New
  `web_bot_auth.allow_private_networks` setting admits operators whose
  key directory lives on a private network (TLS verification and the
  https-only rule stay).  Covered end-to-end by e2e scenario 34 (real
  ed25519 signing against a fake operator directory, replay-defence
  included) plus template-shape and signer-format unit tests.

## [0.1.0] — 2026-05-25

### Added
- (2026-06-06) **Web Bot Auth verification (RFC 9421 HTTP Message
  Signatures)**.  A new `webbotauth` package validates ed25519-signed
  `Signature-Input` / `Signature` headers (per
  draft-meunier-web-bot-auth-architecture-05), and the nginx plugin exposes
  a `$unmask_has_signed_agent` variable so a request carrying a bot
  signature can be routed differently from one identified only by a
  spoofable User-Agent or rDNS.  Lets a cooperating agent (e.g. a signed
  crawler) prove its identity cryptographically.

- (2026-06-06) **Per-site aggregates for the captcha-force,
  flag-distribution and AI-traffic dashboard cards** (migrations
  0016-0019).  These three cards now read pre-rolled per-site aggregate
  tables instead of scanning raw events, joining the funnel / verdict /
  countries cards already on the aggregate path.

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
- (2026-06-06) **Global CSRF double-submit shim in the admin header
  tooling**.  A single `init_csrf` injector adds the hidden `_csrf` field
  on every form submit and the `X-CSRF-Token` header on every `fetch`, so
  new forms and fetches are covered with no per-form edits.  Replaces the
  static per-form injection that had silently missed 19 settings forms.

- (2026-06-06) **All admin timestamps render in the operator's cookie
  timezone**.  Server-side fallbacks and the JS formatter both resolve
  against the `unmask_tz` cookie, which is now auto-synced from the
  browser on first hit.  Aggregation stays UTC-at-rest; only the display
  localizes.

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
- (2026-06-06) **nginx / Apache integration fixes surfaced by the first real
  multi-mode install-matrix fire** (the matrix's fire-check had silently been
  install-only since the binary rename, masking these on fresh installs):
  - **native nginx**: the `unmask-web-nginx` postinstall symlinked the http.inc
    auto-load at the retired `/etc/unmask/native/http.inc` placeholder instead
    of the flat `/etc/unmask/http.inc` render path, so the JA4 maps / log_format
    never loaded and `nginx -t` aborted with `unknown log format`.
  - **forward-auth nginx**: `forward-auth/server.inc` did `proxy_pass
    http://unmask_admin` with no upstream defined (the render that once emitted
    it was retired); the postinstall now writes a default-port `upstream
    unmask_admin`.  Its `X-Client-JA4` / `X-JA4-*` headers (native-only vars)
    are commented out so pure forward-auth `nginx -t` passes.
  - **forward-auth Apache packaging**: `unmask-web-apache` depended on
    `libapache2-mod-lua` (deb) / `apache2-mod-lua` (apk), neither of which
    exists; now `apache2` + `lua-socket` (deb) and `apache2-lua` + `lua5.1-socket`
    (apk, matching Alpine's Lua 5.1 mod_lua).
  - **http.inc** no longer sets `map_hash_bucket_size`; it conflicted with a
    host nginx.conf that declares a `map{}` first (e.g. Alpine's stock
    `map $http_upgrade`), and the default bucket already fits the widest key.
  Verified end-to-end (install → bot traffic → unmask_event count climbs) for
  native nginx + forward-auth nginx + forward-auth Apache on AlmaLinux 9,
  Ubuntu 24.04, and Alpine.

- (2026-06-06) **`known_browser_action` now defaults to `pass`**.  It was unset,
  which `uaDecide` treats as a PoW challenge, so a fresh install challenged
  every real-browser visitor on the first hit -- the opposite of the JA4 design
  (a TLS-confirmed browser should sail through; only a spoofed UA whose JA4
  mismatches is challenged).  Unknown UAs keep the implicit PoW challenge.

- (2026-06-06) **Stuck hover popovers are dismissed by a hover-reconcile
  watchdog**.  A fast pointer pass could leave a popover pinned after the
  cursor had already left its trigger; an rAF-throttled `:hover`
  ground-truth check now tears the orphaned popover down.

- (2026-06-06) **`/admin/login` carries a rate-limit preset** (5 req/min,
  captcha_only) so the admin login path is covered by the same preset
  machinery as the other protected paths, backfilled in-memory without
  rewriting a sparse `admin.yml`.

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
  proxy_pass to the unmask loopback socket.  Opt out with
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
  - New CLI: `unmask install-ipgeo [-kind country|asn] [-path PATH]`.<br>
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
  A conversational doc for users whose unmask is already running but
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
  <code>unmask user create &lt;name&gt; -role superadmin -password
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
