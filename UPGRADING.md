# Upgrading

What a release asks of the operator, from 0.1.50 on.  `CHANGELOG.md` has
every change; this page keeps the actions.  For releases before 0.1.50, read
the changelog's "Upgrade note" paragraphs.

Still 0.x: a patch release can rename or remove a settings key, and most
releases ask nginx for a reload or a restart.  The table says which.

## Every upgrade

- Back up before you start: `unmask backup`.
- Upgrade the unmask packages as one set.  `unmask-plugin-nginx` and the
  `unmask-web-*` packages are pinned to the daemon's exact version, so the
  package manager moves them together.  The `unmask` package restarts the
  daemon itself.
- nginx: every upgrade re-renders the nginx configuration, so run `nginx -t`
  and reload nginx afterwards; the admin pages show a notice until nginx has
  loaded it.  When the module itself changed, a reload keeps the old module:
  the plugin package's output says either "module unchanged -- left in
  place; nginx does not need a restart" or "The module file changed: restart
  nginx".  A testing-channel (rc) build prints the same.
  unmask never reloads a running nginx by itself.  To automate that reload
  (after an upgrade or a settings save alike): `systemctl enable --now
  unmask-nginx-reload.timer`.  The timer ships disabled with
  `unmask-web-nginx`; every five minutes it reloads nginx when a render
  changed the configuration and `nginx -t` passes, at most once per ten
  minutes, and never restarts it.  While the nginx master still maps a
  shared library an OS update has replaced, it reloads nothing and writes to
  the journal that a restart is needed: the workers a reload forks on that
  master crash on the old copy.  Without systemd, run
  `/usr/share/unmask/nginx-reload-if-stale.sh` from cron.
- Schema: the daemon applies a short schema update when it starts.  An index
  build that would take long is left for the operator: the package output,
  the admin and `unmask doctor` announce it, and `unmask migrate` runs it
  while the challenge keeps being served.
- Afterwards, run `unmask doctor` (from a shell, or from the admin): it
  reports what the upgrade left to do, and whether nginx has loaded the
  rendered configuration.

## Release by release

One line per release; the section of the same name under Details says what
each cell means.  "Restart" is a restart of nginx (a reload keeps the module
it has loaded); "Reload" is `nginx -t` and a reload after the package's
render.

| Release | nginx | Sign-in | Settings keys | Schema |
|---|---|---|---|---|
| **0.1.57** | Reload | -- | 1 new, optional | 0051 |
| **0.1.56** | Reload; restart where the module changed | -- | -- | -- |
| **0.1.55** | Restart | Signed out once | 9 new, all optional | 0050 |
| 0.1.54 (tagged, not published) | -- | -- | -- | -- |
| **0.1.53** | Restart | Signed out once | 8 new, all optional | 0046, 0048, 0049 |
| **0.1.52** | Reload | -- | 1 renamed | index builds, on a large database |
| **0.1.51** | Reload | -- | 1 removed, 4 renamed | -- |
| **0.1.50** | Reload | -- | -- | -- |

## Details

### 0.1.57

- **nginx: reload.**  The module file is the one 0.1.56 shipped, so the
  plugin package says "module unchanged" and nginx needs no restart.  The
  rendered configuration changes: run `nginx -t` and reload.  The reload is
  what brings this release's nginx-side fixes in -- the Google Cloud preset
  and the untrusted JA4 header below, the SQL-injection trap's pattern that a
  crafted URL could hold a worker on, the access-log line's fields, and the
  static-assets bypass preset, which now passes the sitemaps a sitemap index
  names and `/llms.txt` (GET, HEAD and OPTIONS).
- **Google Cloud load balancer.**  The `gcp` trusted-LB preset no longer
  trusts 35.227.0.0/16, most of which is Google customers' machines.  It
  trusts the load balancer's proxy ranges and reads past 35.227.192.0/18 in
  `X-Forwarded-For`, where global load balancers' own addresses are: nothing
  to do when your load balancer's address (its forwarding rule's) is in that
  range.  One elsewhere -- another range, IPv6, a regional load balancer --
  had to be listed as a trusted LB of your own before, and still does.  If
  your own `nginx.conf` sets `set_real_ip_from 35.227.0.0/16`, narrow it to
  35.227.192.0/18 or to your load balancer's address.  `unmask doctor` now
  warns when every request of the last hour from outside the load balancer's
  ranges came from one address.
- **A JA4 header from an untrusted address.**  With a trusted-LB preset on,
  a request that reached the origin directly and carried the load
  balancer's JA4 header is judged by its own connection's fingerprint, no
  longer recorded as `NOT_TRUSTED`.  Nothing to do but the reload.
- **nginx is no longer a dependency of the rpm and deb packages.**
  `unmask-plugin-nginx` and `unmask-web-nginx` suggest it: on a host without
  nginx, install it first.  Where `dnf` installed nginx as a dependency of
  an earlier unmask, run `sudo dnf mark install nginx` so that `dnf
  autoremove` leaves it.  apt keeps a suggested package installed.
- **An nginx built from source.**  New: the plugin runs on an nginx no
  package installed -- built by hand or by a hosting panel -- when it is
  built `--with-compat`.  The packages keep the module and their include
  files in their own directories and print the two `include` lines to add
  to that nginx's `nginx.conf` (README, "Requirements").  Nothing changes
  for an nginx installed from a package.
- **systemd.**  Picking the module for the installed nginx version is now a
  unit of its own, `unmask-place-module.service`, started before nginx's
  service (as a step of that service it ran after the distributions' own
  `nginx -t`, and a host nginx upgrade kept nginx from starting).  The
  plugin package installs it and a drop-in that has `nginx.service` want it;
  nothing to do.
- **SysVinit and OpenRC (CentOS 6, Alpine).**  The package adds the unmask
  user to the group nginx's workers run in, and the access-log socket is
  shared with them by group, no longer with every local user.  On SysVinit
  it also installs `/etc/logrotate.d/unmask` (weekly, eight kept) when no
  such file exists; if you already rotate `/var/log/unmask.log` with a file
  of your own, keep one of the two.
- **Apache.**  Copy this release's `apache-unmask.lua` over your
  `unmask.lua` again, as at install: a visitor who passes the challenge then
  lands on the page they asked for, no longer on the site's top page.
- **Settings to look at.**
  - The public test pages' site picker came back on at every daemon start;
    if you had turned it off, turn it off again.
  - A save of a site's own challenge or design form stored the built-in
    value of every field left unset -- a seven-day PoW cookie where the
    global setting said one day.  Open each site's form, where inherited
    fields are now marked, and clear what should follow the global setting.
    A display style saved for a site takes effect from this release.
  - A bypass path of your own gains a methods picker (`safe_methods_only`):
    existing rows keep passing every method.
  - `unmask doctor` names patterns in `config.yml` that nginx cannot compile
    (the settings page now refuses them), and regex locations whose `$1`
    unmask's maps empty (use a named capture there).
- **config.yml.**  The daemon re-reads the file seconds after it changes --
  an edit, or `unmask upgrade-review --apply` -- and renders; reloading
  nginx stays yours.  A malformed address or socket path in it now stops the
  render and keeps the previous files (the log and `unmask doctor` say
  which), and a malformed range of a custom load balancer is left out with a
  warning.
- **Bans on a relay's exit.**  No automatic ban is placed on an address in
  the relay list (iCloud Private Relay, web gateways): one visitor's trap hit
  banned everyone behind that exit.  Bans placed by hand apply as before;
  automatic ones placed earlier run until they expire.
- **Schema.**  0051 adds one table, the per-site crawler counts behind the
  crawler card's site picker and its CSV.  It is created when the daemon
  starts.

### 0.1.56

- **nginx: restart on older systems, reload elsewhere.**  The module files
  for OpenSSL 1.1, OpenSSL 1.0 and glibc 2.12 hosts (RHEL 8 and its
  rebuilds, Debian 11, Ubuntu 20.04, CentOS 7, CentOS 6) are now built with
  the stack protector, RELRO and `BIND_NOW` the current build already had,
  so the module changes there: restart nginx after the plugin package has
  been upgraded.  On other hosts the plugin package's output says whether
  the module file changed, as on every upgrade.
- **Forward-auth.**  The decision endpoint no longer answers on
  `/unmask/api/<site>/check`; no shipped configuration used that path, and
  through the copy-paste nginx snippet it let a visitor get another address
  banned.  The daemon upgrade closes it.  If your own configuration points
  `auth_request` at that path, point it at `/unmask/api/check`.  If you
  pasted `/usr/share/unmask/snippets/nginx-forward-auth.conf`, paste its
  PART 2 again: its locations now set the `X-Original-*` headers themselves.
  The packaged `/etc/unmask/forward-auth/server.inc` gains a location for
  `/unmask/readyz`; an edited copy is kept on upgrade, so add it by hand
  (copy the healthz block) to reach readyz through nginx.
- **Monitoring.**  `unmask_event_total` changes meaning: it is the number of
  events this daemon has written since it started (0 at every start), no
  longer the last 24 hours of the event table.  `rate()` and `increase()`
  over it need no change -- the shipped dashboard uses them -- but a rule
  that read the raw value as "events in the last 24 hours" must become
  `increase(unmask_event_total[24h])`, and on nodes sharing one MariaDB each
  daemon now exports its own writes (`sum()` is the total).
  `unmask_event_unique_ip` is an estimate from the hourly rollup and has no
  sample while the daemon has no database or has not finished its first
  rollup pass.  `unmask_db_query_seconds` is a summary.  New:
  `unmask_db_up`, `/unmask/readyz` (200 with the database, 503 without;
  keep a load balancer's health check on `/unmask/healthz`, which is
  unchanged), two alert rules (`UnmaskDaemonDown`, whose `job` label you set
  to your scrape job's, and `UnmaskDatabaseUnavailable`) and a dashboard
  tile: import the dashboard again.
- **A daemon without its database.**  On an install that is set up, a daemon
  that cannot open its database at start no longer sends the admin to the
  setup wizard: admin pages answer 503, the daemon retries, and it restarts
  itself in place (same PID) when the database answers.  Nodes sharing one
  MariaDB take a named lock (`unmask_aggregate:<database>`) while they fold
  events into the hourly statistics; counts an earlier release doubled are
  not corrected, and leave with the rollup's 32-day window.
- **Admin pages.**  The script policy that 0.1.54 published report-only is
  enforced: `Content-Security-Policy: ...; script-src 'nonce-...'
  'report-sample'; report-uri <base>/admin/csp-report`.  Nothing in a stock
  install is affected.  Anything that adds a script to the admin's pages
  from outside is now refused by the browser -- a proxy in front that
  injects or rewrites scripts (an optimiser, an analytics snippet added with
  `sub_filter`), a userscript, an extension that writes a script into the
  page: exclude `<base>/admin/` from it.  Each refusal is one line in the
  daemon's log (`admin csp violation: ...`, at most 20 a minute); on a stock
  install such a line is a bug in the admin to report, or an injected script
  that was stopped.  `POST <base>/admin/csp-report` is new, takes no session
  (the browser sends it on its own) and writes nothing but that line; a
  front proxy that lets only known admin paths through has to let it
  through as well, or the reports are lost.  The install wizard's pages now
  send the admin's security headers too.
- **Passwords.**  Every page that sets an admin password now refuses fewer
  than eight characters, as the setup wizard always did.  Existing shorter
  passwords still sign in.
- **config.yml.**  A pattern the settings page would not have taken -- one
  that does not compile, or that nginx's regex engine could take exponential
  time on -- is now named in the daemon's log at start and by `unmask
  doctor`.  Nothing is changed in the file or in what is rendered.
- **Alpine.**  The plugin now places `load_module` in
  `/etc/nginx/modules/50-mod-unmask.conf`; an install that has the line in
  nginx.conf keeps it there.  To go back to 0.1.55 or older, remove the
  plugin package and install the older one (an in-place downgrade would load
  the module twice).  Alpine 3.22 and older: Alpine's own nginx package is
  built without `--with-compat` and has never loaded the module; use
  nginx.org's package there, or Alpine 3.23.
- **Uninstalling.**  Removing the packages now lists the `include` lines
  left in your own server blocks and prints what `nginx -t` answers
  (README, "Uninstall").  With dnf, leave out `-q` to see it.

### 0.1.55

0.1.55 is 0.1.54 with one fix: the module file is built without fortified
libc calls, so Alpine's nginx (musl, loading the glibc build through
`gcompat`) loads it again.  0.1.54 was tagged but never published; every
item under 0.1.54 below applies to an upgrade from 0.1.53 to 0.1.55.

### 0.1.54 (not published)

- **Sign-in.**  The admin session, its CSRF tokens and the sign-in form's
  token are signed with a new `secret.admin_secret` that only the daemon
  holds; every operator signs in again once after the daemon restarts.
  Nothing to configure: an install whose `config.yml` has no `admin_secret`
  gets one generated and kept at `/var/lib/unmask/admin_secret` (0600, the
  daemon's user).  To carry the key in `config.yml` instead (a backup, or a
  second daemon host behind one admin address) set `secret.admin_secret` to
  any random string; `unmask config-init` writes one on a fresh install.  The
  key must never reach nginx's files; `unmask doctor` reports it if it does.
- **nginx: restart, and re-render.**  Besides the module changes above, the
  plugin's ban lookup now reads `$unmask_ban_ja4`, which the new `http.inc`
  defines on `$effective_ja4` (an older plugin ignores the map), so JA4 bans
  hold behind a balancer that forwards the fingerprint.  With
  `nginx.https_redirect` on, the rendered `server.inc` changed too: re-render
  (`unmask render-nginx`, or any save) and reload.
- **A posture that ends in a CAPTCHA.**  On a site whose operating-mode
  bucket (`known_browser_action` or `unknown_ua_action`) is
  `pow_then_captcha` or `captcha_only`, a visitor holding only a
  proof-of-work pass clears the CAPTCHA once after the upgrade; a
  CAPTCHA-grade pass carries over.  Clearing such a posture already mints a
  CAPTCHA-grade pass, so an ordinary visitor on it is unaffected: what is
  asked again is a pass obtained another way (a `pow_only` bucket, a rate zone
  or a protected path set to `pow`, or a cookie a client minted itself).
  Known browsers on `pow_only` are not touched.
- **Challenge in flight.**  A challenge page served by the previous version
  carries a token the new verify refuses as stale; the page reloads itself
  once and the visitor sees the check again.  The token is now bound to the
  client and names the chain, and a `pow_then_captcha` page sends its
  proof-of-work with the CAPTCHA answer.
- **Runtime directory.**  `/run/unmask` is 0750 and owned by the web
  server's group (the sockets in it already were); the service unit, the
  init script and the container set it.
- **nginx: restart.**  The module changed: it reads the ban list on a change
  instead of on every request, accepts a quoted `_bv` cookie, keeps the
  main-request marker across an internal redirect, encodes the compose
  redirect's query, and is built with a stack protector and full RELRO.
  Restart nginx once the plugin package has been upgraded; a reload keeps the
  module it has loaded, and the admin says so.
- **Challenge page.**  The challenge is served with a Content-Security-Policy
  of its own (a nonce for its inline scripts, `blob:` workers, the CAPTCHA
  provider's origin).  A site that adds its own policy in the same `server`
  block has to allow the same; the FAQ has the details
  (https://unmask.sh/docs/faq/#content-security-policy).
- **Access-log socket.**  `/run/unmask/log.sock` changes from 0666 to 0660
  owned by the web server's group on the first start of the new version.
  The service unit already puts the daemon in that group
  (`SupplementaryGroups=`), so a package install needs nothing.  Where the
  daemon is not a member of the worker's group, or no `nginx` / `www-data` /
  `http` group exists, the socket stays at 0666 and the daemon log and
  `unmask doctor` say so; set `nginx_log.socket_group` (and add the daemon
  user to that group) to share it by group.
- **Outbound connections.**  A webhook, feed or AI endpoint on the host's
  loopback address needs `outbound.allow_loopback: true` from this version;
  the SMTP relay and a local AI model keep loopback without it.  The cloud
  metadata addresses are refused everywhere.  `outbound.deny_private: true`
  closes the private ranges as well.
- **Settings keys.**  New and optional: `secret.admin_secret` (see
  Sign-in), `nginx_log.socket_mode`, `nginx_log.socket_group`,
  `outbound.deny_private`, `outbound.allow_loopback`, `server.access_log`
  (`"off"` silences the line per request), `db.max_conns` (MariaDB, custom
  profile), `db.mysql_tls` (TLS to MariaDB) and the challenge branding's
  `privacy_url`.  Nothing is renamed or removed.
- **Schema.**  Update 0050 adds the table the login lockout counts in; it is
  small and runs at start.
- **Admin pages.**  Every response carries a report-only script policy
  (`Content-Security-Policy-Report-Only`); nothing is blocked, and the
  browser console lists what an enforced policy would stop.  The sign-in
  form now carries a CSRF token: a sign-in page left open from before the
  upgrade must be reloaded once.
- **Plugin.**  The placer puts in only the module built for exactly the
  host's nginx version; nginx loads no other, and the "closest match" of
  the same branch it used to pick never loaded.  With no module for the
  host's version it prints the version, the versions bundled and the ways
  out, and exits 1 (the package install still succeeds; nginx starts
  without the module, as before).  A host whose nginx the bundle does not
  cover should pin the nginx package to a bundled version.

### 0.1.53

- **nginx: restart.**  The plugin and the daemon must move together: the
  pass cookie is bound through nginx's new `$unmask_bind_key`, the reuse
  cap's per-pass tier is keyed on its new `$unmask_bv_id`, and the module
  also changed its ban-file check and the `_bv` cookie budget.  Restart
  nginx once the plugin package has been upgraded.  forward-auth: the nginx
  and Apache snippets changed too; reload nginx / restart httpd so the
  updated snippets are read.  The Apache snippet needs mod_setenvif, which
  the distributions' httpd packages load by default.
- **Sign-in.**  Schema update 0046 gives each account a session generation;
  every admin session is signed out once by the upgrade.  Password-reset and
  invite links sent by an earlier build stop working; send them again.  A
  reset link is now built on `nginx.admin_public_url`; without it, on the
  first hostname in `nginx.admin_allowed_hosts`; with neither, the mail
  carries the path alone.
- **Settings keys, new and optional.**  `nginx.trusted_lb_realip` (the
  visitor's address from X-Forwarded-For behind the trusted LB / CDN set);
  `nginx.cdn_egress_extra` (your own CDN origin-facing ranges);
  `nginx.cdn_egress_ban` (ban CDN egress after all);
  `nginx.admin_public_url` (the admin's own address, used for the links in
  mail); `notifications.critical_url`,
  `notifications.critical_min_severity` and `notifications.critical_format`
  (a second webhook for the critical alerts, with a format of its own);
  `secret.sig_hash` (`sha1`, the default, or `sha256`; below).
- **Schema.**  0046, a session generation per account.  0048 widens
  `cookie_bv` on MariaDB; on a large table it is left for the operator
  (`unmask migrate -status`).  0049, the pass cookies each address presented
  in a day.
- **Defaults and behaviour.**  New checks on by default, held for review on
  an install that reviews its upgrades: the UA-TLS consistency tier, the
  proof-of-work pass budget, and the reuse cap's per-pass budget.  The
  default bypass presets pass GET, HEAD and OPTIONS only.  A crawler passed
  on its name alone meets traps, rules and limits, and a per-address budget.
  With a third-party CAPTCHA configured, a verify without its token is
  refused.  Changing the SMTP host or the AI endpoint clears the stored
  credential.  Forwarded headers count only from a trusted proxy, for
  `/metrics` too.  The data directory is 0751 so nginx's worker reads the
  ban list (no ban held in nginx before).  No automatic ban lands on a CDN's
  origin-facing address (CloudFront, Cloudflare, Fastly); a CloudFront
  preset joins the trusted LB / CDN set.  `nginx.admin_allowed_hosts`, when
  set, guards every admin page, not only sign-in and password reset: list
  every name you reach the admin under before upgrading.  Logging out ends
  every session of the account, on every device.  A pass re-bound to a new
  address ends with the window of the solve behind it (seven days for a
  proof-of-work by default); a visitor whose pass was being carried past
  that window meets a challenge again.  A browser whose Accept-Language
  names neither ja nor en gets the challenge, deny and admin pages in
  English; they were Japanese.  The access log carries the pass cookie
  (`bv=`) once the plugin verified it, and the stats page ranks the passes
  behind each address -- how many in a day, and the busiest hour of one --
  from the moment nginx runs the rendered configuration.
- The pass-cookie reuse cap counts in two tiers now.  The new first tier is
  per pass: one pass (one browser on one network) holds 500 requests an hour
  by default (`rate_limit.reuse.pass_per_hour`), so the people behind an
  office proxy or a carrier NAT each have a budget of their own, and a
  solved CAPTCHA is a new pass with its own.  The address's budget (10,000 a
  day, 2,000 at once) stays as the second tier; a new pass does not reset
  it.  An install that reviews its upgrades runs the address tier alone
  until 0.1.53 is acknowledged.  A site whose pages call its API many times
  a minute from one browser can raise the hourly figure; the stats page's
  "busiest hour of one pass" column shows what the visitors reach.
- The admin's "nginx is still running the previous configuration" notice
  now tells a module upgrade apart: every access-log line carries the hash
  of the module file nginx loaded (`mo=`, the module's `$unmask_module_id`),
  and while the file on disk is newer, the notice asks for a restart in
  place of a reload -- a reload keeps the old module.  It needs the new
  module to say so; this one upgrade still relies on you to restart.
- Cookie signatures and the proof-of-work seed can be HMAC-SHA256.  The
  daemon and the module now verify both HMAC-SHA1 (what every release so
  far signed with) and HMAC-SHA256; what is issued stays SHA-1 until you set
  `secret.sig_hash: sha256`, which is safe once every nginx that verifies
  the site's cookies runs the 0.1.53 module (restarted onto it).  A later
  release makes sha256 the default, and a later one still stops accepting
  sha1.  Cookies signed before the switch stay good for their window.
  `unmask doctor` warns when sha256 is set while nginx still logs lines
  without a module id (an older module, or an older configuration).
- nginx's error log, and `unmask doctor`, now say when the module's TLS
  callback was replaced by another module (every request then runs without
  a JA4): one callback per SSL context is OpenSSL's rule, not a bug to fix
  on either side; load one of the two.

### 0.1.52

- **nginx: reload.**
- **Settings keys.**  `audit_retention_days` became
  `audit_log_retention_days` (the retention tab; 0 keeps the log), with
  `notice_retention_days` for the notification list.  The old key is ignored
  and named at startup; delete it from config.yml to silence the warning.
- **Schema.**  On a large database the upgrade leaves the index builds to
  you -- the stats page's per-visitor card indexes, and 0039 (the Community
  Bans count): run `unmask migrate` when convenient, or start it from the
  admin's notice; the challenge keeps being served meanwhile.  Bans work
  during the build; account and profile edits wait.
- **Behaviour.**  The settings page takes the admin role; a viewer gets the
  dashboard, statistics and bot hunt.

### 0.1.51

- **nginx: reload.**  Native installs need it for path normalization,
  challenge counting and monitor mode.
- **Settings keys.**  `global.passthrough` (pass-through mode) is gone and
  ignored.  If it was on, enforcement is back on; monitor mode
  (`challenge.default.observe_only`) is the switch, and on a module install
  it is rendered into nginx (`render-nginx` + reload after turning it on).
  `search_bots.upstream_disabled` and `upstream_ua_enabled` are replaced by
  `search_bots.upstream_pattern_mode`: crawlers still listed in
  `upstream_disabled` pass again until each is set to Normal checks in its
  group's Detail on the UA filter tab (stored as
  `upstream_pattern_mode: {<pattern>: none}`); the startup log names them.
  `upstream_ua_enabled` needs nothing.  The over-block alarm's `min_serves`
  / `max_serves_per_ip` became `min_stuck_ips` / `stuck_percent`.
- **Behaviour.**  Crawler modes read Pass / Normal checks / Stop (were
  White / Neutral / Black).  The admin shows a notice while nginx runs an
  older configuration.

### 0.1.50

- **nginx: reload.**
- **Schema.**  `unmask migrate` ends at the last index and can be
  interrupted; `unmask db-vacuum` builds the query statistics, and
  `migrate -status` and the upgrade notice point to `unmask db-vacuum -plan`
  for a fragmented database file.
- **Behaviour.**  The SQL-injection honeypot preset is on by default, held
  for review on an install that reviews new enforcement; its patterns now
  match encoded probes.  A site whose search echoes SQL itself can switch it
  off.

## Rolling back

The schema only moves forward: a release's schema updates are not undone,
and an earlier daemon is not run against a later schema.  Going back to an
earlier version therefore starts from the backup taken before the upgrade
(`unmask backup`; `unmask backup -h` has the restore steps).  Without one,
the database stays as the later version left it, and the earlier daemon
starts against it at your own risk.

1. Stop the daemon: `systemctl stop unmask` (`rc-service unmask stop` on
   OpenRC).
2. Put back `config.yml` and, on SQLite, the database file from the
   archive, after removing the `-wal` and `-shm` files next to it; the
   `branding/` files to `/var/lib/unmask/branding/`; `chown` all of them to
   the daemon's user (`unmask`).  On MariaDB, restore the `mysqldump` taken
   with the backup.  Settings keys the earlier version does not know are
   named at its startup and ignored.
3. Install the earlier version, the three packages as one set (the plugin
   and the web snippets are pinned to the daemon's exact version).  The
   repository carries the current release only; the package files of every
   release are on its release page,
   https://github.com/unmask-sh/unmask/releases, under the version's tag.
   - rpm: `sudo dnf downgrade ./unmask-<version>-*.rpm ./unmask-plugin-nginx-<version>-*.rpm ./unmask-web-nginx-<version>-*.rpm`
   - deb: `sudo apt install --allow-downgrades ./unmask_<version>-*.deb ./unmask-plugin-nginx_<version>-*.deb ./unmask-web-nginx_<version>-*.deb`
   - apk: `sudo apk add ./unmask_<version>-*.apk ./unmask-plugin-nginx_<version>-*.apk ./unmask-web-nginx_<version>-*.apk`
   - the gateway container: pin the image to the version in the compose
     file (`image: unmask.sh/unmask:<version>`; the registry keeps every
     released tag, `latest` moves) and `docker compose up -d`.  The
     `/etc/unmask` volume holds the config and the database: put the
     backup's files back there before starting the container.
   The `unmask` package starts the daemon again; otherwise `systemctl start
   unmask`.
4. nginx: the plugin package placed the earlier module file, and a reload
   keeps the one loaded: `nginx -t`, then restart nginx.  The daemon's
   start re-rendered the configuration for the earlier version.
5. `unmask doctor` reports what is left: the rendered configuration nginx
   runs, the module it loaded, and the schema.

Sessions signed out by the later version stay signed out; sign in again.
