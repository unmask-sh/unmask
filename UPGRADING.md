# Upgrading

What a release asks of the operator, from 0.1.50 on.  `CHANGELOG.md` has
every change; this page keeps the actions.  For releases before 0.1.50, read
the changelog's "Upgrade note" paragraphs.

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
  minutes, and never restarts it.  Without systemd, run
  `/usr/share/unmask/nginx-reload-if-stale.sh` from cron.
- Schema: the daemon applies a short schema update when it starts.  An index
  build that would take long is left for the operator: the package output,
  the admin and `unmask doctor` announce it, and `unmask migrate` runs it
  while the challenge keeps being served.
- Afterwards, run `unmask doctor` (from a shell, or from the admin): it
  reports what the upgrade left to do, and whether nginx has loaded the
  rendered configuration.

## Release by release

| Release | nginx | Sign-in | Settings keys | Schema | Defaults and behaviour |
|---|---|---|---|---|---|
| **0.1.53** (testing builds) | **Restart**: the module changed (`$unmask_bind_key`, the ban-file check, the `_bv` budget); update the plugin together with the daemon.  forward-auth: the nginx and Apache snippets changed; reload nginx / restart httpd. | Every admin session is signed out once; sign in again.  Password-reset and invite links sent by an earlier build stop working; send them again. | New, all optional: `nginx.trusted_lb_realip` (the visitor's address from X-Forwarded-For behind the trusted LB / CDN set), `nginx.cdn_egress_extra` (your own CDN origin-facing ranges), `nginx.cdn_egress_ban` (ban CDN egress after all), `nginx.admin_public_url` (the admin's own address, used for the links in mail). | 0046, a session generation per account.  0048 widens `cookie_bv` on MariaDB; on a large table it is left for the operator (`unmask migrate -status`). | New checks on by default, held for review on an install that reviews its upgrades: the UA-TLS consistency tier and the proof-of-work pass budget.  The default bypass presets pass GET, HEAD and OPTIONS only.  A crawler passed on its name alone meets traps, rules and limits, and a per-address budget.  With a third-party CAPTCHA configured, a verify without its token is refused.  Changing the SMTP host or the AI endpoint clears the stored credential.  Forwarded headers count only from a trusted proxy, for `/metrics` too.  The data directory is 0751 so nginx's worker reads the ban list (no ban held in nginx before).  No automatic ban lands on a CDN's origin-facing address (CloudFront, Cloudflare, Fastly); a CloudFront preset joins the trusted LB / CDN set. |
| **0.1.52** | Reload. | -- | `audit_retention_days` removed; `audit_log_retention_days` (0 = keep) and `notice_retention_days` replace it.  The old key is ignored and named at startup. | Index builds a large database leaves for the operator: the stats page's per-visitor card indexes, and 0039 (the Community Bans count).  Bans work during the build; account and profile edits wait. | The settings page takes the admin role; a viewer gets the dashboard, statistics and bot hunt. |
| **0.1.51** | Reload: native installs need it for path normalization, challenge counting and monitor mode. | -- | `global.passthrough` removed: monitor mode (`challenge.default.observe_only`) is the switch.  `search_bots.upstream_disabled` and `upstream_ua_enabled` replaced by `search_bots.upstream_pattern_mode`.  Over-block alarm: `min_serves` / `max_serves_per_ip` replaced by `min_stuck_ips` / `stuck_percent`. | -- | Crawler modes read Pass / Normal checks / Stop (were White / Neutral / Black).  The admin shows a notice while nginx runs an older configuration. |
| **0.1.50** | Reload. | -- | -- | `unmask migrate` ends at the last index and can be interrupted; `unmask db-vacuum` builds the query statistics. | The SQL-injection honeypot preset is on by default, held for review on an install that reviews new enforcement; its patterns now match encoded probes. |

## Details

### 0.1.53 (testing channel)

- The plugin and the daemon must move together: the pass cookie is bound
  through nginx's new `$unmask_bind_key`, and the module also changed its
  ban-file check and the `_bv` cookie budget.  Restart nginx once the plugin
  package has been upgraded.
- Schema update 0046 gives each account a session generation; existing
  sessions are signed out once by the upgrade.
- The forward-auth snippets now set the client address (Apache) and clear
  the cookie's bind-key header themselves; reload nginx or restart httpd so
  the updated snippets are read.
- A password-reset mail goes out only when the admin host allowlist has a
  usable entry; the log says when none does.

### 0.1.52

- `audit_retention_days` became `audit_log_retention_days` (the retention
  tab; 0 keeps the log), with `notice_retention_days` for the notification
  list.  Delete the old key from config.yml to silence the startup warning.
- On a large database the upgrade leaves the index builds to you: run
  `unmask migrate` when convenient, or start it from the admin's notice; the
  challenge keeps being served meanwhile.

### 0.1.51

- `global.passthrough` (pass-through mode) is gone and ignored.  If it was
  on, enforcement is back on; monitor mode is the switch, and on a module
  install it is rendered into nginx (`render-nginx` + reload after turning it
  on).
- `search_bots.upstream_disabled`: crawlers still listed there pass again
  until each is set to Normal checks in its group's Detail on the UA filter
  tab (stored as `upstream_pattern_mode: {<pattern>: none}`); the startup
  log names them.  `upstream_ua_enabled` needs nothing.
- The over-block alarm's `min_serves` / `max_serves_per_ip` became
  `min_stuck_ips` / `stuck_percent`.

### 0.1.50

- The SQL-injection honeypot preset turns on; a site whose search echoes SQL
  itself can switch it off.
- `migrate -status` and the upgrade notice point to `unmask db-vacuum -plan`
  for a fragmented database file.
