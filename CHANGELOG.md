# Changelog

Change history for unmask.  Format follows [Keep a Changelog](https://keepachangelog.com/).
Versioning follows [Semantic Versioning](https://semver.org/).

## Conventions

- Each entry starts with `(YYYY-MM-DD)` — the date the change landed.
- Within a release, entries are sorted by date descending (newest at top).
- An entry is a bold one-line title plus one to three sentences: what was
  wrong or what is new, what changes for the operator, and — for a security
  entry — how it was reachable and which release closes it.  About 40–70
  words.  The reasoning behind a change belongs in the commit message.

## [Unreleased]

### Fixed
- (2026-08-30) **The setup wizard no longer dead-ends when the token sits at the legacy path.**  The token step was shown only when `/var/lib/unmask/.setup-token` existed, while every wizard POST validated against either that file or `/etc/unmask/.setup-token`; an install with only the legacy file skipped the token step and then silently bounced the admin-user step back to itself.  Both now use the same lookup.  The container entrypoint, which wrote the legacy path, now mints the token where the daemon looks first.

- (2026-08-30) **The live tail no longer drops and reconnects every minute.**  A vhost-level `proxy_read_timeout 60` -- a common default -- was inherited by the admin location and closed the SSE stream at 60s regardless of its 5-second heartbeat, so the tail flickered "(reconnecting)" once a minute for as long as it was open.  The rendered location now sets its own hour-long read and send timeout.  Native installs: `render-nginx` + reload.

- (2026-08-29) **The bot-hunt date column is back to 13rem.**  0.1.36 moved the host pill out of the cell and then widened the column to 18rem, so on every row without a site badge -- most rows on a single-site install -- the timestamp sat beside a hand's width of empty space before the IP.  The width is what it was before any of this; the cell keeps clipping, so a badge that does not fit under an unusually wide font is cut rather than painted over the IP, and its full value is in the popover.

### Added
- (2026-08-30) **Container images, with a gateway that needs no nginx of your own.**  `ghcr.io/unmask-sh/admin` is the daemon; `ghcr.io/unmask-sh/nginx` is the official nginx image plus the module.  With `UNMASK_UPSTREAM` set the nginx container terminates TLS on :443 -- so it sees the real ClientHello and JA4 works -- runs the decision, and proxies what passes to any HTTP server; without it, it is a plain nginx-with-module for your own conf.d.  The nginx container reloads itself a few seconds after the admin renders a change (`nginx -t` first; `UNMASK_AUTORELOAD=0` turns it off).  `docker-compose.example.yml` wires the two up with a stand-in upstream.

- (2026-08-30) **Settings > Gateway: the vhost name and its certificate, managed in the admin.**  Shown only on a gateway install.  Three certificate sources: automatic HTTPS through nginx's own ACME module (Let's Encrypt, production or staging, issued and renewed in place with no client or cron), a pasted purchased certificate (certificate, intermediate chain, key; checked for a matching pair and expiry, stored with the key readable by nobody else and never shown again), or paths to files something else keeps current.  The tab shows what :443 is actually serving -- issuer, expiry, name match.  The `UNMASK_SERVER_NAME` / `UNMASK_ACME_*` / `UNMASK_TLS_*` variables on the admin service only seed the tab on the first boot.

- (2026-08-30) **The live tail shows the flag, the network, the user agent and the path.**  Each streamed event now carries the country and ASN its address resolves to and the same short user-agent reading the static rows use, so a line reads like a table row: flag, address, network, phase, fingerprint, verdict, UA, path.  The path and UA are clipped at the end of the line with the full value on hover.

- (2026-08-29) **doctor notices when an install's history has split in two.**  With `server.host_id` unset an install records under its OS hostname, so a rename splits its history into two names with nothing saying they are the same node.  doctor now warns when the database holds several host ids and none is pinned here; the fix is `server.host_id` on each node.

## [0.1.36] - 2026-08-28

### Fixed
- (2026-08-27) **The bot-hunt log's date cell painted over the IP beside it.**  The column is fixed-width and never clipped, so a third element (the host pill, shown only after a host rename) spilled onto the next cell.  The node's host id moved into the timestamp popover as a labelled row, the column is wider, and the cell now clips -- which holds whatever monospace font the viewer's machine resolves.

- (2026-08-25) **Security: the challenge page could redirect a visitor off-site.**  `/unmask/challenge/?_test_redirect=` was guarded by three character checks that a URL parser defeats -- it strips TAB/CR/LF before parsing, so `/%09/evil.example` navigated to `//evil.example`.  Reachable on every install with default settings; five Go-side redirects shared the same guard.  All now resolve the value against the page's own origin.  Request-supplied values are also stripped of control characters before reaching the daemon's log.

- (2026-08-25) **Security: alert mail could have a header injected through it.**  Header values were written unfiltered, and a notification subject carries the address or site an event came from -- so whoever caused the event chose part of a mail header, and a CRLF in it became a new header or the body.  Every header value is now filtered where it is written: CR/LF become spaces, other control characters are dropped.

- (2026-08-23) **doctor no longer says the packaged challenge asset is the one being served.**  Since 0.1.32 the embedded assets are authoritative and a copy under `/usr/share/unmask/challenge/` reaches nobody, but doctor kept its pre-0.1.32 wording claiming the opposite.  It now says the copy on disk is unused, names the two ways to make it count, and is an informational line rather than a warning.

- (2026-08-23) **Unpinning a popover left it stranded on screen.**  Clicking a pinned popover again returned it to hover form without registering it as one, so no gesture could close it.  Two clicks on a bot-hunt phase reached it.  The unpin path now goes through the same registration every hover opening does.

## [0.1.35] - 2026-08-23

### Added
- (2026-08-21) **The bot-hunt timeline shows which TLS fingerprint each phase actually presented.**  A beacon is its own connection and can carry a different JA4 than the challenge it answers, so a row could show a bot-verdict pill beside a fingerprint matching no rule.  The serve-time fingerprint now rides every beacon, a `⇄` marks rows whose connection differed, and the session timeline gains a fingerprint column.  Display-only: enforcement never reads the echo.

### Changed
- (2026-08-21) **Every unset axis action now resolves to `pow_then_captcha`.**  header-integrity, stale-browser, manual bans and the community feed used to fall back to `captcha_only`; they now match the honeypot and rate-limit default.  Same clients stopped, same pass grade -- but the proof-of-work leg first splits the outcome into cannot-run-JS / headless solver / person.  An explicit `captcha_only` is unchanged.  Installs that never set these pick the change up on upgrade.

- (2026-08-21) **The statistics tables' user-agent columns read like the hunt log's.**  A platform glyph and a short reading (`Windows 10 · Chrome 126`) replace several hundred pixels of raw `Mozilla/5.0 (…)` that distinguished nothing; the full agent stays one click away.  Applies to the cookie-reuse rankings, the CAPTCHA pass/fail tables and the stealth card.

- (2026-08-21) **The absence of a verdict is one token everywhere: `(none)`.**  The same unlabelled request showed as `ok`, `none`, `(none)` or `-` depending on the page -- and `ok` asserted an evaluation nobody performed.  Every verdict column now renders it as `(none)`, sorted after every named verdict; the funnel's permanently empty `ok` row is gone.

### Fixed
- (2026-08-21) **A rebind lineage could be forgotten while its CAPTCHA cookie was still valid.**  The 8-day cutoffs on the cookie-reuse table and on rebind lineages predate unmask's own 7-day PoW / 14-day CAPTCHA defaults, so a pruned lineage let the next rebind reset its per-lineage limits.  Both windows are now 15 days.

## [0.1.34] - 2026-08-21

### Fixed (security)
- (2026-08-20) **Security: a proof-of-work cookie no longer satisfies a bot-verdict JA4 rule.**  A fingerprint marked `bot` was CAPTCHA-gated only for clients arriving bare; any PoW cookie -- minted under another fingerprint, or before the rule existed -- passed for the cookie's lifetime.  Seen live with a residential-proxy herd.  The JA4 axis now joins the CAPTCHA-grade gate on both wires.  Native installs: `render-nginx` + reload.

### Changed
- (2026-08-20) **The stats range picker goes below a day: 1h / 3h / 6h / 12h.**  Judging a rule changed ten minutes ago against a 24h window reads mostly pre-change traffic.  Sub-day windows bypass the hourly rollup (whose grain would leak up to an hour on either side) and scan raw events on exact timestamps.

- (2026-08-20) **A bot-verdict fingerprint with no configured chain inherits the operating default on every consumer.**  Forward-auth hardcoded `captcha_only` while native served the operating default, and with the grade gate that disagreement is a challenge loop.  One resolver (`EffectiveJA4BotChain`) now serves the check, the serve, the gate and the render.  An explicit `pow_only` remains the opt-out.

### Fixed
- (2026-08-20) **A pass rate stops rounding up to `100.0%` beside a non-zero Challenged column.**  `100.0%` and `0.0%` are reserved for the exact values; anything short reads `>99.9%` or `<0.1%`.

- (2026-08-20) **A bot-hunt ranking card no longer stretches the row it sits in.**  The address card, holding far more distinct values than its neighbours, set the row height and pushed the event log down the page.  Overflow now scrolls inside the card with the header fixed.

- (2026-08-20) **Four app user-agent labels now read in English.**  `Google アプリ` and three others were Japanese literals in the classifier, so they rendered as Japanese in an English admin.  Japanese belongs in i18n.

## [0.1.33] - 2026-08-20

- (2026-08-20) **Security: a headless browser could clear the behavioural CAPTCHA at full marks.**  The check read the mouse trail's shape and ignored its timing, so a driver tracing a curve scored 1.0.  It now reads how the movement was built -- a script interpolating a path repeats one step length, a hand does not -- and a real automation-driven Chrome scores 0.4.  Untrusted (page-dispatched) input and touchless phones with a cursor are also marked down.

- (2026-08-20) **The numeric-add fallback no longer hands CAPTCHA grade to scripts.**  It asked for arithmetic, the one task a headless browser does best.  A pass with no input events behind it (a script assigning `.value`) is now issued at proof-of-work grade, so it fails exactly where an operator demanded a CAPTCHA.  Challenge pages cached before this keep the full grade.

- (2026-08-20) **A refusal says which axis refused.**  Every deny logged as `axis_deny`; they now read `geo_deny` / `asn_deny` / `ua_deny` / `ja4_deny` / `community_deny` and carry the matching entry.  The hunt reason filter can select them.

- (2026-08-19) **Alerting reaches the operator, and admin accounts grow a lifecycle.**  Notification settings become their own tab (webhook, mail, SMTP server), an invitation is a settings link rather than a shared password, and an account can be disabled without being deleted.  `doctor` warns when alerting is configured but cannot deliver.

- (2026-08-19) **`mysql` is accepted as a driver name.**  The backend has always been both — one wire protocol, one driver — but a hand-written `driver: mysql` failed to open, and would have mis-branched the per-driver code had it opened.  The alias normalises at load; the labels that still said only MariaDB now say MariaDB/MySQL.

- (2026-08-18) **The hub feeds are signed.**  Each bypass-range document carries a detached ed25519 signature made on a host other than the one serving it, and the daemon refuses a mismatch or a document older than the one it holds.  `sync_insecure_tls` waives the transport check but makes the signature mandatory.

- (2026-08-18) **Range updates without a network.**  `update-iprange -file` imports a local copy of the aggregated document; `unmask sign-feed` signs and verifies one for self-hosted hubs.  A running daemon now notices override files another process wrote, so a CLI sync is no longer rolled back by the next settings save.

- (2026-08-18) **Bypass presets follow the user-agent policy you already set.**  A range preset added in a later release sat unchecked forever on installs that had saved their list, leaving its vendor on name-only rescue.  A vendor whose crawlers already pass by name now gets its published ranges enabled automatically -- address verification, so only impostors change fate.  Requires unanimity and fresh data; never written into your config.

- (2026-08-18) **The retention page stops blaming the wrong card, and stops timing out.**  A log-ingest timeout used to flag the (correct) prune stats; flags are per card now, and the row count is an O(1) estimate rather than a scan that outran the query budget.

- (2026-08-18) **The release refuses to ship a stale range snapshot.**  Refreshing the compiled-in ranges was a manual step that went six weeks unrun, so installs that cannot sync refused genuine crawlers.  A snapshot older than a week now fails the release.

- (2026-08-19) **An admin account can be disabled without deleting it.**  A suspended account refuses sign-in (indistinguishably from a wrong password), loses its session on the next request and drops out of alert-mail recipients; role, email and history stay.  The last enabled superadmin cannot be suspended, and you cannot suspend yourself.

- (2026-08-19) **New admin users can be invited by mail, with no password ever travelling by mail.**  The account is created under a random password nobody sees and the invitee gets a one-time setup link (72 hours) to choose their own.  A per-row "send setup link" button doubles as admin-side password recovery.  Requires SMTP and an email; every send is audit-logged.

- (2026-08-19) **Alert mail can go to an explicit address list.**  `notifications.mail_to` names the alert recipients directly, separating the account contact from the alert destination; left empty, alerts still go to admin users' emails.  While set, the per-user opt-out is not consulted.

- (2026-08-19) **Each notification channel can be paused.**  Webhook and alert mail get their own toggle, so muting no longer means blanking a URL or host.  Pausing alert mail leaves the SMTP transport alone, so password-reset mail keeps working.

- (2026-08-19) **`__hostname__` in notification labels.**  `notifications.site_label` and `smtp.from_name` expand it to the install's host id at startup and on save, so a fleet ships one config fragment and an alert's label matches the events host column.

- (2026-08-19) **doctor: over-block alert deliverability.**  With the breaker armed (its default) and neither a webhook URL nor an SMTP host configured, doctor now warns that a trip shows nowhere but the daemon log and the overview banner — the shape of the 2026-06-08 incident, where a challenge loop over-blocked visitors for ~14h before anyone looked.

### Changed
- (2026-08-19) **The over-block breaker counts browser-grade traffic only.**  Serves with no User-Agent or a confirmed-bot JA4 verdict no longer feed its ratio: a scanner swarm is not a visitor stuck in a loop, and its volume drowned the signal (a 2026-07-04 trip was 170 UA-less probes).

### Fixed
- (2026-08-19) **`starttls: false` sent mail over STARTTLS anyway and failed on the relay's certificate.**  The plaintext path used stdlib `smtp.SendMail`, which upgrades whenever the server advertises STARTTLS and then verifies the certificate -- fatal for the self-signed localhost relay the setting exists for.  Plaintext now never upgrades.

- (2026-08-19) **Every mail send blocked up to ~10s on a DNS lookup.**  The EHLO name was resolved as CNAME("localhost") through DNS — the wrong name to advertise (EHLO names the client) and a resolver-timeout stall on hosts with no answer for it.  It is now the host's own name.
-->

## [0.1.32] - 2026-08-18

- (2026-08-16) **A CAPTCHA pass is a pass, not proof of a person.**  The overview's CAPTCHA tile summed every request carrying a CAPTCHA-grade cookie and called it humans.  It now separates solves from returning cookie traffic, both tiles explain what they count, and the report's `ok` column is named as a TLS-fingerprint grade.

- (2026-08-16) **Truncation is measured in a way every browser agrees with.**  `scrollWidth` never reported overflow for table cells on Firefox, so the underline and full-value popover were missing there.  A DOM Range measures the content now; every clamped cell shows the same dotted underline, and the popover assets are cache-busted.

- (2026-08-16) **Admin tables come in two sizes, on purpose.**  Four drifted font sizes across the hunt, bans and statistics tables become two deliberate tiers, and a request line hundreds of characters long is clipped in its cell instead of setting the table's width.

- (2026-08-16) **A hunt row always names its site.**  The site badge was suppressed on single-site installs as redundant, but "redundant" assumed the reader knew the install was single-site; the row now says where the event happened, every time.

- (2026-08-15) **The timeline says which clock each line came from.**  Times reconstructed from the browser's own intervals are marked `≈` with a legend; server-stamped lines carry no mark, so the mark means something.

- (2026-08-15) **An abandon pill says whether the visitor ever got in.**  It now answers the operator's actual question: did this client later pass (`✓`) or not (`∅`), at the front of the pill where it survives overflow.

- (2026-08-15) **A ranking that could not be read says so.**  A hunt ranking that exceeded the statement timeout rendered as empty -- indistinguishable from "nothing matched" mid-incident.  Each failed ranking now says it was unavailable.

- (2026-08-15) **A geo or ASN rule's chain is the chain that gets served.**  On native installs the challenge endpoint attributed a serve to the rule that fired and then served the site's default chain -- `captcha_only` came out as `pow_then_captcha`.  The serve now uses the same resolution that named the axis.

- (2026-08-15) **The built-in challenge assets are what runs, unless you say otherwise.**  A copy under `/usr/share/unmask/challenge/` silently outranked the embedded assets, so an upgrade could ship a new page and an old overlay kept serving.  Embedded wins now; a custom page needs the explicit `challenge_html_path` / `challenge_js_path` setting, and a stray overlay is warned about at startup.

## [0.1.31] - 2026-08-15

- (2026-08-15) **A session that ran exactly as served was reported as having diverged.**  Any CAPTCHA on a chain other than `captcha_only` counted as a departure, so `pow_then_captcha` was flagged the moment it reached its second leg.  The line now reads the reason each CAPTCHA beacon already records, so only a real escalation is called out.

- (2026-08-15) **What a visitor did after abandoning rides inside the abandon pill.**  The separate chip wrapped onto its own line and read as another step; it is now one character at the front: `↩` when a request followed, `∅` when none did.

- (2026-08-14) **A honeypot ban says which host was probed, not just which path.**  `/cgi-bin/…` exists on every vhost, so the path alone could not say which site was scanned.  Both deployment modes now record the host, budgeted so a kilobyte of path cannot push it out.

- (2026-08-14) **A ban reason that is really a request line no longer sets the width of the whole table.**  Honeypot paths are injection probes hundreds of characters long; the reason is now clamped with the full value one hover away, and address / fingerprint / action columns no longer wrap.

- (2026-08-14) **The bot-hunt log orders a session by when the browser sent each beacon, not when the server received it.**  Phases leaving in the same JavaScript tick raced over the wire and could show a CAPTCHA before the proof of work that led to it.  Beacons carry the page's sequence number; the absolute clock stays the server's.

- (2026-08-14) **Security: a geo or ASN rule set to a CAPTCHA was satisfied by a proof-of-work cookie.**  The pass-cookie gate consulted the user-agent chain, protected paths and the community feed but never the network axes, on either deployment mode.  Both now fold geo and ASN into the same grade requirement; rate-limit-mode rules are unaffected.

- (2026-08-14) **An ASN rule matching on organisation rendered a config nginx refuses to load.**  An organisation name can contain a space and the geo block emitted it unquoted; the render succeeded and `nginx -t` failed afterwards.  Values are quoted now.

- (2026-08-14) **The built-in CAPTCHA is the recommended one.**  An external provider must be told which domains may use it, and an admin panel on an unregistered host fails the check -- locking the operator out of the page they would fix it on.

- (2026-08-13) **The statistics page offers only the spans it can fill.**  A range longer than the data on hand looked like an outage; the choices now stop at the oldest hour actually stored.

- (2026-08-13) **Self-measured figures are out of the shipped files.**  The rendered nginx configuration and the challenge page served to every visitor carried request counts, address-pool sizes and node names from our own deployment, used as evidence in code comments.  The arguments never needed the numbers, and they are not ours to publish on someone else's install.

## [0.1.30] - 2026-08-12

> Anthropic's crawlers are verified by address now.  Anthropic used to be the
> one major AI vendor that published no crawler IP ranges, which left ClaudeBot
> as the one major AI crawler this project could not verify: every request
> wearing the name passed on the user-agent string alone.  That gap closed --
> claude.com/crawling/bots.json exists -- and the difference it makes is not
> subtle: on a site with the preset on, the overwhelming majority of requests
> wearing the name turn out to come from somewhere else entirely, scattered
> cloud addresses probing for `.aws/credentials` and `.env` under the borrowed
> name.  This release also adds `unmask stats`, a read-only report for the
> operator whose database is exactly the thing they cannot open.

### Added
- (2026-08-12) **Anthropic's crawlers are verified by their published IP ranges.**  A new `claude` preset carries the official list for ClaudeBot, Claude-User and Claude-SearchBot; with it on, only an address inside the ranges passes, as Googlebot / GPTBot / Applebot already work.  Fresh installs get it by default; existing installs keep their saved list until they opt in.

- (2026-08-12) **`unmask stats`: the numbers, without opening the database.**  A read-only aggregate dump for hosts where a DB client is unavailable (CentOS 6's sqlite3 refuses WAL files).  Six reports over one window, `-site` scoping, and `-tsv` for `awk`.

### Fixed
- (2026-08-12) **The over-block breaker no longer trips on a scanner farm.**  Web-shell probes from a few cloud addresses produce exactly the serves-per-address ratio it watched for while never loading a challenge page.  It now requires the loads to corroborate the ratio.

- (2026-08-12) **The traffic-composition card stopped hiding its breakdown behind a wrong diagnosis.**  A small skew from minute-bucketed counters against hourly terms tripped a double-counting warning that replaced the whole breakdown.  The residual is now shown honestly; the warning is reserved for a counter feed that is off entirely.

- (2026-08-12) **A hunt row names its Host when the reader cannot infer it.**  A row outside every declared site showed an address with no context.  Ghost hosts carry an amber badge, and collapsing a session keeps the phase cell's badges.

- (2026-08-12) **`unmask doctor` no longer tells you to run it with sudo.**  doctor drops privileges before that check ran, so the advice was unreachable; the permission notes now name the actual remedy (group membership for the paths).

## [0.1.29] - 2026-08-11

> A fix for anyone running behind forward-auth on nginx: a fresh install would
> challenge you for your own admin login, refuse the credential that challenge
> minted, and challenge you again -- with no way out from the browser.  Nothing
> had to be misconfigured to reach it.  Native (nginx module) and Apache
> forward-auth deployments were never affected.

### Fixed
- (2026-08-11) **A fresh forward-auth install on nginx locked you out of its own admin.**  The default "unmask itself" preset demanded a CAPTCHA-grade pass for `/unmask/admin/`, but the challenge recovered the URI through a helper that drops anything under the unmask mount, never learned the request was protected, and served a proof-of-work screen -- solved, refused, served again, forever.  The protected rule now resolves from a helper that keeps those URIs.

- (2026-08-11) **A challenge is never served that the gate would refuse.**  If a CAPTCHA-grade pass is required, the chain now ends in a CAPTCHA whatever route picked it; escalation keeps the proof-of-work leg, so it is never weaker than what was chosen.

- (2026-08-11) **Collapsing a session in the bot hunt threw away its badges.**  The rate-limit zone, the LB-misconfiguration warning, the returned/gone marker and the reload counter were all dropped when a session had a second row.  All four now survive the collapse.

## [0.1.28] - 2026-08-11

> The community feed now enforces on every deployment.  It shipped enforced by
> a set of nginx map lookups, which meant a forward-auth install -- Apache, or
> nginx without the module -- pulled the shared list, showed it in the admin,
> and blocked nothing with it.  The same release settles what a feed hit and a
> black-listed user-agent actually cost, in one place each, so both deployment
> modes answer the same way.

### Fixed
- (2026-08-11) **Security: the community feed enforced nothing on forward-auth deployments.**  Enforcement lived in the nginx map files, which Apache and forward-auth nginx never read -- such an install listed every entry as enforced while every listed client walked through.  The daemon now builds its matcher from those same map files, so a hit is enforced in-process.

- (2026-08-11) **A community-feed hit was reported as nothing at all.**  It was folded into the protected-path variable and arrived with `force_reason=none`.  It is now its own axis end to end, reported as `community_bans` with the match kind.

- (2026-08-11) **A community-feed hit could re-challenge forever on a PoW-only install.**  The hit raised the CAPTCHA-grade requirement but never chose the screen, so a `pow_only` install minted a cookie the next request refused.  One value now drives both.

- (2026-08-11) **A black-listed user-agent met a different challenge depending on the deployment mode.**  Native inherited the install's default chain; forward-auth kept a fixed `captcha_only` from before the picker existed.  All consumers resolve through one function now, so forward-auth with the picker unset serves the default chain.

- (2026-08-11) **Deleting old events could starve the ban lookup.**  Retention issued one unbounded `DELETE` that exceeded its budget, rolled back and retried every run while holding locks the ban lookup needs.  Pruning now runs in bounded batches that keep what they committed and checkpoints the WAL.

- (2026-08-11) **Port 80 (https) behind a load balancer.**  Hunt read the port from the connection to nginx, which behind a TLS-terminating load balancer is the backend hop, not the visitor's.  It now records the forwarded port and shows the accepted one beside it when they differ.

- (2026-08-11) **Inherited labels went stale while you were editing.**  Changing a tab's default left every "unset" option, the new-row scaffold and the view pills naming the old value until a reload.  Fixed on the protected-paths, ua-filter, country and ASN tabs.

### Changed
- (2026-08-11) **The community feed's action is yours to pick.**  A hit was hardcoded to a CAPTCHA; it now takes `pow_only` / `captcha_only` / `pow_then_captcha` / `deny` on the Community Bans tab, applied identically on both wires.  Default `captcha_only`.  Verified search bots, bypass IPs/paths and a valid pass cookie are still consulted first.

- (2026-08-11) **Protected paths take a default mode.**  A row or preset left unset follows a tab-level default instead of a fixed value, the same way the country and ASN tabs already work.

### Removed
- (2026-08-11) **`bans.community_bans_default_action`.**  It looked like the knob for what a feed hit costs, but community entries are never written to the local ban list, so nothing ever read it.  The setting on the Community Bans tab replaces it.

## [0.1.27] - 2026-08-10

> A protected path that asks for a CAPTCHA now gets one.  The gate that guards
> unmask's own admin login shipped on by default and could be satisfied by a
> proof-of-work cookie -- the exact credential a headless solver mints for
> itself.  The rest of the release is retention: raw events are the only thing
> the retention window still governs, so its default drops to a week and a busy
> install stops growing toward tens of gigabytes.

### Fixed
- (2026-08-10) **Security: a protected path whose mode ends in a CAPTCHA was satisfied by a proof-of-work cookie.**  The pass-cookie exemption never consulted the protected axis, so a headless solver's PoW cookie walked through the captcha-graded gate on the product's own admin login.  Both deployment modes now require CAPTCHA grade for `captcha` and `pow_then_captcha` paths; `pow` paths are unchanged.

### Changed
- (2026-08-10) **A protected path's mode is the challenge it runs.**  The served chain used to come from three inheritance layers an unrelated tab could change.  A path now carries one value that is both match mode and action: `pow`, `captcha`, or `pow_then_captcha` (new, default).  `strict` is gone.

- (2026-08-10) **Raw-event retention defaults to 7 days.**  Raw events back only the bot-hunt log, support lookups and rankings; every long-range chart reads fixed 32-day aggregates.  On a high-volume install 30 days runs to tens of gigabytes.  Existing installs keep their stored value.

### Added
- (2026-08-10) **The crawler trend and declared sites' funnels survive a short retention.**  Both still followed the raw-event window; the trend now uses the fixed 32-day window, and declared sites get their own funnel aggregates (no backfill).

- (2026-08-10) **The retention tab projects the disk.**  Observed growth per day, the size the current setting converges to, and free space on the volume, with a warning when the projection fills the disk.

- (2026-08-10) **Hunt shows where a visitor came from.**  The `Referer` of the request that was challenged (and, on forward-auth, of one that passed) is recorded and shown in the URL cell's popover -- context for reading whether a person navigating in from your own pages hit a challenge.  Empty on most rows, since bots rarely send one.

## [0.1.26] - 2026-08-09

### Added
- (2026-08-09) **Upgrade review: an upgrade never silently tightens what you block.**  On the `review` policy (default for fresh installs) a new default-on enforcement preset stays inert until you acknowledge it; rescue presets are never held.  A dashboard banner and `unmask upgrade-review` apply them.  Existing installs default to `apply`.

- (2026-08-09) **A GCP load-balancer health-check stats-exclude preset.**  One opt-in toggle drops the probe ranges (35.191.0.0/16, 130.211.0.0/22) from statistics and bypasses the challenge -- a failed check drops the node.

### Changed
- (2026-08-09) **A shipped preset is active from the release that ships it.**  The old opt-in gate keyed on a drifting `seen_version`, so nodes silently ran different rulesets.  Presets now apply at their declared default on every install; `seen_version` remains only as the "NEW" badge.

- (2026-08-09) **Every preset in the settings UI carries a version.**  A few presets — the trusted-LB and HTTPS-redirect-exempt groups, and the stats-exclude toggles — rendered without the "since vX.Y.Z" label the other presets show; they now carry it (and a NEW badge when added after your last save), so a preset a later release adds is always identifiable.

### Fixed
- (2026-08-09) **A client disconnect no longer logs as an insert error.**  On a busy node a client often drops before the async `unmask_event` (or audit) insert finishes, cancelling the request context; that abort was logged as an error — noise, not a fault.  It is now logged only when the context is still live.

## [0.1.25] - 2026-08-09

> Mostly the settings surface this release: text you typed into a rule survives a
> rejected save instead of vanishing, every tab lives at its own URL, the
> admin-host allowlist speaks in hosts rather than raw regex, and the overview's
> composition card is yours to slice.

### Changed
- (2026-08-09) **The admin-host allowlist speaks in hosts, not generic patterns.**  "contains" was a substring match that would admit `example.com.attacker.com`.  The modes are now **exact**, **subdomain** (end-anchored) and **regex** (full-string); a legacy contains entry reads as exact.

- (2026-08-08) **Each settings tab has its own URL.**  The tab was a query parameter (`?tab=network`); it is now a path segment (`/admin/settings/network/`), matching the stats and per-site pages, so a tab can be linked, bookmarked and opened in a new window as itself.

- (2026-08-08) **Every segment of the overview's composition card is a filter.**  The segments of the traffic-composition bar can each be clicked in or out of the denominator, so the headline percentage recomputes against exactly the slice you want to read; the selection persists in a cookie, and the card now shares the legend behaviour the stats charts already had.

### Fixed
- (2026-08-08) **A rejected rule-list save no longer discards what you typed.**  Every settings tab now keeps your input on rejection, opens only the rows you changed, and marks the offending row with the reason.

- (2026-08-07) **The admin-host allowlist honours its own mode toggle, and rejects a pattern it cannot use.**  A regex host was read literally and an invalid one silently dropped, leaving the gate open under a green "saved" banner.  Invalid values are now rejected at save with the reason.

- (2026-08-08) **The composition breakdown reads as figures and stays put when pinned.**  Its popover rows now separate their label from their number, keep their styling when the popover is pinned to the page, and reserve the room a toggled-off segment needs so the legend no longer reflows as you click.

## [0.1.24] - 2026-08-07

> One production report drove most of this release: a distributed crawler that
> solved a single challenge and walked the credential across hundreds of
> addresses -- the same crawler whose deny fix shipped in 0.1.21.  Passing by
> re-binding was invisible, because every individual request was a legitimate
> pass, and it was cheap, because one solve priced the whole fleet.  This
> release makes it visible everywhere it shows up, and makes a CAPTCHA posture
> actually cost a CAPTCHA.

### Fixed
- (2026-08-07) **The overview page slowed with the size of the event log.**  Its 24h counters scanned the raw event table on every load -- 20 seconds cold on a large node.  They now read the hourly rollup; figures are unchanged, the window is hour-aligned.

- (2026-08-06) **A pass earned by re-binding onto a new address was reported as a CAPTCHA solve.**  The plugin classified a cookie by shape, and a re-bound entry has the same shape as a solved CAPTCHA.  Both wires now report the signed kind; re-bound passes appear in the composition's residue and the reuse ranking.

### Changed
- (2026-08-06) **Security: a rule whose chain ends in a CAPTCHA is satisfied only by a CAPTCHA-grade pass.**  A UA deliberately put behind a CAPTCHA walked through on a proof-of-work cookie, and a silent re-bind extended that pass to new addresses.  Each solve now records its grade into the credential; the exemption requires that grade on both wires, and a re-bind checks the lineage's grade.

- (2026-08-06) **A cookie minted while enforcement was off no longer reads as a solve.**  Monitoring-mode passes inflated the pass counts and satisfied the exemption after enforcement was turned on.  They are their own kind now, never sufficient for a grade requirement.

### Added
- (2026-08-07) **Paths on the stats page say which host they belong to.**  Path rankings carried the path alone, which on a multi-site install answers less than it seems; each row now names the site and carries the same popover as hunt, with the full URL ready to open.

- (2026-08-07) **The pass KPIs name the requests an existing cookie admitted.**  Each pass card carries a second line counting requests admitted by cookies of that kind, in its own units.

- (2026-08-06) **How far one solved challenge has travelled is now visible.**  The stats page ranks credential lineages by the distinct addresses a single solve was re-bound onto, with refused re-binds and cap status -- ranked by spread, because the case worth finding never surfaces by volume.

## [0.1.23] - 2026-08-06

> 0.1.22 was published to the pre-release (testing) channel only and never
> reached stable; everything it carried ships here.  A build superseded while
> in testing keeps its number and stays there -- one version never means two
> different files.

### Fixed
- (2026-08-06) **A schema migration could wedge an install forever when the database already carried part of its work.**  A duplicate column aborted the file before its `CREATE INDEX`, the version was never recorded, and every restart retried into the same error.  Duplicate column / key errors now count as that statement already done; anything else still aborts.

- (2026-08-06) **The abandonment rate counted rule-targeted crawlers, so on a bot-heavy site it read as a catastrophe.**  Departures a rule caused are the rule working.  The rate is now computed over visitors no rule pointed at; the same window reads 4.8% instead of near-total.

- (2026-08-06) **Promoting an rpm out of the pre-release channel could not tell the identical build from a different one.**  Rpms are re-signed with a fresh timestamp on every index, so bytes never matched twice.  The payload digest is compared now; deb and apk stay byte-compared.

### Changed
- (2026-08-06) **Rendering the same settings twice no longer rewrites the files.**  Every render rewrote every file, so mtimes meant nothing and the stale-config check called all seven fleet nodes stale after a no-op upgrade.  A render whose output differs only in its stamps leaves the file alone.

### Added
- (2026-08-06) **doctor now notices a rendered config that nginx never loaded.**  Saving settings renders the conf and deliberately does not reload nginx, and every check read healthy in that gap.  doctor reads the newest worker's start time from `/proc` and warns when the config changed after it.

- (2026-08-06) **A leftover `challenge_targets.all` gets a warning that names the consequence.**  Removed in 0.1.19, it produced only "unrecognized keys (ignored)" -- on one install describing a downgrade.  The warning now names the replacement: a UA row with action deny.

- (2026-08-06) **Publishing verifies what is now being served, from the URLs a client would use.**  An apk index once reached unmask.sh unsigned, which empties the repository.  The publish now fetches the signatures clients verify, inspects the apk index for its `.SIGN` entry, and installs from the live repository in a container per format.  It also refuses an unresolvable signing key or a mixed-version tree.

- (2026-08-06) **Reindexing stable cannot silently replace a build that testing confirmed.**  Every artifact is compared against the testing tree first (payload digest for rpm, bytes for deb/apk); replacing a confirmed build on purpose needs `UNMASK_ALLOW_TESTING_MISMATCH=1`.

- (2026-08-06) **`unmask version` names the commit it was built from.**  Two binaries that differ were indistinguishable once installed; the commit is now stamped at link time and printed beside the version.

## [0.1.21] - 2026-08-06

### Added
- (2026-08-05) **A pre-release channel, so a fix can be confirmed by its reporter before it ships.**  Promotion copies the artifact rather than rebuilding it.  `unmask-release` configures the channel inactive on every install; enable it by name (`--enablerepo=unmask-testing`, an apt pin, `apk --repository`).  See https://unmask.sh/docs/faq/#install-specific-version.

### Fixed
- (2026-08-05) **Security: "deny" did not deny.**  Every axis except the ban was consulted only when the visitor held no pass cookie, so a crawler that solved the proof of work once per address rode through a UA row set to deny for a week.  A resolved deny is now enforced beside the ban, ahead of anything that reads the cookie, on both wires.  Rescues still win.

- (2026-08-05) **The overview counted some requests twice, and could not say how much of the traffic was human.**  A request with a pass cookie that also matched a bypass rule counted as both.  The classification is one decision now, the human share counts requests holding a pass cookie, and the unattributed remainder gets its own segment.  Parts now sum exactly to the total.

- (2026-08-05) **A rescued crawler was counted as nothing in forward-auth mode.**  Only three of four buckets were recorded on `/api/check` nodes, so the benign share sat at zero all day.

- (2026-08-05) **Turning on Web Bot Auth made every request to the vhost pay for the whole decision chain.**  Its gate was keyed on an eagerly built value, so static-file locations computed the JA4 fingerprint and every axis.  Measured 56k -> 3.9k req/s; now 42-54k.  Privacy Pass had the same shape.

## [0.1.20] - 2026-08-05

### Fixed
- (2026-08-05) **A visitor who left while the challenge page was holding lost the solve they had already made.**  The 0.1.19 display hold ran before the pass cookie was written, so closing the tab during unmask's own pause meant a fresh challenge -- one node's abandonment jumped several times over.  The wait now happens after the cookie is written.

## [0.1.19] - 2026-08-05

### Added
- (2026-08-04) **The traffic-composition card can be read against the traffic unmask actually judged.**  Bypassed requests -- 56% of a day on one node -- sat in the denominator and halved every other share.  The card now names its denominator and offers both: all traffic, or judged only.

### Changed
- (2026-08-04) **Lowering the proof-of-work difficulty now warns that it breaks the site until nginx reloads.**  The native module verifies cookies against the rendered difficulty, so dropping it daemon-side alone loops visitors about four times before one solve happens to pass.  `render-nginx` now prints the share of solves that will be refused and the reload command.  Lower the gate first, then the daemon.

### Added
- (2026-08-04) **The challenge page's presentation is a setting.**  The visible style holds the page a configurable minimum (`min_display_ms`, default 800) with "✓ Verified"; the invisible style shows nothing until `invisible_reveal_ms` (default 1200), so a fast device sees no interstitial at all.  CAPTCHA and error screens appear immediately, and the hold is never counted into solve-time metrics.

### Fixed
- (2026-08-04) **The rate-limit funnel rollup wedged forever on the first hour containing a verdict-less event.**  A NULL `ja4_verdict` errored the scan, the cursor never advanced, and the dashboard fell back to raw-scanning an ever-growing window.  The fix un-wedges existing installs on its own.

- (2026-08-04) **On an install that challenges every visitor, hunt attributed every challenge to the operator's UA rules.**  Under the challenge-everything toggle every UA read `ua_target`; the reason now names a rule only when a pattern actually matched.

### Removed
- (2026-08-04) **`challenge_targets.all` is gone; the challenge-everything posture is the Operating-mode buckets' job.**  The invisible key duplicated the bucket actions and fed the attribution bug above.  A default install behaves identically; `known_browser_action: pass` set beside it is now honoured.

## [0.1.18] - 2026-08-04

### Fixed
- (2026-08-03) **Every visitor was held 1.5 seconds before the challenge let them through, and the wait was entirely artificial.**  A display floor meant for the test pages shipped to production because a placeholder had drifted from the constant substituted into it, and a second 800ms padded the redirect.  PoW p50 1508ms -> 389ms; abandonment on the same node 7.53% -> 2.76%.

- (2026-08-03) **Browsers without `TextEncoder` could not solve the proof of work and looped on the challenge forever.**  EdgeHTML has it on neither the window nor a worker, so the PoW worker died on its first message.  UTF-8 is encoded by hand now, and a test fails on any worker callee left behind.

- (2026-08-03) **The dashboard could report "0 human visitors" for a site that had them.**  A listed crawler fetching a bypassed path was counted in two segments, so the human remainder went negative and was floored to zero.  Bypass now wins that overlap, and an uncomputable remainder reads "—" with the reason.

- (2026-08-03) **A visitor who merely changed IP was re-challenged instead of being silently re-bound.**  The roaming rebind runs only on the plain path, and a new escalation-reason attribution filled that field in before the gate that reads it.  Caught by the end-to-end suite, not by unit tests.

### Added
- (2026-08-03) **A pattern can say that it means itself.**  Every rule field was a regular expression, so a User-Agent pasted verbatim matched nothing.  Each pattern now declares how it is read -- regex, contains, or exact -- via a chip in the field, on every pattern list.  Unmarked patterns stay regexes.

- (2026-08-03) **A UA block-list rule can pin its own action.**  The list ran one chain for every pattern in it, so a rule that needed `captcha_only` could only get there by moving every other rule with it.

- (2026-08-03) **Hunt says why a challenge fired, for the axis that fires most of them.**  A challenge raised by the operator's UA rule was recorded as "none"; it now reads `ua_target` and is filterable.  The serve event records which chain it offered, and every phase pill has a popover.

- (2026-08-03) **Requests a bypass rule let through are counted apart from people.**  A repository or API behind a bypass path used to land in the human share -- 30% of all traffic on one install.  Both deployment modes feed the same counter.

- (2026-08-03) **Acting on a hunt row no longer leaves the page.**  The UA and network buttons open a dialog like BAN beside them; the UA dialog proposes the identifying token rather than the whole string, counts what the pattern would match, and refuses one that does not match the UA it was built from.

### Changed
- (2026-08-03) **Hunt's identifier columns abbreviate until there is room, and expand when a card is folded away.**  The JA4 was clipped at 25 of its 36 characters server-side, so widening its card revealed nothing.

- (2026-08-03) **A UA pattern added from hunt is validated the way the settings form validates one.**  That path rejected nothing, and a self-identifying crawler's `(+https://…)` is not a valid regex -- nginx would have refused the whole configuration at the next reload.

## [0.1.17] - 2026-08-03

### Added
- (2026-08-02) **The dashboard says what a site's traffic is made of, in requests.**  The old "non-human traffic" figure counted distinct clients that failed a challenge, missing every crawler let through on purpose.  It now reads as three shares of one total -- bots passed on purpose, bots stopped, and the rest -- in requests, because a crawler from a few addresses and a bot spread over thousands rank in opposite order by client count.

- (2026-08-02) **Every custom rule records when it was added and when it was last edited.**  The audit log is pruned on a retention window, so older rules had nothing left to say when they arrived.  The edit date is stamped only when a confirmed edit actually changed something.

- (2026-08-02) **Hunt can drill from a network into the requests behind it.**  The ASN is resolved at render time, not stored, so the drill-down resolves the window's addresses and filters on the network.  Without an ASN database it shows nothing rather than the unfiltered log.

- (2026-08-02) **Rank cards fold away, and the choice sticks.**  Any card folds to a labelled strip and hands its width to the ones still open; the user-agent card can then switch to the raw string.

- (2026-08-02) **The managed geo databases keep themselves current.**  Country and ASN can each update monthly; a download is swapped in only after it verifies as a readable database.  Custom paths are never touched.

- (2026-08-02) **`unmask` drops to the daemon's user when run as root.**  `install-ipgeo` under sudo left root-owned databases and every country lookup stopped resolving, while doctor read them as root and reported them fine.  doctor now checks ownership too, and flags a deployed challenge asset that no longer matches the binary.

### Changed
- (2026-08-02) **The proof of work runs in a Web Worker.**  Browsers clamp a background tab's timers to one second, so a visitor who switched tabs waited roughly a minute -- fleet data showed a cluster at 41-70 seconds.  A worker needs no yielding; the UI-thread loop stays as a fallback.

- (2026-08-02) **Every path field states whether it takes a regular expression, with examples.**  Seven path settings disagreed (rate-limit zones matched literally, one list was case-sensitive); they are regular expressions now, uniformly.

- (2026-08-02) **Bot hunt ranks the networks traffic came from, not just the addresses.**  A bot renting thousands of addresses in one hosting AS never surfaces in a per-IP list.  The new "top networks" card orders by distinct IPs, shows whether an ASN rule already covers each, and links uncovered rows into the ASN tab with the number filled in.  Omitted when no ASN database is installed.

- (2026-08-02) **Bulk network lookups stopped paying for data they discard.**  Network-only lookups skip the country database and the shared cache, keeping the new ranking off the critical path and the cache bounded.

### Fixed
- (2026-08-02) **A visitor that sends no User-Agent was recorded -- and classified -- as unmask's own fetcher.**  Forward-auth reports an absent UA as an empty header, and the resolver fell back to the subrequest's own UA (LuaSocket under Apache).  On the install where this surfaced, a large share of events carried that name -- exactly the scanner population the check exists to catch.

- (2026-08-02) **Observe mode no longer reports itself as "no attacks".**  The headline counts challenges that fired, and observe mode fires none, so an install being scanned continuously showed a calm dashboard.  It now reports what would have been stopped, and says which question it is answering.

- (2026-08-02) **A confirmed settings row stopped offering controls, and stopped changing when one was touched.**  The action dropdown stayed editable on a confirmed row and opening it toggled the enabled switch; confirming also rewrote the summary as plain text.  Fixed.

- (2026-08-02) **The Apache hook fired on internal redirects and sub-requests.**  One visitor request could be judged several times, and a request the server generated for itself was judged as if it had come from outside.

- (2026-08-02) **The hunt log's user-agent column reads four cases correctly.**  A version without a trailing dot, an in-app browser named after its engine, a crawler summarised as "bot" from its URL, and a crawler that failed its address check described as challenged.

- (2026-08-02) **Redirect exemptions kept restamping their own date.**  The row posted a fixed value rather than what it held, so every save of that tab recorded the rule as added that day.

## [0.1.16] - 2026-08-01

### Added
- (2026-08-01) **The default rate limit is now three parallel axes -- per-IP, per-JA4, per-IP+JA4 -- each a row with its own threshold.**  A bot fleet rotating addresses never accumulates per-IP but tends to share a TLS fingerprint, so a per-JA4 counter keeps counting.  The JA4 row ships off (one fingerprint covers every user of one browser build); enabling it adopts 600 r/min and a challenge action.  The finer key must carry the lower threshold, or the coarser counter always trips first.  Existing config files load unchanged.

- (2026-08-01) **Named zones can count against their own key.**  A path-scoped zone now takes ip / ja4 / ip+ja4 in a new column (empty = follow the default), so `/api/` can throttle per fingerprint while everything else stays per-address.  The zone table's help carries the same crowd-key caveat as the default card.

- (2026-08-01) **The admin login and password-reset forms throttle per address -- in the application, where it actually fires.**  The nginx rate-limit preset never counted a request, because anyone holding a pass cookie is exempt from challenge-mode zones.  Repeated failed logins now answer 429 with Retry-After, and password-reset requests get their own budget, on both deploy modes.

### Changed
- (2026-08-01) **Every value list in the settings renders as confirmed rows, with a per-row off switch, a note, and reorder arrows.**  The admin allowlist, admin hostnames, metrics allowlist, defined sites and trusted-LB list were permanently editable inputs on forms that save whole -- and a mistyped allowlist locks you out.  A switched-off row is absent from every consumer; the self-lockout guard judges the enabled subset.

- (2026-08-01) **The hunt log's user-agent column tells apps, browsers and bot kinds apart at a glance.**  Browser and platform marks, in-app requests named after the app rather than its engine, and bot claims split into two badges: a listed crawler (amber, vendor known) versus a self-declared bot (grey, nothing to check against).  The pager caption counts sessions on screen.

- (2026-08-01) **Settings tabs, smaller strokes.**  Public test pages default to on with the site picker wired; the performance tab gains named profiles and shows what "auto" resolves to on this machine; the geo tab shows country names; the PoW cookie-lifetime hint renders on load.

### Fixed
- (2026-08-01) **Rate-limit zones enforce identically on both wires.**  Path patterns were a case-insensitive regex on nginx but literal bytes on forward-auth; a zone with no patterns was declared but never applied natively; overlapping zones counted first-match-only on forward-auth while nginx stacks them.  All three now agree, and a deny trip outranks a challenge trip.

- (2026-08-01) **Hunt paging, round two.**  The boundary margin was sized to how many rows a session has, not how far they spread among concurrent traffic, so sessions kept arriving decapitated; it now covers the measured spread.  The 1000-rows option works (limits clamp instead of resetting), and the fragment marker names all three causes, including the serve landing on another node behind a load balancer.

- (2026-08-01) **Saving a geo or ASN row no longer wipes the pills out of its confirmed view.**  Confirming an edit rewrote the whole cell as plain text, which destroyed the country name and both action pills until the next full page load.  The confirm now rewrites only the value.

## [0.1.15] - 2026-08-01

### Added
- (2026-07-31) **Crawlers that publish their egress ranges are verified by address rather than by name -- as standing policy, on by default.**  The per-row opt-in could be pinned months earlier and quietly keep a vendor UA passing on the string alone.  While the new UA-filter switch is on, every range-backed bot with live presets is judged by address alone; a bot whose preset is disabled keeps its UA rescue rather than losing every path.  Switching it off restores the per-row choices.

- (2026-07-31) **Each row of the three network allowlists can carry a note.**  Six months on, nobody remembers which office VPN `203.0.113.7` let in, and the safe-looking cleanup is how an operator locks themselves out.  Purely for memory; nothing matches on it.

- (2026-07-30) **A collapsed challenge session shows how long the whole exchange took.**  The popover carries first event to last, so "cleared PoW in 1.4s" is read directly.

- (2026-07-30) **Apple push-notification previews pass out of the box -- behind a TLS-fingerprint guard.**  Subscribers' own devices fetch the article to build the rich preview, from residential IPs with no vendor ranges to verify.  The `notification-preview` preset rescues the UA only when the request's JA4 carries Apple's cipher-suite hash (JA4_b, stable across CFNetwork builds), so a spoofer must mimic Apple's TLS stack rather than copy a string.

### Changed
- (2026-07-30) **The hunt log shows each user agent as "platform · browser version" instead of the raw string's first few inches.**  `Windows 10 · Chrome 126`, `iOS 26.5 · Safari`; the full string is in the popover, and a UA that does not parse as a browser keeps its raw form.

- (2026-07-30) **A refused roaming rebind appears inside the session it interrupts instead of as a stray row.**  `bv_rebind_reject` rows carried no session token; the hunt now folds the refusal into the session that follows, so one line tells the story.

- (2026-07-30) **The site-scoped challenge preview moved from `/unmask/challenge/<site>/` to `/unmask/test/site/<site>/`.**  The old address put an operator test surface in the production namespace and forced dotted host ids into that path's grammar -- the cause of 0.1.13's PoW loop.  `/unmask/challenge/` now has exactly one shape.  The old URL is gone, not redirected; every link to it is generated by unmask's own UI.

### Fixed
- (2026-07-31) **Paging through the hunt log is no longer corrupted by the log's own growth.**  Sessions straddling a page boundary arrived cut in half, and "next" repeated rows that new events had pushed down.  Each page reads past both edges and assigns every session to one page; page 1 pins the newest event id so paging walks the log as it stood.

- (2026-07-31) **Looking up a support ref no longer reads the whole event table.**  A `LIKE` over the JSON payload took 53 seconds on 3.4M rows, on the path an operator walks while a blocked visitor waits.  Migration 0025 adds an indexed `ref_id`: 9ms.  Not backfilled; the gap closes within days on the retention window.

- (2026-07-30) **Per-site checkboxes show the value that is actually in effect.**  "off here" and "inherit" were confused both ways, so unchecking a flag came back ticked and saving an untouched form silently pinned it off.  Checkboxes now render the resolved value, and an untouched form stores nothing.

- (2026-07-30) **A per-site logo appears in the theme previews, not just the thumbnail beside the upload field.**  The preview iframes resolved branding by the admin's own Host, so they showed the wrong site's identity and no logo, which read as "the save did not take".  Per-site previews now load the site-scoped route.

## [0.1.14] - 2026-07-30

### Changed
- (2026-07-29) **SQLite memory is budgeted for the whole daemon instead of per connection, so unmask fits on a 1GB VPS.**  `cache_size` and `mmap_size` are per-connection and the pool opens up to 8, so "128MB + 256MB" was really 8x each -- 3.7GB RSS peak on a synthetic 2.2GB database.  Both are now derived from the memory the process may use (cgroup, `/proc/meminfo`, then `sysinfo`) and split across a pool sized to the CPUs: 447MB peak for 16% more wall-clock.

### Added
- (2026-07-29) **A Performance tab, so the resource dials are visible and adjustable.**  Shows the detected memory limit and CPU count, what is in effect, and what each preset -- Conservative / Standard / Generous / Custom -- would use on this host.  A resource dial, not a speed dial: a larger cache does not reduce the rows an index walk reads.  Write-batching settings moved here from Log management.

### Fixed
- (2026-07-29) **The header-integrity axis no longer charges genuine pre-2021 browsers for a header they never had.**  `Sec-CH-UA` shipped in Chromium 89, so every older browser was flagged permanently -- and the behavioural CAPTCHA is hardest on exactly the old handsets this caught.  The axis now stays silent below Chromium 89 on both deploy modes.

## [0.1.13] - 2026-07-29

### Changed
- (2026-07-28) **A per-site setting no longer freezes everything else about that site.**  Setting one knob used to seed the site with a complete copy of the global record, so later global changes never reached it.  A site record now holds only what you set; unset fields are marked on the form, and turning a flag off for one site is expressible.

- (2026-07-28) **The challenge page's theme, colours and credit line moved to the design settings, where the logo already lived.**  They sat in the challenge-behaviour record, so choosing a theme pinned a site's PoW and cookie settings to a snapshot.  Existing config files are moved across on load; a record that had already drifted is kept as-is.

- (2026-07-28) **The header-integrity axis is on by default, and it outranks the stale-browser tier.**  A Chrome / Edge / Opera UA with no `Sec-CH-UA` over HTTPS contradicts itself, and what that catches is almost purely non-human.  Clamped to a challenge, never a hard block; `header_integrity: false` turns it off.  Both deploy modes now report a simultaneous trip as `header`.

### Added
- (2026-07-29) **The audit log records where each admin action came from.**  Behind a load balancer the operator's real address was written down nowhere, which blocked setting an admin IP allowlist and answering "which of these logins was not us".  Every audited action, failed logins included, now carries the client IP.

- (2026-07-28) **You can delete a site's settings, not just switch them off.**  Nothing in the UI removed the record, so a site configured once kept an entry forever.  Both the design and challenge tabs offer a delete when something is stored.

- (2026-07-28) **The cookie-reuse ranking covers PoW cookies, not just CAPTCHA ones.**  A client riding one proof-of-work solve fired no events and was invisible everywhere -- precisely the shape of a scraper that found the cheap door.  The PoW ranking carries a JA4 count: shared egress shows many fingerprints, one client riding one solve shows exactly one.  PoW rows are kept 8 days.

- (2026-07-28) **An abandoned challenge says whether the visitor went back or left for good.**  Browsers refuse to say which gesture ended a page, but the server can tell: each departure row reports whether the same client sent anything within 30 seconds, shown as **stayed** or **gone**.

- (2026-07-28) **The abandonment report separates when the visitor left from when unmask noticed.**  A handler delayed by the PoW holding the main thread recorded a mid-solve departure as "left right after passing".  The beacon now carries the browser's own event time (`left_at_ms`) and the delay.

- (2026-07-28) **You can see visitors who gave up on the challenge instead of failing it.**  A visitor who closed the tab mid-challenge left no trace, indistinguishable from a bot that never ran the JavaScript.  The page now reports an `abandon` phase with the step and the wait, via `pagehide` + `visibilitychange`; a successful pass suppresses it.  Grey in the hunt log, with a filter.

- (2026-07-28) **Link-preview bots that are ordinary in Japan pass out of the box.**  The upstream crawler list carries Slack / Twitter / Discord unfurlers but not Chatwork, so links pasted into chat rendered bare.  unmask ships a supplement (Chatwork LinkPreview, WebexTeams, NotionEmbedder), switchable per pattern like any other.

### Fixed
- (2026-07-28) **`unmask doctor` reported nginx config as out of date when it was not.**  The freshness check re-rendered without the hub-pulled crawler ranges, so every node that had ever pulled them was told it was stale.  It now renders the same way, and a genuine difference names the line on each side.

- (2026-07-28) **Previewing a site from the test page looped on the PoW forever.**  The post-pass redirect's site-segment pattern disallowed dots while the router accepted them, so `/unmask/challenge/shop.example.jp/` reloaded itself: solve, challenge, solve.  The two patterns now agree.

- (2026-07-28) **A per-site logo could be saved correctly and still look like it had failed.**  The thumbnail was fetched from the host-resolved route, so editing site A on host B got a 404.  It now uses the site-scoped route.

- (2026-07-28) **The scope picker did not show the host you had just added.**  The scope being edited is now always in the list, normalized the same way the save handler normalizes it.

- (2026-07-28) **A per-site save whose override toggle was off reported success while discarding the form.**  When the disabling script had not run, the values -- logo upload included -- were thrown away behind a "saved" banner.  That save now stops and says what to do.

## [0.1.12] - 2026-07-28

### Fixed
- (2026-07-27) **The header-integrity axis works behind a TLS-terminating load balancer.**  It required HTTPS on HTTP/2·3 as seen by nginx itself, and an LB re-originates the backend hop as plain HTTP/1.1 -- so on LB-fronted deployments it never fired, silently (5000/5000 backend requests HTTP/1.1).  With a trusted LB configured it now keys off `X-Forwarded-Proto`; within minutes it was catching spoofed-Chromium scrapers.

### Added
- (2026-07-27) The overview's challenge-serves / PoW-pass / CAPTCHA-pass KPI tiles now carry the same colours as the "all requests" chart's buckets (a legend dot in the label, a darker matching tone on the number), so the tiles read as that chart's buckets at a glance and the overview, dashboard and stats views speak one colour language.

- (2026-07-27) **The stale-library warning fires only when the running code actually differs from what is on disk.**  Reinstalling the same build leaves an unlinked mapping whose bytes are current; four of seven fleet hosts were that.  Each candidate is now compared against the current file.

- (2026-07-27) **unmask warns when a reload cannot apply what you changed, because nginx is still running on replaced libraries.**  `nginx -s reload` does not re-exec the master, so after a library upgrade fresh workers are forked from a broken image and can die with SIGSEGV.  `doctor` and `render-nginx` now read the master's memory map, name the replaced files, and point at `systemctl restart nginx`.

- (2026-07-27) The escalation axis is now visible *per row*, not only as totals: the CAPTCHA pass report's recent-passers list shows each pass's force reason, and the CAPTCHA-failure IP ranking lists the distinct axes behind each IP's failures.  Both cards read as aggregate pills on top plus the axis on every row.

- (2026-07-27) The CAPTCHA pass report and the CAPTCHA-failure IP ranking gain a by-axis breakdown (which escalation reason the solved / failed CAPTCHAs came from).  Read together they show each axis's CAPTCHA effectiveness: a bot-facing axis should pile up failures; a pile of *passes* on one axis means a solver is walking through it.

- (2026-07-27) The bot-hunt raw log shows each event's escalation reason in its own column next to phase (violet badge; the axis is an attribute of the visit, not a phase) and can filter by it — so "show me everything the header-integrity axis escalated" is one click.

- (2026-07-27) The challenge funnel gains `header` / `asn` / `geo` pseudo-rows (alongside the existing `rate_limit` one), so you can see the *pass rate* of a header-integrity / ASN / country challenge — i.e. that axis's false-positive rate — not just its count. The challenge page now carries the force reason through every phase beacon, so the whole serve→load→pass chain is attributed to the axis that raised it.

- (2026-07-27) The "Forced CAPTCHA (reason breakdown)" dashboard card now attributes challenges raised by the header-integrity axis (`header`) and by the ASN / country filters (`asn` / `geo`) instead of folding them into the generic `none` bucket — so an operator can see those axes actually firing. A rate overage still shows as `rate_limit`; the new buckets are the *direct* (non-rate) challenges.

- (2026-07-27) The header-integrity axis (Sec-CH-UA absence) can now escalate to `pow_then_captcha`, not only `pow_only` / `captcha_only` — a stronger, still-clearable challenge chain for operators who want it. `deny` stays unavailable for this axis (a stripped header is a legitimate state).

### Changed
- (2026-07-27) The challenge funnel's per-row rate is now a **pass rate over everyone served** (`bv_total / serve`, replacing the old PoW-only rate): of everyone an axis sent to a challenge, how many ultimately came out with a pass cookie.  The denominator includes clients whose JS never ran — mostly bots — so the number reads low on bot-facing rows and high on human-facing ones, which is exactly its job: a proxy for that axis's false-positive rate.  The CAPTCHA rate stays `captcha_passed / captcha` (solver detection, an orthogonal question).

## [0.1.11] - 2026-07-27

### Added
- (2026-07-27) **Verify a claimed crawler by reverse DNS, not just its User-Agent.**  Googlebot / Bingbot / YandexBot / Applebot / Baiduspider claims can be confirmed by PTR -> vendor domain -> forward-confirm.  Asynchronous (no request latency), skipped when a range preset already covers the crawler, toggleable per crawler on the Bypass-IPs tab.

- (2026-07-27) **Throttle a network or country instead of blocking it.**  ASN and country rules gain a per-minute rate; the rule's action applies only to the overage.  Native renders one `limit_req` zone per throttled entry with verified crawlers exempt; forward-auth counts live.

- (2026-07-27) **Exempt a path from the country or ASN decision only.**  RSS/Atom feeds are pulled from datacenters a country or ASN policy would sweep up.  A per-axis exempt path drops just that axis while every other check keeps running.

- (2026-07-27) **Challenge a Chromium browser that is missing its client-hint header (opt-in).**  A UA claiming Chrome / Edge / Opera that carries no `Sec-CH-UA` over HTTPS on HTTP/2·3 is flagged -- a real Chromium always sends it there.  Never touches plain HTTP, HTTP/1.1, Firefox / Safari; clamped to a challenge.  Off by default.

### Changed
- (2026-07-27) **The stale-browser tier's lag is set per browser.**  Chrome and Firefox thresholds are now independent, each defaulting to the built-in value.

- (2026-07-25) **Block or challenge traffic by network (ASN), not just by country.**  Challenge or deny AS16509 (Amazon), AS14061 (DigitalOcean) or a bulletproof host while the residential ISPs of the same country pass.  Same actions as the country axis, both modes, evaluated after the bypass-IP check so Googlebot / GPTBot are never caught.  Requires an ASN mmdb.

### Fixed
- (2026-07-25) **Hover popovers no longer vanish mid-hover and go dead until you leave and re-enter.**  The watchdog derived the trigger by hit-testing the entry point, so moving off a child inside the cell dismissed the popover.  Every hover popover now names its real trigger element (21 call sites).

### Added
- (2026-07-25) **`unmask doctor` warns when config.yml has been hand-edited without re-rendering.**  A direct edit does nothing until `render-nginx` and a reload (a factor in the 2026-07-21 incident).  doctor compares the loaded conf against a fresh render, ignoring the per-render stamps.

## [0.1.10] — 2026-07-25

### Changed
- (2026-07-25) **Both deploy modes share one daemon upstream, `upstream unmask_daemon`, in upstream.conf; the down hook is `@unmask_daemon_down`.**  Native said `upstream unmask`, forward-auth kept the legacy `unmask_admin`.  No aliases are kept.  **Forward-auth upgrade note:** an edited `server.inc` or a custom `@unmask_admin_down` override must move to the new names; `nginx -t` points at leftovers.

- (2026-07-25) **FHS cleanup: the nginx module survives an immutable /usr, the Apache Lua payload moved out of /etc, the vts example to /usr/share/doc.**  On a read-only /usr the placer falls back to `/var/lib/unmask/plugin/` instead of failing silently.  `/etc/httpd/unmask.lua` is now a symlink to `/usr/share/unmask/snippets/`; documented paths keep working.

- (2026-07-25) **SQLite page cache raised from 20MB to 128MB.**  Production event databases run multi-GB, where a 20MB cache thrashed on every cold hunt / stats scan; 128MB is still modest next to the existing 256MB mmap window and the OS reclaims it under memory pressure.

### Fixed
- (2026-07-25) **Saving settings from the web UI no longer deletes config sections owned by other programs.**  `feed_server` and any unrecognized top-level key were silently dropped by the next save.  They are now carried over verbatim under a "not managed by unmask" banner.

- (2026-07-25) **The forward-auth decision endpoint no longer rebuilds its bypass matchers on every request.**  The cache key was the address of a per-call copy that never matched, so every `/api/check` re-assembled ~100 matchers under a lock.  It now keys on the settings snapshot.

- (2026-07-24) **The test-page site picker no longer serves a challenge that can't be passed, and shows the previewed site's logo.**  The preview embedded the site's PoW difficulty but the host verified it, so a differing site looped forever; the difficulty now stays the host's.  A site-scoped `/branding/<site>/logo` route serves the logo.

## [0.1.9] — 2026-07-24

### Added
- (2026-07-23) **The test pages can exercise a specific site's challenge end-to-end.**  The admin test page gains a Site picker that serves the force-PoW / force-CAPTCHA pages via the site-scoped route, while the pass cookie stays bound to the host you are on.  An opt-in shows the picker on the public test pages too (off by default: it reveals which sites have custom settings).

- (2026-07-23) **The admin tells you when the daemon cannot write its own database.**  Challenges keep serving on a read-only DB while stats and events record nothing -- the classic cause is a root-owned `unmask.sqlite` from `unmask migrate` as root.  The retention tab runs a live write probe from inside the daemon, and `doctor` gains the matching check.

### Fixed
- (2026-07-23) **The setup-wizard token moved from /etc/unmask to /var/lib/unmask.**  Transient state, not configuration.  The old path is still read as a fallback so a mid-setup upgrade finishes unchanged.

- (2026-07-23) **Per-site challenge logos actually work, and uploaded logos moved out of /etc.**  Every upload was written to the same file, so a site's logo silently replaced the Default's.  Each record now gets its own file under `/var/lib/unmask/branding/`; existing configs keep working.

## [0.1.8] — 2026-07-22

### Added
- (2026-07-22) **The UA-filter checkbox and the Bypass-IP range presets are independent axes, and the UA-filter tab shows each range-backed crawler's true rescue path.**  One tab's state used to change the other's behaviour invisibly.  Now the UA checkbox means "pass by UA string" and the range presets mean "pass by vendor IP"; a live 4-state badge (IP-verified / UA+IP / UA only / no rescue) shows the effect before saving.  No install's behaviour changes until an operator saves the tab.

- (2026-07-22) **The AI-crawler drill-down shows that a range-verified crawler's "served" count is spoofed traffic.**  Genuine Googlebot is rescued by range before it can be challenged, so what remains under its UA is forgeries.  Such rows carry a 🛡 badge and the column is renamed "challenge".  Display-only.

- (2026-07-21) **The stale-browser tier's current-major baselines auto-follow an unmask.sh feed.**  unmask.sh aggregates the vendors' version feeds daily into one document; each install subscribes and resolves operator-pinned first, else the newer of hub and built-in -- a hub outage can never drag a baseline below what the binary shipped with.  The tab's fields are now explicit automatic / manual.

- (2026-07-22) **Bot-hunt rankings filter the raw log in one click, gain a User-Agent search, and hide once a filter is active.**  Each IP / JA4 / UA row folds a 🔍 into its count; a UA substring box pulls every request carrying a spoofed crawler string.  Rankings hide under a value filter because they are window-wide and would quietly disagree with it.

- (2026-07-21) **The stale-browser tier covers Firefox too.**  Same lag over Firefox's built-in baseline; the current Firefox ESR major is always exempt (it legitimately trails by up to ~15 majors).  Safari stays out of scope: its numbering jumped and is pinned to the OS.

### Fixed
- (2026-07-22) **A protected path's mode actually picks the challenge screen it serves.**  The mode was rendered into the nginx map but never drove the page, and forward-auth passed no mode at all.  Both now follow it.  Admin HTML also gains `Cache-Control: no-store`, so a redeployed dashboard appears on the next load instead of after a hard reload.

- (2026-07-21) **Saving a settings tab no longer silently rewrites settings you did not touch.**  A browser-faithful no-op save on every tab flushed out a family of bugs: the geo tab's save had never worked (400), the ua-filter save forced `challenge_targets.all` off, and every default-action dropdown persisted its display fallback -- which pinned `pow_then_captcha` across the fleet.  Dropdowns now offer an explicit "(unset)" that round-trips, and blank number fields follow the default.

- (2026-07-21) **The UA black-list's default action no longer leaks onto every challenge.**  It applied to every challenge the native page served, so saving anything on the ua-filter tab walked current Chrome into the CAPTCHA leg meant for black-listed UAs.  It now fires only on an actual challenge-target match; forward-auth honours the same setting.

## [0.1.7] — 2026-07-21

> **Upgrade note**: crawler UA patterns whose vendors publish official IP ranges (Google, Bing, DuckDuckGo, OpenAI, Perplexity, Apple, Amazon) are **no longer rescued by their User-Agent string alone** once the matching IP-range presets are enabled.  Genuine crawlers keep passing — their published ranges are folded into the bypass-IP allowlist (on by default) — but a spoofed Googlebot from outside Google's ranges now gets the challenge.  For installs upgrading from 0.1.6 or earlier this applies immediately to the vendors whose presets shipped in 0.1 (Google, Bing, DuckDuckBot, OpenAI, PerplexityBot); the four presets added in this release (Applebot, Amazonbot, DuckAssistBot, Perplexity-User) stay off until reviewed in settings (NEW badge).  To restore the old UA-only behavior for a vendor, disable its IP-range preset on the Bypass IPs tab — that vendor then falls back to UA-only rescue, exactly as before.

### Changed
- (2026-07-21) **The admin dashboard is dramatically faster on large multi-site installs.**  The 30-day charts scanned the full per-site per-minute history on every load; they now read hourly install-wide rollups a background pass maintains.  A stats page that took six to eight seconds returns in about two.

- (2026-07-20) **The stats page's rate-limit card** now lists the top 30 source IPs and the top 30 hit paths (each with its query-string breakdown), collapsed to 10 rows apiece behind a show-more expander so the common case stays compact.

- (2026-07-16) **Security: a spoofed crawler User-Agent no longer walks through the challenge.**  During the 2026-07-15 incident a 94k-IP botnet crawled with a fake `Googlebot` UA and was waved through on the string alone.  For range-publishing vendors the UA patterns are dropped from the rescue and the official IP ranges carry it; if a vendor's preset is disabled it reverts to UA-only rescue, never to "no rescue".

- (2026-07-16) `PresetIsNew` / `VersionLess` now compare the patch segment, so presets added by a patch-step release (v0.1.6 → v0.1.7) correctly show the NEW badge and stay off until reviewed; previously only major.minor were compared and a patch-added preset silently skipped the review gate.  Preset `AddedIn` values are now written in full `vMAJOR.MINOR.PATCH` form (a present segment must be numeric — no lenient fallback), and the settings UI's "since" labels show the same 0.0.1-granularity version.

### Added
- (2026-07-19) **A browser pinned to an outdated Chrome version can be escalated to a CAPTCHA (off by default).**  A scraper across thousands of residential IPs solved the PoW headlessly; its one tell was a frozen `Chrome/139` against stable 150.  The stale-browser tier escalates a Chromium-family major at least N behind current stable (`stale_browser_lag`, default 10).  Firefox / Safari untouched; bypass IPs and crawlers keep their rescue.

- (2026-07-19) **Stats-exclude IPs can carry a title, like the bypass list.**  Monitoring probes and fleet addresses become unidentifiable months later.  Titles are stored in a parallel array; existing configs load unchanged.

- (2026-07-16) **Four new official IP-range presets**: Apple (Applebot), Amazon (Amazonbot), DuckDuckGo (DuckAssistBot) and Perplexity (Perplexity-User).  On by default for fresh installs; existing installs enable them from the NEW-badged rows.

- (2026-07-16) `unmask doctor` now checks crawler IP-range freshness: when UA rescue is riding the vendor ranges, it warns if the synced range files are missing (never synced from the hub) or older than 30 days — a stale snapshot can eventually challenge genuine crawlers arriving from newly added vendor IPs.

### Fixed
- (2026-07-20) **The Community Bans tab no longer hangs on first load.**  The 30-day impact figure walks every serve row through the ban matcher; it now computes in the background behind a spinner.

- (2026-07-20) **The retention tab no longer times out on a multi-gigabyte database.**  The stored-event count is an O(1) id-range estimate ("≈"), and a figure that cannot be read shows "??" rather than a misleading zero.

## [0.1.6] — 2026-07-15

> **Upgrade note**: this release fixes a critical connection leak in the nginx module's compose flow (0.1.5, nginx 1.17.6+).  After upgrading, **restart nginx** (`systemctl restart nginx`) — a plain reload does not load the replaced module, and any connections already orphaned by 0.1.5 are only released by a restart.

### Fixed
- (2026-07-15) **Compose mode leaked every challenged connection, exhausting nginx's fd budget and taking the node down within hours.**  The ACCESS-phase handler returned `NGX_DONE` from an internal redirect without finalizing, so each challenged connection was orphaned holding its fd until `worker_connections` ran out and every port timed out.  All three native production nodes went down within ~2 hours.  The redirect is now paired with `ngx_http_finalize_request(r, NGX_DONE)`.

## [0.1.5] — 2026-07-14

> **Upgrade note**: this release updates the nginx module (`ngx_http_unmask_module.so`) for the first time since 0.1.2.  After upgrading the packages, **restart nginx** (`systemctl restart nginx`) — a plain reload does not load the replaced module and can leave nginx running a config/module mix.  On nginx 1.17.6+ the rendered config also switches from the classic to the compose rate-limit flow automatically at the next render; no configuration change is needed, and older nginx keeps the classic flow.

### Fixed
- (2026-07-14) **Security: on AlmaLinux / RHEL 8 the nginx plugin read the wrong request fields, and on a compose-mode host protected locations let every bot through.**  Those distributions patch `ngx_http_headers_in_t`, shifting every later struct member by eight bytes with no signature change.  `r->main` read as NULL, so protected locations served bots straight through and solved cookies were never found.  The plugin now reaches request state only through nginx's own entry points.

- (2026-07-14) **On a SELinux-enforcing host without `semanage`, native mode silently recorded zero events; and every daemon restart rewrote inherited honeypot bans as hard `deny`.**  The postinstall's SELinux block was gated on `semanage`, absent on minimal RHEL 8; it now falls back to `chcon` plus a boot drop-in.  Separately, the per-source action resolver was registered after the first ban-file flush, so on every restart challengeable bans became 403s.  Seeded before `Start()` now.

- (2026-07-14) **A honeypot probe on the plaintext port no longer earns a whole-IP auto-ban.**  With `https_redirect` on, a `:80` trap hit produced a fingerprint-less log line and an `ip_only` ban broader than the precise one its HTTPS visit earns.  Redirect-only lines are left to the HTTPS path.

- (2026-07-10) **The admin no longer redirect-loops when the CSRF cookie expires before the session (~30 days after login).**  The backfill 303-redirected to the same URL, and Chrome withholds `SameSite=Strict` cookies across a cross-site redirect chain, so the loop never terminated.  The cookie is issued and the page rendered directly; the CSRF cookie becomes `SameSite=Lax`.  Workaround until deployed: open `/unmask/admin/login` and log in again.

- (2026-07-09) **The stats and bot-hunt pages no longer get slower as events accumulate.**  SQLite ships no planner statistics until `ANALYZE` runs, so range queries scanned whole indexes.  New `unmask db-analyze` builds them (`migrate` does so on a small DB; `doctor` warns when missing).  Bot-hunt IP ranking 1.5s -> 5ms.  MariaDB unaffected.

- (2026-07-09) **The nginx module no longer floods `error.log` with "uninitialized unmask_compose variable" warnings.**  The variable is registered with a default handler resolving to "off".

- (2026-07-08) **Forward-auth mode bypasses the challenge for stats-exclude IPs, matching native -- without making them unbannable.**  A monitoring probe was challenged on the forward-auth node but passed natively.  The ban allowlist stays narrower: stats-exclusion is a dashboard filter, not a ban-policy grant.

### Added
- (2026-07-14) **The dashboard shows what the Community Bans feed actually stopped.**  A new card reports the traffic hub-derived bans blocked over 30 days, from a cached background pass.

### Changed
- (2026-07-14) **The bot-hunt log lets you pick how many rows to show**, and the challenge page's "protected by unmask" credit now sends Japanese visitors to the Japanese landing page instead of the English one.

- (2026-07-10) **The stats page's data-source badge explains itself, and compose mode is gated on nginx 1.17.6+.**  "from access log" with a popover per mode.  Compose needs `limit_req_dry_run` and `limit_req_status` (1.17.6), and a deny zone on older nginx used to emit a directive that fails `nginx -t`.  The daemon now probes `nginx -v`; `nginx.rate_compose_mode` (`auto` / `always` / `never`) overrides.

- (2026-07-08) **`unmask events` prints a `reason=` column** (`rate_limit` / `ja4_bot` / `honeypot` / `banned` / `protected` / `test` / `none`), so a rate-limit block is distinguishable from a baseline challenge at the CLI.  `force_reason` is now populated consistently across the SSE, paged and `--ref` endpoints.

## [0.1.4] — 2026-07-08

### Added
- (2026-07-05) **Stats-exclude "private networks" preset.**  Drops RFC1918 / loopback / link-local from statistics in one click.  Off by default on purpose: stats-exclude also bypasses the challenge, so an intranet site would lose protection.

- (2026-07-04) **`unmask doctor` probes :80 as a load-balancer health checker and warns on a redirect.**  A 301 to a health check is a failed check, so the LB drops the node.  Fires only when the health-check exemption was turned off.

### Changed
- (2026-07-05) **Custom IP / host list fields are structured rows, not newline textareas.**  Admin-IP, admin-host, metrics, stats-exclude and defined-sites lists become add/delete rows.

- (2026-07-04) **Network-tab wording fixes.**  The IP-geo "not loaded" hint pointed at the wrong side ("the button on the right" -> "on the left"; the download button is to its left), and the trusted-LB custom-row placeholders now localize (the technical tokens CIDR / X-Client-JA4 stay as-is).

- (2026-07-04) **The last row of a custom rule list can be deleted.**  An empty list is a legitimate state; the Add button starts a new one.

- (2026-07-04) **The HTTPS-redirect exemptions now use the same preset / custom two-badge layout as the trusted-LB section**, and the trusted-LB custom list no longer opens with a blank row by default (click Add to insert one).

### Fixed
- (2026-07-05) **The "already BANned" pill was clipped in the hunt table.**  The 4rem actions column was too narrow for the ~6rem pill; widened, and the label moved to i18n.

## [0.1.3] — 2026-07-04

### Fixed
- (2026-07-04) **The theme-tab preview showed the actual site instead of the challenge for operators who had already passed it.**  The roaming-rebind guard did not exclude `_preview`, so a valid `_bvj` cookie navigated the iframe to the site.

- (2026-07-04) **The over-block banner showed a literal `&mdash;` entity.**  The banner renders through the escaping template pipeline (unlike the safeHTML popovers), so the HTML entity was shown verbatim; use the literal em dash.

### Added
- (2026-07-04) **Configurable HTTPS-redirect exemptions (`nginx.https_redirect_exempt`).**  Two presets ship on: ACME HTTP-01 (by path) and load-balancer health checks (by user-agent: `GoogleHC` / `ELB-HealthChecker` / `kube-probe` / Azure).  An un-exempted 301 is a failed health check that drops the node -- how `https_redirect` on a GCP-fronted node stopped recording.

- (2026-07-04) **A preview-language selector on the theme settings tab.**  All 18 shipped locales; honoured only in a preview context, so a real visitor's detection is unchanged.

- (2026-07-04) **`unmask doctor` warns when `nginx.https_redirect` is enabled but the rendered `server.inc` has no 301 block** (the setting was turned on without re-rendering) — the same stale-render class as the existing bv_secret check.

## [0.1.2] — 2026-07-03

### Added
- (2026-07-03) **HTTP -> HTTPS redirect option (`nginx.https_redirect`, off by default).**  Emitted before the ban / honeypot / challenge gates, since a no-TLS request carries no JA4.  Keys off `X-Forwarded-Proto` behind an LB; exempts ACME HTTP-01.

- (2026-07-03) **Bypass-path presets declare per-preset factory defaults.**  Machine-access presets (ACME, robots.txt, health checks) default on; anything that could be a protection target stays off.  The config stores only deviations.

- (2026-07-03) **A guard test for undefined `$unmask_*` template variables.**  nginx expands an undefined variable to the empty string without erroring, so a map removed while its uses remain silently no-ops the feature that referenced it — `nginx -t` and the render tests both stay green.  The new test cross-checks every referenced variable against the template and C-module definitions.

### Fixed
- (2026-07-03) **The access-log parser dropped `hpuri` and `ua` on TLS-resumption lines.**  `$effective_ja4` renders as `-` with no fingerprint, and the parser's charset refused it, un-anchoring every later field.  The placeholder is now accepted.

- (2026-07-03) **The events table stacked a native tooltip on top of the datetime popover.**  The shared datetime formatter sets a local/UTC `title` on every cell; the popover shows the same detail, so the title is stripped on cells that carry it.  The popover also gains Host / Port rows.

- (2026-07-03) **The sites tab implied DEFINED acceptance mode limits recording.**  Reworded: events are recorded for every Host in either mode — the mode only affects display (picker suggestions and ghost detection).

## [0.1.1] — 2026-07-02

### Fixed
- (2026-07-02) **A reinstall could leave the daemon running the old, deleted binary, causing an admin redirect loop.**  The postinstall now ends every init path with a final-guarantee restart, so upgrade / reinstall / remove-install always converges on the new binary.

- (2026-07-02) **`protect.inc` included at server scope self-DoS'd the site.**  The gate's rewrite also caught the `/unmask/` machinery, so the challenge could never complete and every human looped while bots still got 403.  `protect.inc` now exempts the machinery, and `doctor` warns on a server-scope include.

- (2026-07-02) **The plugin postinstall printed `unrecognized libcrypto` on nginx built against a statically-linked OpenSSL.**  Detection now falls back to `nginx -V` and then to the newest system libcrypto.

### Added
- (2026-06-28) **Apache forward-auth captures and LB-gates a forwarded JA4, at parity with nginx.**  Nothing verified that a forwarded `X-Client-JA4` came via a trusted LB, so a direct client could forge one.  The Lua hook forwards the raw TCP peer, and the daemon honours the JA4 only when that peer is a configured trusted LB.  The never-implemented `ja4_source` / `trusted_forward_auth_proxies` keys are removed.

- (2026-06-27) **The native plugin emits a `q`-prefix JA4 for HTTP/3 (QUIC) requests.**  Labelling a QUIC ClientHello `t…` mis-fingerprinted every HTTP/3 visitor.  Guarded to nginx >= 1.25 with QUIC.

- (2026-06-26) **Privacy Pass / Apple Private Access Token verification: an attested client can skip the challenge.**  unmask acts as an origin (verifier only) for token type `0x0002` (Blind RSA, RFC 9577/9578).  Pure Go, opt-in, and behind the Advanced switch, so inert until enabled.

- (2026-06-22) **`trust_forwarded_ja4` is a network-tab checkbox for forward-auth mode.**  A trusted loopback peer does not make a client-sent value trustworthy, so honouring it is its own opt-in; it was config-only.

- (2026-06-20) **Custom `[from,to]` date range on the stats dashboard and the hunt page.**  These views were fixed windows, so a past incident could not be scoped to its day.

- (2026-06-19) **Two CAPTCHA watchlist cards: a pass report and a cookie-reuse ranking.**  Investigative signals, not verdicts -- passing a CAPTCHA is not proof of a bot.

- (2026-06-19) **Roaming-rebind refusals are visible in the hunt log.**  A refused silent `_bv` rebind left no trace; every refusal is now a `bv_rebind_reject` event with its reason.  This surfaced the HTTP/2 <-> HTTP/3 false positive fixed below.

- (2026-06-19) **Unix-socket admin bind is fully operator-usable.**  `socket_group` auto-detects the web server's group instead of hard-coding `nginx`; `socket_mode` supports `0660` / `0666`; `admin_allowed_ips` works over a socket via the forwarded `X-Real-IP`.

- (2026-06-18) **A support "Ref ID" on every challenge / deny / ban page, with a reverse lookup.**  A blocked visitor can quote a short 16-hex id; `unmask events --ref <id>` and the hunt page resolve it to the exact serve event and its decision context.

- (2026-06-18) **Branded "blocked" deny page across native, nginx forward-auth and Apache.**  A ban deny used to be a bare `return 403`; both it and the rate-limit deny now render a themed, localized page in 18 languages.  `/unmask/_ban` fails closed during a daemon outage so a ban holds.

- (2026-06-17) **Native rate-limit "deny mode": a hard cap that returns 403, and a valid `_bv` does not buy past it.**  Flooding is flooding, so deny zones count cookie holders; only trusted sources stay exempt.  On protected paths a new compose mode runs `limit_req` in dry-run so the deny zone beats the protected CAPTCHA (nginx 1.17.1+; compiled out on older nginx).

- (2026-06-14) **The `_bv` cookie and the native rate-limiter bind to the IPv6 /64, not the /128.**  Privacy extensions rotate a client's address within its /64 several times a day, so a /128 binding re-challenged on every rotation and multiplied the rate budget.  IPv4 cookies are byte-identical.

- (2026-06-14) **Per-crawler drill-down on the AI / crawler card.**  Each category tag opens a popover listing the individual crawlers behind it, each with a trend sparkline.

- (2026-06-14) **Fuzz harnesses for the JA4 string builder and the `_bv` cookie parser.**  Both run under ASan / UBSan in CI; the `_bv` unit also pins the C verifier and the Go issuer together.

- (2026-06-14) **In-app update check, an About tab, and a published `releases.json` update feed.**  The admin checks for a newer release (12-hour cache, toggleable) and shows the per-distro update command, so an operator learns about a security release without watching the repo.

- (2026-06-13) **Superadmin reconfigure wizard: re-run setup to switch the database.**  `/admin/setup/` is re-runnable behind superadmin auth, pre-fills the current DB, warns that switching keeps the old DB, and runs the non-destructive Migrate.

- (2026-06-13) **Every table and column now carries a DB comment in both dialects.**  The base schema, the numbered-migration tables, and the `schema_migrations` version-history table now ship `COMMENT` clauses on MariaDB and trailing `--` comments on SQLite, so an operator inspecting the database directly finds the schema self-documenting rather than having to cross-reference the Go models.

- (2026-06-13) **Branded `/dl/` landing page, a Japanese landing, and a themed download index.**

- (2026-06-12) **aarch64 (arm64) packages are now a first-class part of
  the release set.**  `make release` builds the web integration packages for
  both architectures and packages an arm64 fat plugin from a pre-built `.so`
  cache (produced once under qemu: `docker run --platform=linux/arm64 …
  make build-module-multi GOARCH=arm64`), and the completeness gate now
  asserts every family × format × **arch** so an arm64-less build can no
  longer call itself a release.  The arm64 plugin bundles the modern nginx
  range (1.18.0–1.30.0, OpenSSL 3 ABI) — the OpenSSL 1.0/1.1 and glibc-2.12
  compat bundles stay amd64-only, since no supported arm64 distro pairs an
  OpenSSL 3 system with those nginx eras; the placer's fail-safe keeps nginx
  running (module off, forward-auth unaffected) on anything unmatched.
  Multi-module cache dirs are arch-suffixed so the arm64 package can never
  silently bundle x86 `.so` files, and the Makefile's GOARCH fallback now
  derives from `uname -m` instead of hardcoding amd64 (inside the Go-less
  arm64 builder container the old fallback silently no-op'ed the whole build
  against the amd64 cache).

### Removed
- (2026-06-15) **Dropped Traefik as a shipped integration -- nginx and Apache only.**  Forward-auth stays HTTP-server-agnostic (`/unmask/api/check` speaks the standard `200/401/403` contract), so it can still be wired by hand; it is no longer a documented sample.

- (2026-06-12) **Dropped Caddy support** (the `unmask-web-caddy` package and its snippet).  The install matrix covers nginx and Apache end-to-end; the Caddy artifacts were never integration-tested.  Forward-auth itself is unchanged.

### Added
- (2026-06-12) **Roaming clients keep their challenge clearance across
  IP changes (silent rebind).**  `_bv` entries are IP-bound by design (replay
  defense), so a phone hopping cells (5G CGNAT churn) re-solved the PoW once
  per network even though the multi-IP list absorbs a stable wifi/office set.
  Solving a challenge now also issues `_bvj`, an admin-only companion cookie
  carrying a signed, host-bound proof of the solve (JA4 + UA fingerprint
  hashes, the solve-time ASN, a random lineage id).  When its holder lands on
  the challenge route from a new IP, the admin re-binds a fresh per-IP `_bv`
  entry and bounces straight back — no PoW — provided the fingerprints match,
  the ASN veto passes (when an ASN mmdb is loaded; cap-only otherwise) and the
  per-lineage cap has room (default 16 lifetime / 4 per hour, consumed
  atomically in the DB so one stolen cookie fanned out across IPs cannot
  double-spend).  Rebound entries carry `kind="rebind"` and cannot seed a
  fresh budget via `/api/bvj`, closing the refill recursion.  Forced
  challenges (honeypot / ja4_bot / banned / protected / rate-limit) never
  rebind.  The native C plugin is unchanged — rolling this out is an
  admin-binary swap.  On by default; the `rebind:` config block (no settings
  UI) tunes or disables it, and `unmask doctor` reports how the gates resolve.

### Changed
- (2026-06-28) **Forward-auth JA4 trust is driven by the trusted-LB list; the `trust_forwarded_ja4` toggle is gone.**  `render-nginx` emits `forward-auth-lbtrust.conf`, which resolves the client JA4 only when the original peer is inside a trusted-LB range -- a direct visitor's spoofed JA4 is dropped at the edge.  One setting for both modes.

- (2026-06-26) **Web Bot Auth and Privacy Pass are behind an Advanced master switch, off by default.**  When off, both are inert and the rendered nginx config is byte-identical.

- (2026-06-26) **The admin settings and challenge copy were rewritten in native Japanese.**  The Japanese strings were rewritten away from translation-ese into natural phrasing, with technical and product terms (JA4 / PoW / CAPTCHA / bot) kept in English; no behavior change, but the UI reads as written-in-Japanese rather than machine-translated.

- (2026-06-19) **Default raw-event retention dropped from 90 to 30 days.**  The dashboard keeps its own 30-day aggregate and hunt is capped at 24 hours, so older raw rows were dead weight.

- (2026-06-14) **golangci-lint is now a hard CI gate.**  The accumulated lint debt was paid down and the reviewed gosec findings cleared (file-permission exclusions, audited TLS / SSRF `nolint`s), so a lint regression now fails the build instead of accreting.

- (2026-06-12) **Non-systemd plugin installs now tell the operator how to
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
- (2026-06-12) **The web / plugin sub-packages now pin the `unmask`
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
- (2026-06-11) **doctor and the daemon now self-check three operator
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

- (2026-06-11) **Removed the UI-hidden built-in UA whitelist presets so
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

- (2026-06-11) **Native daemon-down fail-open trips fast when the daemon
  is unreachable on another host**.  The `/unmask/*` proxy locations had no
  `proxy_connect_timeout`, so a TCP upstream that became unreachable (= admin
  on a separate host that went down, as opposed to a same-host ECONNREFUSED
  which is instant) hung on nginx's default 60s connect timeout before
  `@unmask_daemon_down` could fail open — visitors waited seconds for the
  original page.  Capped at 2s; read/send stay at the default so slow
  challenge renders and the SSE stream are unaffected.  Completes the native
  fail-open added earlier this cycle; e2e scenario 35 exercises the
  container-stop path end-to-end.

- (2026-06-11) **JS-error card separates foreign-script noise from
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

- (2026-06-11) **Native mode now fails open automatically when the admin
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
- (2026-06-19) **`ja4_mismatch` false positives from HTTP/2 <-> HTTP/3 drift on roaming rebind.**  A browser presents a different JA4 over QUIC than over TCP, so `_bvj` refused rebinds on the other transport -- daily, and none were bots.  `_bvj` now stores up to 3 JA4s and matches any.

- (2026-06-19) **Stats queries warn instead of returning a silent zero on timeout.**  A 0 reads as "no traffic", not "could not compute".  Cards now show a warning or "—".

- (2026-06-18) **A roaming `_bvj` whose fingerprint had drifted stranded the holder on repeated PoW.**  It was never re-minted, so each roam failed the JA4 / UA match.  It now re-mints whenever the stored fingerprint no longer matches.

- (2026-06-15) **The Daily-Unique-IPs card timed out on large databases.**  It merged ~65k per-minute HLL sketches in Go (~15s); they are now pre-merged hourly, so the card reads ~720 sketches plus a short tail.

- (2026-06-15) **Two `nginx -t` failures from unmask's rendered config.**  The variable count exceeded nginx's 1024 default (now `variables_hash_max_size 2048`), and the community-bans `map_hash_*` directive was a fatal duplicate on Alpine 3.23's stock conf, silently disabling native mode.  Both guarded.

- (2026-06-13) **Several setup-wizard papercuts.**  Enter no longer triggers Skip, passwords are match-checked client-side, a duplicate username is rejected at the user step, and errors are localized.

- (2026-06-13) **Admin authentication hardening.**  Session signature widened to 128-bit, the setup password is argon2id-hashed the instant it is submitted, reset-token consumption is atomic so a token cannot be redeemed twice, and an unknown role denies instead of admitting everyone.

- (2026-06-13) **Data-integrity and input-sanitization hardening.**  A `UNIQUE` index on user email, manual bans reject `|` and newline so they cannot smuggle a ban-file line, operator paths are sanitized before entering an nginx `include`, logo upload is atomic, and feed-URL logging strips userinfo.

- (2026-06-13) **The challenge primitives are hardened against replay and overflow.**  The CAPTCHA math token is IP-bound with a 15-minute window; the auto-generated `_bv` secret persists to a `0600` sidecar so `render-nginx` and the daemon share one key; a native int64 overflow on 19-digit input is removed; the rate-limiter uses the monotonic clock with a hard map cap.

- (2026-06-13) **The admin web surface is hardened against XSS and cookie leakage.**  Uploaded SVG logos ship a `sandbox` CSP, the challenge page's preview overrides require a same-origin `/admin/` referrer, the flash cookie carries `Secure`, and payload extraction is escape-aware.

- (2026-06-13) **A manual ban could silently widen a honeypot ban into a
  JA4-wide block (DB-3).**  The ban list keyed UNIQUE(ip, ja4), so manually
  banning an (ip, ja4) that a honeypot had already auto-banned overwrote the
  existing row — including its scope.  An `ip_ja4` ban rewritten to `ja4_only`
  silently expands "this one device" into "every IP presenting this JA4", the
  exact ranking accident the search-bot rescue (CLAUDE.md #4) guards against,
  with no signal to the operator.  Scope now joins the conflict/UNIQUE key so a
  honeypot `ip_ja4` ban and a manual `ja4_only` ban on the same (ip, ja4)
  coexist as separate rows (the native plugin already matches each scope
  independently).  Existing databases migrate in place, rows preserved.
- (2026-06-12) **The forgot-password endpoint is now rate-limited like
  login (AUTH-5).**  The per-IP admin-login zone (5/min, CAPTCHA on trip)
  covered only `/admin/login`, leaving `/admin/forgot-password` open: a flood
  could spam reset emails and clobber a pending reset token (each request
  overwrites the previous), blocking a legitimate reset.  Both auth-credential
  endpoints now share the one zone.
- (2026-06-12) **An operator could be locked out of changing their own
  password (AUTH-4).**  The profile form hard-capped new passwords at 72 bytes
  (a bcrypt leftover) while every other path caps at 1024 (argon2), so after an
  operator reset another user's >72-char passphrase they couldn't set their own
  through the profile form.  Both paths now share `user.MaxPasswordLen`.
- (2026-06-12) **A search/AI crawler landing on a honeypot URI could be
  auto-banned, and a freshly added bypass IP was ignored until restart (M-3 /
  DB-4).**  The ban manager's bypass allowlist was a literal-IP map snapshotted
  at startup — it held no preset crawler ranges (Googlebot / Bingbot / GPTBot)
  and no CIDRs, and never refreshed.  So a crawler range tripping a honeypot got
  banned (the exact ranking accident the search-bot rescue exists to prevent),
  and toggling a preset / adding a bypass IP in the admin UI didn't protect it
  until the next restart.  The allowlist is now the same preset+CIDR matcher the
  native geo block and forward-auth path use, injected over live settings so a
  bypass change applies immediately.
- (2026-06-12) **The placer's verify fail-safe no longer strips a healthy
  native module over an error that merely mentions an unmask path.**  The
  "is this nginx -t failure unmask's fault?" classifier matched any error
  containing `unmask` — including an OPERATOR vhost whose
  `include /etc/unmask/forward-auth/server.inc` (the documented forward-auth
  wiring) pointed at a file that did not exist at that instant.  That is
  exactly the mid-transaction state on a remove→reinstall: the plugin's
  postinstall verify runs BEFORE unmask-web-nginx lays its files back down,
  so the fail-safe deleted the just-placed `.so` and autoload conf — and the
  strip could not even fix the error it reacted to (the operator's include
  stays).  Found on the install matrix (AlmaLinux 8 carried such a vhost).
  The classifier now keys on unmask's OWN wiring artifacts only
  (`ngx_http_unmask*`, `00-unmask*`, `50-mod-unmask.conf`,
  `/var/lib/unmask/nginx/`); anything else is a host config error that the
  operator (or the rest of the same package transaction) resolves.
- (2026-06-12) **The module placer no longer duplicates an
  operator-managed `load_module` — which used to escalate into the fail-safe
  stripping a healthy module.**  `place-module.sh` (run before every nginx
  start via the service drop-in) dropped its `50-mod-unmask.conf` autoload
  unconditionally whenever a main-scope include dir existed.  If the operator
  already loaded the module themselves — a hand-added `load_module` line in
  nginx.conf, or their own conf file in that include dir — nginx saw the
  directive twice, `nginx -t` failed with "module is already loaded", and the
  placer's verify fail-safe classified that as an unmask-caused breakage and
  stripped the module wiring **including the placed `.so`**, leaving the
  operator's own (now dangling) `load_module` pointing at a deleted file:
  nginx could not start at all.  Caught by the 9-distro install matrix (every
  rpm/deb distro's native mode failed this way once the ExecStartPre re-pick
  ran on restart).  The placer (and the slim plugin postinstall) now detect a
  foreign `load_module ngx_http_unmask_module` in nginx.conf or any other
  conf in the include dir, skip dropping their own, and remove a stale drop
  of ours — self-healing an already-duplicated setup on the next start.
  Overwriting our own previous drop (the normal re-pick path) is unaffected.
- (2026-06-12) **A headless browser could clear the behavioral check
  without ever seeing the math fallback.**  The behavioral score penalized a
  short `mouseTrail` by a flat -0.3, so a headless Chromium (Playwright /
  Puppeteer) that reports `hasMouseEvents=true`, a non-zero `windowSize` and an
  unhurried `clickAt` scored 0.7 and passed on behavioral signal alone — its
  `.click()` synthesizes the click without the human mousemove run, so the
  trail is just the single click coordinate.  A trail of ≤1 point (mouse events
  claimed, yet no actual movement) is now penalized -0.6, dropping that score
  to 0.4 so the math fallback engages; a merely short trail (2-4 points, a fast
  but real cursor move) keeps the soft -0.3.  The fallback is math, not denial,
  so a fast human with a near-empty trail solves an addition rather than being
  locked out, and a human-like trail is unaffected.
- (2026-06-12) **The cookie_minute v1→kind/cnt migration is now safe to
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
- (2026-06-12) **The English community-bans "not applied" tooltip no
  longer shows raw `%d` / `%s`.**  Two catalog strings
  (`community_bans.below_threshold_title` / `reports_only_title`) carried
  `fmt.Sprintf` placeholders, but the badge renders them through the plain
  (non-formatting) `t` template helper, so English readers saw the literal
  `currently %d` and a bogus `href="%s"` link in the hover popover; the
  Japanese strings were already placeholder-free.  Rewrote the English to be
  self-contained.  A new locale test (`TestLocaleFormatVerbParity`) now fails
  the build if any key's ja/en strings carry mismatched format verbs, so this
  class of drift can't return.
- (2026-06-12) **The live settings hot-swap is race-free.**  A request in flight during a save could observe a torn settings struct and mis-evaluate a decision.  It is now an `atomic.Pointer`, tested under `go test -race`.

- (2026-06-11) **A config that omits secret.bv_secret no longer passes
  doctor while silently breaking the site.**  Load() fills an empty bv_secret
  with a per-process random key that is never persisted, so render-nginx and
  the daemon sign / verify _bv with different keys and every visitor loops on
  the challenge — yet `unmask doctor` checked the post-Load value (a
  healthy-looking 24-byte string) and reported a false green.  Load() now logs
  a loud WARNING when it has to fabricate the key, and doctor reads the RAW
  config so a missing secret is an [ERR], not an [OK].  Only hand-rolled
  configs are affected (package install runs config-init; docker persists one).
- (2026-06-11) **A fresh box no longer contacts the hub before setup is
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
- (2026-06-11) **Event writes are no longer dropped on a transient DB
  error.**  The async event flusher logged an insertBulk failure and then
  cleared the batch, permanently losing those unmask_event rows on a brief
  SQLite-busy or MariaDB blip.  It now retains the batch and retries on the
  next tick (matching nginxlog's flushOnce), bounded so a persistent outage
  can't grow it without limit — overflow drops the oldest events and counts
  them in a droppedOnError metric kept distinct from the queue-full drop
  counter.
- (2026-06-11) **Saving settings on a dev / source build no longer
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
- (2026-06-10) **Web Bot Auth actually works in native mode.**  Three fatal flaws in the signed-route -- a header gate that also fired in the verification subrequest, a phantom proxy endpoint, and a filesystem `try_files` on proxied vhosts -- meant the daemon was never consulted (the dlvr.it incident).  Redesigned around `@unmask_signed_continue`; a daemon outage degrades to the normal challenge.  New `web_bot_auth.allow_private_networks`.

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

- (2026-05-25) **Ubuntu 22.04 LTS in the verified install matrix.**  Closes the nginx 1.18.0 gap between alma8 and alma9.

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
- (2026-05-24) **Alpine first-class native-mode support.**  `unmask-plugin-nginx` depends on `gcompat`, so Alpine's musl-linked nginx can dlopen the glibc-built .so; the postinstall detects `http.d/` vs `conf.d/`.  JA4 fingerprinting works on Alpine.

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
- (2026-05-24) **SELinux blocked the auth_request subrequest on the RHEL family.**  The postinstall now applies `setsebool -P httpd_can_network_connect 1` when Enforcing (opt out with `UNMASK_SKIP_SETSEBOOL=1`).  Fixes "challenge silently does not fire" on alma8 / alma9 / alma10 / centos7.

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

- (2026-05-23) **Install-page nginx config examples reorganised** so the three shared elements are fixed across scopes and only the `protect.inc` placement varies.

- (2026-05-24) **CI workflow** (= .github/workflows/ci.yml): Go 1.22 →
  1.25 to match go.mod and release.yml; push / pull_request triggers
  now include the multi-site branch (= the current v0.1 dev branch).

- (2026-05-23) **README + LP product tone sweep**: dropped "handled when
  time permits" hedge in README status; LP TOP use case 03 rewritten to
  "SaaS-non-outsourced"; competitor product names removed across LP / docs;
  "nginx" generalised to "httpd" where the message applies to multiple
  HTTP servers.

### Added
- (2026-05-19) **IP-geo (ipgeo) UX overhaul**: per-country geo rules, one-click DB-IP Lite install (`unmask install-ipgeo`), a network-tab radio (DB-IP / custom / none), and vendor detection badges.  Renamed from `geoip` to `ipgeo` for trademark distance; DB-IP Lite is downloaded on demand under CC BY 4.0.

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

- (2026-05-07) **Eliminated all `bot_*` / `suspect_*` prefix hardcoding from
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

- (2026-05-07) **Fixed `admin_allow_from` having no effect on existing-site deploys** that include only `unmask-locations.inc`.  An equivalent check now runs at the handler layer (`AdminIPAllowMiddleware`), matching `X-Real-IP` / `X-Forwarded-For` against exact and CIDR entries.  The default changed from loopback-only to empty (= allow all) to avoid lockouts.

- (2026-05-07) **Fixed JA4 / verdict always NULL in check-phase events.**  The values were extracted but not passed to the insert.  Requests where the LB provides no `X-Client-JA4` remain empty.

- (2026-05-07) **Fixed UTC appearing under the TZ picker's "browser auto".**  Rows now carry unix seconds (`data-ts`) and are formatted client-side in the picker timezone.

### Changed
- (2026-05-07) Show `check` phase entries on hunt / overview / live-tail
  as **`check(pass)` / `check(block)`**. The <code>action</code> value inside
  payload_json is extracted server-side (simple string search; JSON parse would
  be overkill) into Row.Action. Pill colors are
  <code>ph-check-pass</code> (green) / <code>ph-check-block</code> (red) for
  visibility. When you see just "check", you can now immediately tell whether
  the request was passed or blocked.

- (2026-05-07) Switched settings error messages to **flash cookies**.
  Long error text used to ride on the URL via <code>?err=...</code>, which
  looked ugly. Now it's written to a short-lived cookie (60s) on redirect, and
  the next GET's readFlash consumes and displays it. Applied to: settings /
  bans / users / hunt / profile.<br>
  Also **removed required validation** for <code>admin_allow_from</code> /
  <code>metrics_allow_from</code> (empty = allow all is already handled at the
  middleware). A missing setting no longer fails save outright; it falls
  through as "allow all, restrict later".

- (2026-05-07) Improved the dashboard 30-day stacked bar chart:<br>
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
- (2026-05-07) **Resolved frequent "(connection error)" on SSE.**  Heartbeat 30s -> 20s (GCP HTTPS LB cuts idle backends at 30s), and an auto-retrying `EventSource` now reads "(reconnecting)" instead of an error.

- (2026-05-07) **Live-tail lightening, round 2.**  SSE poll 1s -> 2s, the tail pauses when scrolled off-screen or after 5 minutes idle, and the scroll listener is passive.

- (2026-05-07) **Lightened live tail under high traffic.**  rAF-batched inserts (reflow capped at 60/s), disconnect while the tab is hidden, and a scroll-aware pause that buffers new events while reading older ones.

### Added
- (2026-05-07) Install guide's **mode comparison cards are now clickable**.
  Cards carry a <code>data-pick</code> attribute and click handler that
  updates the mode dropdown and toggles the related section. The selected
  card gets a "Selected" badge + blue border. The recommended option (nginx
  native) has a star prefix on the heading (a green border conflicted with
  "selected", so it was removed). A small italic hint below each card says
  "click to select xxx".

- (2026-05-07) Added an **unmask main install section** to the install
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

- (2026-05-07) **Tabbed the docs page** (overview / install / help / faq).  `/admin/install/` 301-redirects to `/admin/docs/?tab=install`.

- (2026-05-07) Added an **install guide screen** (= /admin/install/).
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

- (2026-05-07) Added an **mmdb candidate path scanner** to the settings
  GeoIP section. Below the input fields, it scans typical mmdb paths under
  `/usr/share/GeoIP/`, `/var/lib/GeoIP/`, and `/etc/unmask/geoip/`, showing
  **only files that exist** with a folder button + size + mtime (UTC).
  Clicking the button populates the input above. Helps spot stale mmdb
  files (a few years old) and time updates. If nothing matches, the list is
  hidden.

- (2026-05-07) Added a **GeoIP database section** to the settings
  network tab. <code>mmdb_path</code> (City / Country) and
  <code>mmdb_asn_path</code> (ASN) are editable from the web. On save, paths
  are validated by trying <code>maxminddb.Open</code> (rejected on invalid).
  After save, <code>geoip.Reader.Reload</code> hot-reloads (no server
  restart, cache flushed). Current load state (loaded / not loaded) is shown
  at the end of the section. Installs without a <code>geoip:</code> section
  in config.yml can complete setup entirely from the web.

- (2026-05-07) Added a **self password-change screen** for logged-in
  users (= GET/POST `/admin/profile/`). Available to all roles (superadmin /
  admin / viewer). Current password required. Added "Change password" link
  to the user_menu dropdown. Separate from the superadmin-only
  `reset_password` op on `/admin/users/` (confirmation step + audit log
  `user_change_own_password`).

### Fixed
- (2026-05-07) Fixed broken header layout on the playground (right
  side: language / TZ picker + user_menu). The inline `<style>` was missing
  the CSS (`.picker` / `.user-menu`) for the `lang_tz_picker` / `user_menu`
  partial templates.
- (2026-05-07) Fixed **right-aligned numbers not taking effect** in
  dashboard / stats tables. `.bcd-table th, .bcd-table td { text-align:left }`
  specificity (0,1,1) was overriding `.bcd-num` (0,1,0), so even cells with
  `bcd-num` rendered left-aligned. Changed the selector to
  `.bcd-table th.bcd-num, .bcd-table td.bcd-num` for specificity (0,2,1)
  that wins.

### Changed
- (2026-05-07) **Right-aligned values** in overview KPI cards. Numbers
  line up cleanly even as digit counts grow.
- (2026-05-07) Added **thousands separators** to overview hero / KPI
  values (via the `comma` template func). Improves readability past 4
  digits.
- (2026-05-07) Cleaned up faint-cell styling in dashboard funnel
  tables. Removed <code>n-zero</code> (extra-faint gray for 0) on rl,
  <code>n-muted</code> on uniq IP, and <code>n-faint</code> on silent in
  favor of normal coloring. Alert highlighting remains:
  <code>n-warn</code> orange for rl > 0, <code>n-stealth</code> red bold for
  stealth > 0.
- (2026-05-07) Reordered dashboard funnel-table columns to prioritize
  the main flow. New order:
  `verdict / serve / load / pow / captcha / verify_ok / verify_ng / cookie_err /
  JS error / pow_rate / captcha_rate / rl / uniq IP / silent / stealth`.
  rl / uniq IP / silent / stealth are auxiliary observation metrics and
  moved to the end.

### Fixed
- (2026-05-07) Fixed **`action=bot` JA4 verdicts going through the PoW
  path**. Cause: `ServeChallenge` required the `X-JA4-Action` header, but
  deploys whose nginx snippet only forwards the verdict ended up with
  `ja4_hit_flag=0`. Added a fallback so that when X-JA4-Action is absent, the
  action is resolved from X-Client-JA4 via settings (preset / extra rule).
  Verdict labels are free-form strings; the Action enum (bot / suspect / ok)
  should be the source of truth instead of prefix checks.<br>
  Verified on production: after deploy, bot-classified JA4 traffic proceeds
  `serve.hit=1` → load → captcha, with zero pow events.

### Changed
- (2026-05-07) **Install wizard DB step keeps form values on connection
  failure**. The failure redirect's query string now embeds
  <code>driver / sqlite_path / mariadb_host / mariadb_port /
  mariadb_database / mariadb_user</code>, which <code>AdminSetupIndex</code>
  overlays. Only the password is wiped (re-entered each time).
- (2026-05-07) **Removed bootstrap admin auto-seed; introduced setup
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
- (2026-05-07) Rewrote the README "Operating modes" section.
  - Documented that with an LB (GCP / Cloudflare etc.) that supplies the
    <code>X-Client-JA4</code> header, auth_request mode also gets full
    functionality including JA4 verdict.<br>
  - Added a "functionality vs performance" comparison table. After a
    `_bv` cookie is set, requests cost **native = 0.01 ms / auth_request =
    0.5–2 ms** — a ~50–200x difference.<br>
  - Added a recommended-mode matrix: "nginx-heavy + high traffic = native /
    Apache etc. + LB JA4 = auth_request + LB JA4 / Docker / trial =
    auth_request".
- (2026-05-07) Extended the **IP / UA / JA4 rankings** on the bot-hunt
  tab to show a badge in place of a button for already-registered items.<br>
  - IP: "BAN'd" if in <code>unmask_ban</code>, "bypass" if in
    <code>bypass_ips</code>.<br>
  - UA: "search_ai: &lt;group&gt;" (ok color) on <code>search_bots</code>
    hit, group name (bot color) on <code>challenge_targets</code> hit.<br>
  - JA4: same verdict badge as before.<br>
  Implementation: added <code>lookupUAListed</code> in
  <code>auth_check.go</code>; the hunt handler now resolves IP / UA already-
  registered status too.
- (2026-05-07) On the bot-hunt tab's JA4 ranking, JA4s already in
  preset / extra now show a **verdict badge + source tooltip**
  ("preset:rotating_proxy" etc.) in place of the "Register JA4 as bot"
  button. Prevents duplicate registration; clear at-a-glance "already
  registered". Implementation: wrapped <code>auth_check.go</code>'s
  <code>matchJA4</code> with <code>lookupJA4Verdict</code> (with source
  info), shared by the hunt handler.

### Performance
- (2026-05-07) Improved `/admin/stats/` dashboard response time from
  **8s → 0.6s** (13x). Cause: <code>DailyServeByKind</code>'s 30-day ×
  distinct UA × verdict aggregation ran <code>classify.IsBot</code>'s
  647-alternation big regex once per row, millions of evaluations per page.<br>
  Mitigations:<br>
  1. Added a memoize cache on the <code>(ua, verdict)</code> tuple.<br>
  2. Expanded SQLite connection pool <code>SetMaxOpenConns(1) → 8</code>
     (WAL mode allows parallel readers) + <code>cache_size 20MB</code> +
     <code>mmap_size 256MB</code> + <code>busy_timeout 5s</code>.<br>
  3. The stats handler now uses per-query timeouts in independent contexts,
     so heavy queries don't drag down the others.

### Fixed
- (2026-05-07) Fixed cookie-traffic card **mixing bv (CAPTCHA pass) and
  bp (PoW pass)**. The earlier (11:55) fix that made 4-segment PoW cookies
  valid caused everything to count under bv. Fix: split cookie format into
  3-segment (HMAC / CAPTCHA path) and 4-segment (djb2 / PoW path) reasons
  (<code>bv-captcha</code> / <code>bv-pow</code>), so Bump routes to the
  correct column. The funnel-captcha 0 vs cookie-bv 11 discrepancy is
  resolved.
- (2026-05-07) Fixed auth_request mode **unable to verify the `_bv`
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
- (2026-05-07) Fixed auth_request mode's <code>NginxLog.Bump</code>
  always passing **`bp` (= _br cookie present) as false**. Now classifies
  based on the actual presence of <code>_br</code>.
- (2026-05-07) Fixed auth_request mode ignoring settings'
  **ChallengeTargetGroups** (= UA filter / target UA preset). With
  <code>known_browser</code> ON by default, Chrome UAs passed through (zero
  load/PoW events on verdict=ok). The final branch of human classify now
  calls <code>lookupUAListed</code> and routes to challenge if listed +
  category=challenge.
- (2026-05-07) Fixed the challenge HTML's
  `<script src="../static/challenge.js">` **relative path** that worked
  only under narrow conditions. In auth_request mode, when challenge HTML
  is delivered via error_page internal redirect (URL bar shows the
  original path), the browser fetched `/static/...` instead of
  `/unmask/static/...` → flows to the backend, 404 / wrong file → JS does
  not run → no load / PoW events. Switched to absolute path
  `/unmask/static/challenge.js`.
- (2026-05-07) Bot-hunt / SSE / dashboard event datetime: the SQLite
  driver sometimes returns ISO 8601 `2026-05-06T19:55:14Z`. Normalized
  at `events.Row.Date` construction to a unified `2026-05-06 19:55:14`
  format (space separator, no TZ, truncate ms).
- (2026-05-07) Auth_request mode event duplication: one request
  produced two events, `check` (AuthCheck) and `serve` (ServeChallenge).
  Since ServeChallenge always records a serve event for challenge actions,
  AuthCheck now skips the check event on challenge actions (records only
  when action != "challenge"). Pass / block still record the check event
  (no serve follows). Bot-hunt tab now shows one row per request.
- (2026-05-07) Dashboard popover (help text) not showing. Cause:
  the html/template `<script>` context was double-quoting the `safeHTML`
  string as a JS literal (state: `"{\"flags.flags\":\"..."`). Fix:
  wrapped `helpJSON`'s return in `template.JS` and removed `| safeHTML`
  from dashboard.html.
- (2026-05-07) Added logic to read X-Client-JA4 / X-Original-JA4
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

[0.1.4]: https://github.com/unmask-sh/unmask/releases/tag/v0.1.4
[0.1.3]: https://github.com/unmask-sh/unmask/releases/tag/v0.1.3
[0.1.2]: https://github.com/unmask-sh/unmask/releases/tag/v0.1.2
[0.1.1]: https://github.com/unmask-sh/unmask/releases/tag/v0.1.1
[0.1.0]: https://github.com/unmask-sh/unmask/releases/tag/v0.1.0
[0.1.0-pre]: https://github.com/unmask-sh/unmask/commits/main/?until=2026-05-07
