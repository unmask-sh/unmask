# Changelog

Change history for unmask.  Format follows [Keep a Changelog](https://keepachangelog.com/).
Versioning follows [Semantic Versioning](https://semver.org/).

## Conventions

- Each entry starts with `(YYYY-MM-DD)` — the date the change landed.
- Within a release, entries are sorted by date descending (newest at top).

## [0.1.25] - 2026-08-09

> Mostly the settings surface this release: text you typed into a rule survives a
> rejected save instead of vanishing, every tab lives at its own URL, the
> admin-host allowlist speaks in hosts rather than raw regex, and the overview's
> composition card is yours to slice.

### Changed
- (2026-08-09) **The admin-host allowlist speaks in hosts, not generic patterns.**  Its rows carried the same regex / contains / exact toggle as every other list, but two of those readings are wrong for an allowlist: the regex was silently anchored at both ends here (unlike the prefix-by-default regex on the other tabs, which read as an inconsistency), and "contains" was a substring match -- `contains:example.com` would have admitted `example.com.attacker.com`.  The field now offers host modes instead: **exact** (that hostname), **subdomain** (`example.com` and any `*.example.com`, end-anchored), and **regex** (labelled and documented as the full-string match it always was).  A legacy contains entry is read as exact -- fail closed.  Every other list keeps its own modes unchanged.
- (2026-08-08) **Each settings tab has its own URL.**  The tab was a query parameter (`?tab=network`); it is now a path segment (`/admin/settings/network/`), matching the stats and per-site pages, so a tab can be linked, bookmarked and opened in a new window as itself.
- (2026-08-08) **Every segment of the overview's composition card is a filter.**  The segments of the traffic-composition bar can each be clicked in or out of the denominator, so the headline percentage recomputes against exactly the slice you want to read; the selection persists in a cookie, and the card now shares the legend behaviour the stats charts already had.

### Fixed
- (2026-08-08) **A rejected rule-list save no longer discards what you typed.**  Across every settings tab, when a save is rejected -- a self-lockout, an invalid pattern -- the page came back showing the last-saved list, so the entry you were fixing was gone.  It now keeps your input, opens only the rows you changed, and marks the offending row with the reason beside it.
- (2026-08-07) **The admin-host allowlist honours its own mode toggle, and rejects a pattern it cannot use.**  A regex host was read literally regardless of the toggle, and an invalid one was silently dropped -- the list saved short, the gate fell open, and a green "saved" banner claimed success.  The toggle is now applied at match time, and a value that will not compile is rejected at save with the reason, rather than stored to match nothing.
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
- (2026-08-07) **The overview page slowed with the size of the event log, to tens of seconds on a grown install.**  Its 24h counters were computed by scanning the raw event table on every load -- the last page still doing that after the stats page moved to the hourly rollup -- and once the database outgrew the host's memory the scan stopped coming from cache: measured on the largest fleet node, 20 seconds cold against 1.5 warm, for identical queries that were all index-backed already.  The counters now read the rollup, which answers from a few hundred rows however large the install grows.  The raw scans remain as the definition: a host-filtered view, and an install whose aggregator has not finished its first pass, still compute from the events, and two tests hold the two paths equal on the same data.  The figures are unchanged; the window is hour-aligned now, as the stats page's always was.
- (2026-08-06) **A pass earned by re-binding a credential onto a new address was reported as a CAPTCHA solve.**  The plugin classified the cookie by its shape rather than by the kind the admin signed into it, and a re-bound entry has the same three-segment shape as a solved CAPTCHA -- so a crawler passing entirely by roaming read as a quiet trickle of CAPTCHA passes while the proof-of-work counters it never touched read zero, and the challenge looked unbroken while it was being walked through.  Both wires now report the signed kind: re-bound passes are named in the traffic composition (inside the residue breakdown, not folded into the human share), they appear in the per-address reuse ranking, and a kind the plugin does not recognize reads "other" rather than the nearest familiar one.

### Changed
- (2026-08-06) **A rule whose chain ends in a CAPTCHA is now satisfied only by a CAPTCHA-grade pass.**  The pass-cookie exemption asked "does this client hold any valid pass", so a UA the operator had deliberately put behind a CAPTCHA walked through on a proof-of-work cookie -- solvable by any headless runtime -- and a silent re-bind extended that pass to new addresses without ever facing the CAPTCHA either.  Each solve now records the grade it actually proved into the credential (a later CAPTCHA solve upgrades it), the exemption for a CAPTCHA-chained UA requires that grade on both the native and forward-auth wires, and a re-bind checks the lineage's grade before extending it.  The built-in challenge-target presets (curl, python-requests, headless browsers) carry the default chain, so an ordinary install arms this without writing a rule.
- (2026-08-06) **A cookie minted while enforcement was off no longer reads as a solve.**  While a site runs in monitoring mode the challenge hands out passes without asking anything, and those cookies were indistinguishable from solved CAPTCHAs: they inflated the pass counts during the window, and satisfied the pass exemption after enforcement was turned on.  They are their own kind now -- counted separately in the composition, and never sufficient for a grade requirement.

### Added
- (2026-08-07) **Paths on the stats page say which host they belong to.**  Path rankings carried the path alone, which on a multi-site install answers less than it seems; each row now names the site and carries the same popover as hunt, with the full URL ready to open.
- (2026-08-07) **The pass KPIs name the requests an existing cookie admitted.**  "PoW passed" counts solves, and nothing said whether the traffic those solves let through was ten requests or ten thousand.  Each pass card now carries a second line counting the requests admitted by cookies of that kind in the same window, stated in its own units -- requests, not passes.
- (2026-08-06) **How far one solved challenge has travelled is now visible.**  The stats page ranks credential lineages by the number of distinct addresses a single solve has been re-bound onto -- placed beside the per-address reuse ranking, because the two answer opposite halves of the same question -- with the re-binds that succeeded, the ones the cap or the ASN veto refused, and whether the lineage sits at its cap.  Ranked by spread rather than volume on purpose: the case worth finding runs at a handful of requests per five minutes and never surfaces in a volume ranking.

## [0.1.23] - 2026-08-06

> 0.1.22 was published to the pre-release (testing) channel only and never
> reached stable; everything it carried ships here.  A build superseded while
> in testing keeps its number and stays there -- one version never means two
> different files.

### Fixed
- (2026-08-06) **A schema migration could wedge an install forever when the database already carried part of its work.**  Three fleet nodes sat at version 24 with the ref_id column present -- a development binary had run an earlier form of the change -- so 0025 could never apply: the ADD COLUMN failed on the duplicate, the failure aborted the file before its CREATE INDEX ran, the version was never recorded, and every restart retried the same statement into the same error.  The index the migration exists for was missing the whole time, with a one-line log at each startup as the only symptom.  The runner now reads a duplicate column or duplicate key error as proof that statement's end state exists, logs it, and carries on -- so the statements that are genuinely missing still run and the version records.  Only those two errors are treated that way; anything else still aborts.  The mariadb copy of 0025 is also split into two statements so a duplicate column cannot take the index down with it.
- (2026-08-06) **The abandonment rate counted the crawlers the operator had aimed a rule at, so on a site with bot traffic it read as a catastrophe.**  Anything a rule sends to the challenge is expected to leave without solving -- that is the rule working -- but those departures were divided into the same rate offered as "how many people give up on the challenge".  One node read 99.2%: 4,289 of the 4,323 challenge loads in the window were rule-targeted crawlers, and the 34 ordinary visitors underneath them were invisible.  The rate is now computed over the visitors who arrived at a challenge without a rule pointing at them, which is the only population the number is ever used to reason about, and it reads 4.8% on the same window.  The rule-targeted departures are still counted, under the blocked figure where they belong.
- (2026-08-06) **Promoting an rpm out of the pre-release channel could not tell the identical build from a different one.**  The check compared the files byte for byte, and an rpm is re-signed with a fresh timestamp every time an index is built, so the bytes of the same build never match twice -- the guard would have refused every genuine promotion and, had it been relaxed the obvious way, accepted anything.  It compares the payload digest now, which is what identifies the build; deb and apk are still compared as bytes, because they are not rewritten.

### Changed
- (2026-08-06) **Rendering the same settings twice no longer rewrites the files.**  Every render rewrote every file whether or not anything moved, so an `.inc` mtime meant "a render ran" -- and a package upgrade runs one on install.  That made the mtimes useless for the one question worth asking of them, and the check above read them first: it called all seven fleet nodes stale minutes after an upgrade that changed nothing, which is how a warning becomes wallpaper.  A render whose output differs only in its `generated_at` / version stamps now leaves the file completely alone, permissions still asserted, and records the moment a file genuinely changed in a marker the reload check reads instead.  An install that has never changed its config carries no marker, and the check then says nothing rather than guessing.

### Added
- (2026-08-06) **doctor now notices a rendered config that nginx never loaded.**  Saving settings in the admin UI renders the nginx conf immediately and deliberately does not reload nginx -- and in that gap every existing check reads healthy, because "rendered matches config.yml" is true while the running nginx still enforces the previous render.  A field report measured it: http.inc written at 12:24:56, workers started 11:17:21, twelve minutes of saved-but-not-live with all checks green.  The reload moment is recoverable from /proc -- a reload re-forks every worker, so the newest worker's start time is the last time nginx read its config -- and doctor now warns when the config changed after it, naming both timestamps and the reload command.  A draining old worker beside fresh ones stays quiet, and an uninspectable nginx stays silent rather than reporting fresh.
- (2026-08-06) **A leftover `challenge_targets.all` gets a warning that names the consequence, not a shrug.**  The key was removed in 0.1.19 and a config still carrying it produced only the generic "unrecognized keys (ignored)" line -- which reads as harmless, and on one install it was describing a downgrade: under `all: true` every UA had been a challenge target, and the operator's mental model of "that crawler is handled" did not survive the change, because being challenged is not being blocked -- anything that can obtain or re-bind a pass cookie walks through a challenge posture.  The startup warning now says exactly that, and names the replacement: an explicit UA row with action deny, which since 0.1.21 is enforced ahead of the cookie.  Warning only -- the key stays ignored and no behavior returns.
- (2026-08-06) **Publishing verifies what is now being served, from the URLs a client would use.**  The gate checks the packages before they go up and cannot see the publish itself, and the publish is what broke the repository: an apk index reached unmask.sh without its signature, which does not degrade a repository but empties it -- `apk add unmask` answers that there is no such package -- while every pre-publish check had passed minutes earlier against the previous, still-signed index.  The publish now fetches the signatures clients verify, looks inside the apk index for the signature entry rather than trusting a 200, and installs the package from the live repository in a container for each format.  It also refuses to build an index at all if the signing key it was handed does not resolve, or if the tree holds more than one version -- the second failure served an unreleased build to Alpine from the stable channel.
- (2026-08-06) **Reindexing stable cannot silently replace a build that testing confirmed.**  The stable tree is regenerated from `dist/` on every index, so promoting a confirmed build and then reindexing over a rebuilt `dist/` -- same version, different file, because the binary embeds build ids -- would ship an artifact nobody confirmed under the exact name the reporter quoted, and the promotion tool's collision check never sees it, because what lands in stable does not come from the testing tree.  Indexing into stable now compares every artifact against the testing tree first -- payload digest for rpm, since indexing re-signs them with a timestamped signature; bytes for deb and apk -- and refuses on a mismatch, before anything is deleted.  Replacing a confirmed build on purpose has to be said out loud: `UNMASK_ALLOW_TESTING_MISMATCH=1`.
- (2026-08-06) **`unmask version` names the commit it was built from.**  A build carries a version and nothing else, so two binaries that differ -- a pre-release, a rebuild, a hand-placed hotfix -- are indistinguishable once installed, and answering "is this node actually running the fix" meant comparing hashes against a build host.  The commit is stamped at link time and printed beside the version when present; a build made outside a checkout prints the version alone, as before.

## [0.1.21] - 2026-08-06

### Added
- (2026-08-05) **A pre-release channel, so a fix can be confirmed by whoever reported it before it ships.**  Publishing a build for confirmation and then shipping something else built later is not a confirmation, so promotion copies the artifact rather than rebuilding it: the file that was tried is the file that appears in the stable repository, byte for byte.  `unmask-release` configures the channel on every install and leaves it inactive -- `dnf --enablerepo=unmask-testing`, an apt pin below the "only on request" line, an apk `--repository` flag -- so nothing reaches it unless it is asked for by name, and an ordinary update goes back to stable on its own.  Instructions live at https://unmask.sh/docs/faq/#install-specific-version.

### Fixed
- (2026-08-05) **"deny" did not deny.**  Every axis except the ban was consulted only when the visitor held no pass cookie, so the word meant "deny unless this client cleared a challenge at some point in the last week" -- and against anything able to clear one, that is not a block at all.  Measured on a production install: a crawler the operator had already removed from the rescue list solved the proof-of-work from 419 addresses and served itself 137,051 requests in a day through a UA row set to deny.  Raising the difficulty cannot reach it either, because the cookie lasts a week and the cost is one solve per address per week whatever the difficulty is.  A resolved deny is now enforced beside the ban, ahead of anything that reads the cookie, on both the native and forward-auth paths.  Rescues still win: a listed crawler, a bypass IP and a bypass path are all checked first, so nothing an operator exempted on purpose is affected.
- (2026-08-05) **The overview counted some requests twice, and could not say how much of the traffic was human.**  A request carrying a pass cookie that also matched a bypass rule counted as both -- 397,043 of 3,582,523 requests in a day on an install serving its own assets from bypassed paths, and the excess tracked each site's bypass-path share exactly.  The classification is now one decision rather than three that happened not to overlap, and the human share is a count of requests that arrived holding a pass cookie rather than whatever was left over.  What is genuinely unattributed gets its own segment with a breakdown, so the abandons stop being quietly counted as people who got through.  Verified on a fleet node before and after: the parts summed to 15,627 against a total of 13,127 and now sum to exactly the total.
- (2026-08-05) **A rescued crawler was counted as nothing in forward-auth mode.**  The decision was always right -- the crawler was passed -- but only three of the four buckets were recorded, so on a node answering `/api/check` the composition card's benign share sat at zero all day while every rescued crawler fell into the residue.  Each wire was self-consistent, which is why nothing caught it.
- (2026-08-05) **Turning on Web Bot Auth made every request to the vhost pay for the whole decision chain.**  Its gate was keyed on a value nginx builds eagerly, so a location serving static files -- which otherwise evaluates none of it -- started computing the JA4 fingerprint and the full axis set to answer a question only a signed request can answer yes to.  Measured 56k -> 3.9k requests/second; now 42-54k.  Privacy Pass had the same shape.

## [0.1.20] - 2026-08-05

### Fixed
- (2026-08-05) **A visitor who left while the challenge page was holding lost the solve they had already made.**  The display hold added in 0.1.19 ran at the moment the proof of work completed -- ahead of the pass cookie, the beacon and the credential fetch -- so closing the tab during a pause unmask itself imposed meant no cookie, no record of the solve, and a fresh challenge on the next request.  It surfaced while measuring a difficulty change: splitting the window at the hour the hold reached the fleet, one node ran 2.20% abandonment without it and 17.9% with it, against an 11.87% baseline before either change.  The hold was not merely mis-counting departures, it was causing them, and it was large enough to hide the improvement underneath.  The completed-state paint stays where it was; only the wait moves, to after the cookie is written, so leaving during it now keeps the pass.

## [0.1.19] - 2026-08-05

### Added
- (2026-08-04) **The traffic-composition card can be read against the traffic unmask actually judged, not just against everything the server served.**  Requests a bypass rule exempted were in the denominator, and they are not a rounding error — 56% of a day on one node — so every other share was roughly halved by traffic that was never evaluated.  The card now names the denominator it used and offers both: all traffic (what the server is serving) or judged only (of what unmask evaluated, how much was not a person).  On the install that prompted this the two differ by 2.3x.  The choice sticks per operator, the excluded bypass row stays listed rather than vanishing, and both shares are computed in one place server-side — recomputing them in the page would have put the same arithmetic in two places.

### Changed
- (2026-08-04) **Lowering the proof-of-work difficulty now warns that it breaks the site until nginx reloads.**  The difficulty is rendered into the nginx config and the native module verifies every pass cookie against it, so dropping it daemon-side alone leaves the module demanding the old target: a solve two bits short clears one time in four, and the visitor solves, is refused, and is challenged again — about four times before one happens to pass, which is what "the challenge screen loops about five times" turned out to be.  `render-nginx` now compares the difficulty it is about to write against the one the running nginx is still enforcing and, on a drop, prints the share of solves that will be refused and the reload command.  The ordering rule is the reverse of the intuitive one: lower the gate first, then the daemon.

### Added
- (2026-08-04) **The challenge page's presentation is a setting: hold it long enough to read, or show nothing at all.**  Removing the artificial waits left a ~150ms interstitial — a flash the visitor notices but cannot parse, the worst perceptual band there is.  The visible style (default) now holds the page to a configurable minimum (`min_display_ms`, default 800; 0 = redirect the instant the solve lands) with the residual showing "✓ Verified", so the check reads as a check.  The invisible style shows nothing but the themed background until a configurable reveal delay (`invisible_reveal_ms`, default 1200) — a fast device passes with nothing ever shown, indistinguishable from a plain navigation, and only visitors actually waiting get the spinner and its explanation, with a configurable fade-in (`reveal_fade_ms`, 0 = pop in).  A CAPTCHA escalation and every error screen appear immediately in both styles, the hold never delays the CAPTCHA leg, and the hold is never counted into the solve-time metrics — the original floor re-measured after its own sleep, which is how a 1.5s artifact passed for solve time for weeks.  Per-site, like the rest of the challenge record.

### Fixed
- (2026-08-04) **The rate-limit funnel rollup wedged forever on the first hour containing a verdict-less event.**  `ja4_verdict` is NULL on rows that carry no verdict, the rollup's stealth query groups by it, and scanning that group name into a bare string errors — the helper's own comment promised "a NULL yields an empty string" and the code did not deliver it.  A failed batch never advances the cursor, so the 60s ticker retried the same hour forever: one log line per minute, and the dashboard's "live tail" raw-scanning an ever-growing window — exactly the per-IP self-join the rollup exists to avoid, growing without bound on a multi-GB database.  The fix un-wedges existing installs on its own: the cursor advances and the settled hours backfill idempotently.
- (2026-08-04) **On an install whose posture challenges every visitor, hunt attributed every challenge to the operator's UA rules.**  The escalation reason keyed on "is this UA a challenge candidate", and under the challenge-everything toggle every UA is one — so bystanders who matched no pattern read `ua_target`, and the rows the label exists for were indistinguishable from the crowd.  The reason now names a rule only when a pattern actually matched.

### Removed
- (2026-08-04) **`challenge_targets.all` is gone; the challenge-everything posture is the Operating-mode buckets' job.**  The toggle predated the per-UA-shape bucket actions and said the same thing a second way, from a key no form has rendered since the preset overhaul — an invisible setting that steered the whole site and fed the attribution bug above.  The bucket actions already challenge every no-match request out of the box, so a default install behaves identically; a config still carrying the key has it ignored, and an operator who had set `known_browser_action: pass` alongside it will find that choice honoured now instead of silently overridden.

## [0.1.18] - 2026-08-04

### Fixed
- (2026-08-03) **Every visitor was held for 1.5 seconds before the challenge let them through, and the wait was entirely artificial.**  The PoW spinner carried a display floor meant for the test pages: the placeholder in `challenge.html` had drifted from the constant the server substitutes into it, so the substitution silently never fired and the HTML's own value shipped to production.  A second 800ms padded the post-solve redirect so the "verified" beat could be seen.  Neither had anything to do with computing the proof.  Measured against the same window the previous day: PoW p50 1508ms → 389ms, and abandonment on the same node fell from 7.53% to 2.76%.  A test now pins every injected constant against the HTML it is substituted into, because that drift is silent by construction.
- (2026-08-03) **Browsers without `TextEncoder` could not solve the proof of work at all, and looped on the challenge forever.**  `sha256` reached for it, and EdgeHTML has it on neither the window nor a worker: the PoW worker died on its first message, the fallback died the same way, and the visitor sat on a challenge that could never finish, reloaded, and got it again.  UTF-8 is encoded by hand now, and the worker source carries that function with it — the worker is assembled from functions defined elsewhere in the file, so it was possible to inject one without injecting what it calls.  A test walks the injected set and fails on any callee left behind.
- (2026-08-03) **The dashboard could report "0 human visitors" for a site that had them.**  The four traffic segments are shares of one total, and a listed crawler fetching a bypassed path was counted in two of them, so the human remainder went negative and was floored to zero — indistinguishable from a real reading.  Bypass now wins that overlap (the request was never judged, so calling it a crawler we chose to pass is the wrong story), and a remainder that still cannot be computed reads "—" with the reason, rather than a silent zero.
- (2026-08-03) **A visitor who merely changed IP was re-challenged instead of being silently re-bound.**  The roaming rebind runs only on the plain path, and a new escalation-reason attribution filled that field in before the gate that reads it.  Caught by the end-to-end suite, not by unit tests.

### Added
- (2026-08-03) **A pattern can say that it means itself.**  Every rule field is a regular expression, and the obvious thing to do with one — paste the value you want to block — silently does not work: a User-Agent pasted verbatim compiles, passes every check, and matches the UA with its parentheses removed, which is nothing.  A pattern now declares how it is read — regex, contains, or exact — with a chip in the field that switches it and a placeholder that follows.  Applies to every pattern list: UA allow and block, JA4 verdicts, honeypot, protected, bypass, geo and ASN exemptions, rate-limit paths.  Unmarked patterns are regexes and keep meaning exactly what they meant.
- (2026-08-03) **A UA block-list rule can pin its own action.**  The list ran one chain for every pattern in it, so a rule that needed `captcha_only` could only get there by moving every other rule with it.
- (2026-08-03) **Hunt says why a challenge fired, for the axis that fires most of them.**  A challenge raised by the operator's own UA rule was recorded as "none": nginx fires it off a map variable and forwards no header saying so.  It reads `ua_target` now, and is filterable.  The serve event also records which chain it offered, and the phase pill carries a popover on every row — a lone serve row, the common case on a quiet site, had none — so a CAPTCHA the page escalated into after the serve reads as the divergence it is.
- (2026-08-03) **Requests a bypass rule let through are counted apart from people.**  The access log could not tell "deliberately passed" from "matched nothing", so a repository or an API served behind a bypass path landed in the human share — on one install that was 30% of all traffic, package managers counted as visitors.  Both deployment modes feed the same counter.
- (2026-08-03) **Acting on a hunt row no longer leaves the page.**  The UA and network buttons open a dialog like BAN beside them; the UA dialog proposes the identifying token rather than the whole string, counts what the pattern would match, and refuses one that does not match the UA it was built from.

### Changed
- (2026-08-03) **Hunt's identifier columns abbreviate until there is room, and expand when a card is folded away.**  The JA4 was clipped at 25 of its 36 characters server-side, so widening its card revealed nothing.
- (2026-08-03) **A UA pattern added from hunt is validated the way the settings form validates one.**  That path rejected nothing at all — and the strings it let through were the ones the feature exists for, since a self-identifying crawler writes `Name/1.0 (+https://…)` and the `(+` is not a valid repeat.  nginx would have refused the whole configuration at the operator's next reload.

## [0.1.17] - 2026-08-03

### Added
- (2026-08-02) **The dashboard says what a site's traffic is made of, in requests.**  The headline figure was "non-human traffic", counted in distinct clients and reckoned only from clients that failed a challenge — so every crawler let through on purpose was missing from a number named after exactly that, and the unit disagreed with the figures either side of it on the page.  It now reads as three shares of one total: bots passed on purpose, bots stopped, and the rest.  Requests, because that is the unit of the question — a crawler sweeps a site from a handful of addresses while a distributed bot spreads a few requests over thousands, so counting clients ranks the two in the opposite order from the load they cause.  On a live install the two readings differed by a factor of thirty.  The figure has a card of its own above the counters, with a bar, each share as a percentage, and a popover that says where the line between benign and malicious sits and that moving a crawler group behind a challenge is what moves it.
- (2026-08-02) **Every custom rule records when it was added and when it was last edited.**  A rule outlives the reason it was written, and the audit log is pruned on a retention window (90 days by default) — so for anything older there was nothing left that could say when it arrived, and an allowlist entry reading `10.8.11.1` says nothing about whose machine that was.  The add date was in fact already stored under a misleading name; the edit date is new, stamped only when a confirmed edit actually changed something, so the date means "changed" rather than "opened".  Defined sites and the admin, host and metrics allowlists, which use a different row component, gained both.
- (2026-08-02) **Hunt can drill from a network into the requests behind it.**  Every other ranking on the page lets a count be clicked; the network card could not, because the ASN is resolved from the database when the page renders and does not exist on the stored request.  The drill-down resolves the window's addresses and filters on the ones that belong to the network — the same scan the ranking already does.  Without an ASN database it shows nothing rather than the unfiltered log, which would read as that one network accounting for every request on the page.
- (2026-08-02) **Rank cards fold away, and the choice sticks.**  The four cards share one row and the widest data decides what is left for the others, so the row was tuned for the worst case rather than for what the operator is looking at.  Any card now folds to a labelled strip and hands its width to the ones still open.  The user-agent card also switches between the summary and the raw string, since folding a neighbour can hand it enough width to read one.
- (2026-08-02) **The managed geo databases keep themselves current.**  Country and ASN can each be set to update monthly, independently.  The download is written to a temporary file and only swapped in after it verifies as a readable database, so a truncated or unavailable download leaves the working copy alone.  Custom paths are never touched — the switch lives inside the managed-path mode and says so.
- (2026-08-02) **`unmask` drops to the daemon's user when run as root.**  A CLI command run under sudo created files the daemon could not read, and the failure was silent and delayed: `install-ipgeo` under sudo left root-owned databases and every country lookup on the fleet stopped resolving, while doctor read them as root and reported them fine.  Doctor now checks ownership as well, and flags a deployed challenge asset that no longer matches the binary — the case where an upgrade lands everywhere and visitors keep getting the previous day's page.

### Changed
- (2026-08-02) **The proof of work runs in a Web Worker.**  The fallback yields with `setTimeout` so the page stays responsive, and browsers clamp a background tab's timers to one second — which at the default difficulty is around fifty batches, so a visitor who switched tabs waited roughly a minute instead of under one.  Fleet data showed exactly that shape: a cluster of sessions at 41-70 seconds against a body where 88.8% finished within two.  A worker needs no yielding, so the clamp never applies; the UI-thread loop stays as a fallback for browsers without workers.
- (2026-08-02) **Every path field states whether it takes a regular expression, with examples for what that list is actually for.**  Seven path settings offered a text box and no syntax, and they did not all agree: rate-limit zones matched literally while the rest were regular expressions, and one list matched case-sensitively where its neighbours did not.  They are regular expressions now, uniformly, each with a shared explanation of the syntax and a handful of examples drawn from that section's own job.
- (2026-08-02) **Bot hunt now ranks the networks traffic came from, not just the addresses.**  A bot renting a few thousand addresses inside one hosting AS makes only a handful of requests from each, so every one of them sits near the bottom of the top-IP list and the operation as a whole stays invisible — while the network it rents from is the single thing all those addresses share, and the only handle wide enough to act on.  The hunt page gains a "top networks" card ordered by **distinct IPs** rather than requests, which is what makes that shape legible: on a live install the leading row was one network contributing 8,930 addresses.  Each row carries the AS number, the organization, how many addresses and requests it accounted for, and whether an ASN rule already covers it — so a network already dealt with reads differently from one still untouched.  Rows without a rule link into the ASN tab with the number filled in; nothing is applied automatically, because a rule that wide has to stay an explicit decision.  The card is omitted entirely when no ASN database is installed, rather than rendering an empty table that would read as "no networks were seen".

- (2026-08-02) **Bulk network lookups stopped paying for data they discard.**  Resolving an address also queried the country database and decoded its name maps, then wrote the answer into a shared cache — both worthwhile for the per-address popover, where the same few addresses are asked about repeatedly, and both pure cost for a caller that walks every distinct address in a window exactly once.  Network-only lookups now skip both, which keeps the new ranking off the critical path for the default view and stops a page load from growing an unbounded cache by the size of its window.

### Fixed
- (2026-08-02) **A visitor that sends no User-Agent was recorded — and classified — as unmask's own fetcher.**  The forward-auth protocol reports an absent UA as a header the proxy set to the empty string, and the resolver read empty as absent and fell back to the subrequest's own User-Agent, which under Apache is whatever LuaSocket sends.  On the install where this surfaced, 60% of all events (27,204 of 44,968) carried that name, and the sites in question are hit mostly by scanners that send no UA at all — exactly the population the check exists to catch.  nginx's `auth_request` inherits the client's headers, so its subrequest carried the visitor's UA and the substitution was invisible there.
- (2026-08-02) **Observe mode no longer reports itself as "no attacks".**  The headline counts challenges that fired, and observe mode fires none, so an install being scanned continuously showed a calm dashboard.  It now reports what would have been stopped, and says which question it is answering.
- (2026-08-02) **A confirmed settings row stopped offering controls, and stopped changing when one was touched.**  The rule that hides a committed row's inputs missed the action dropdown, so a row that had been confirmed still presented an editable "inherit the default" — and opening it toggled the row's enabled switch, because the whole-row click handler's exemption list named inputs and labels but not selects.  Confirming a row also rewrote its summary as plain text, which took the mode, action and site markers with it until the next page load.  A row still missing its path now shows the values it does have rather than hiding them.
- (2026-08-02) **The Apache hook fired on internal redirects and sub-requests.**  One visitor request could be judged several times, and a request the server generated for itself was judged as if it had come from outside.
- (2026-08-02) **The hunt log's user-agent column reads four cases correctly.**  A version without a trailing dot (`Chrome/131`) went undetected; an in-app browser was named after its engine rather than the app; a crawler whose information URL contains the word "bot" was summarised as "bot"; and a crawler that failed its address check was described as challenged rather than as failing verification.
- (2026-08-02) **Redirect exemptions kept restamping their own date.**  The row posted a fixed value rather than what it held, so every save of that tab recorded the rule as added that day.

## [0.1.16] - 2026-08-01

### Added
- (2026-08-01) **The default rate limit is now three parallel axes — per-IP, per-JA4, per-IP+JA4 — each an always-visible row with its own threshold.**  The old control was a dropdown choosing ONE counting key, which framed a false choice: an operator who wanted the classic per-IP limit AND a fingerprint-based one had no way to say so.  The axis that was missing matters: a bot fleet that rotates addresses never accumulates in a per-IP bucket — each request arrives on a fresh IP and every bucket stays at one — but the whole fleet tends to share a TLS fingerprint, so a per-JA4 counter keeps counting while the addresses churn.  It is the only rate axis with that property, and it now runs in parallel with the per-IP default instead of replacing it.  The JA4 row ships off: one fingerprint covers every user of one browser build, so its bucket is a crowd, and turning it on is an explicit decision paired with a high threshold (enabling with the fields blank adopts 600 r/min) and a challenge-mode action rather than deny.  The row help states the pairing rule the hard way was learned: running two axes only works in the finer-key-gets-the-lower-threshold direction — a looser IP+JA4 next to a tighter IP can never fire, because the coarser counter always trips first.  At least one row must stay enabled (the default zone is what the rest of the enforcement hangs off), thresholds survive a row being switched off, and the stored config keeps its pre-row shape — the primary row writes the same `key` + `default` fields the dropdown wrote, so existing files load unchanged and older binaries still read the primary limit correctly.
- (2026-08-01) **Named zones can count against their own key.**  A path-scoped zone now takes ip / ja4 / ip+ja4 in a new column (empty = follow the default), so `/api/` can throttle per fingerprint while everything else stays per-address.  The zone table's help carries the same crowd-key caveat as the default card.
- (2026-08-01) **The admin login and password-reset forms throttle per address — in the application, where it actually fires.**  The rate-limit preset that claimed to protect the login page never counted a single request: any visitor holding a valid challenge-pass cookie is exempt from challenge-mode rate zones (re-challenging a proven human is pointless), and on an admin page that is essentially everyone who gets far enough to type a password.  The preset is gone, replaced by an in-app throttle on the two POSTs that matter: repeated failed logins from one address answer 429 with Retry-After (the counter resets on success), and password-reset requests get their own smaller budget so the mail path cannot be pumped.  Nothing rides the nginx wiring, so both deploy modes enforce it identically.

### Changed
- (2026-08-01) **Every value list in the settings now renders as confirmed rows — text until explicitly edited — with a per-row off switch, a note, and reorder arrows.**  The admin-UI allowlist, the admin hostname list, the metrics allowlist, the defined-sites list and the custom trusted-LB list were permanently-editable inputs, and the settings tabs save whole forms: a stray keystroke in an allowlist row rode along with whatever the operator actually meant to save.  These are the highest-consequence fields in the product — mistype the allowlist and the admin UI locks you out — so rows now render read-only with an explicit edit toggle, matching the rule lists everywhere else.  The off switch keeps the row's value (switching a VPN range off for a test no longer means retyping it), and a switched-off row is absent from every consumer: the admin and metrics gates, password-reset host validation, ghost-site detection, the pickers, and the trusted-LB set on both wires.  The self-lockout guard judges the enabled subset, so disabling the one row that admits you is refused exactly like deleting it — while switching every row off is the documented way of saying "no restriction".  Promoting a ghost site that already has a switched-off definition re-enables the row instead of appending a duplicate.
- (2026-08-01) **The hunt log's user-agent column tells apps, browsers and bot kinds apart at a glance.**  Platform and browser now carry small marks (Chrome, Edge, Firefox, Safari, Opera, IE, and per-OS glyphs for app WebViews), and a request from inside an app names the app: an Android WebView sends the host app's token AND a Chrome one, and preferring the engine had the same app reading "LINE" on an iPhone but "Chrome" on Android — the app is the identifying half, and the engine version stays in the popover.  Bot claims split into two badges that mean different things: a crawler on the public crawler-user-agents list (amber — its vendor is known, the big ones publish verifiable ranges) versus a self-declared bot (grey — the UA merely says so, and there is nothing to check it against).  The amber badge's hover follows the operator's own policy: for a crawler the config deliberately challenges, genuine visits land in this log too, so the badge says "configured target" instead of accusing the vendor of failing a verification it never took.  The pager caption now counts what is actually on screen — "201-302 (20 sessions)" — since the session collapse folds a hundred rows into a couple dozen lines and the bare row range read as the pager short-changing the page.
- (2026-08-01) **Settings tabs, smaller strokes.**  The public test pages default to on with the site picker wired (the pages are the way to see what a visitor sees; the switch is still there for operators who want them dark).  The performance tab gained named profiles (conservative / standard / generous / custom), shows the memory estimate where the chosen values are, spells out what "auto" resolves to on this machine, and labels the host figures as physical memory and logical cores.  The geo tab shows full country names next to freshly added codes.  The PoW cookie-lifetime hint renders on page load instead of only after the first keystroke.

### Fixed
- (2026-08-01) **Rate-limit zones now enforce identically on both wires.**  Three divergences between native mode (nginx renders the zones) and forward-auth mode (the daemon counts) had crept in, each capable of making the same config file mean different things per deploy mode.  Zone path patterns were interpolated raw into a case-insensitive nginx regex while forward-auth compared literal bytes — `/api/v1.0/` matched `/api/v1X0/` on one wire only; patterns are now escaped and both wires prefix-match literally.  A zone with no path patterns was declared but never applied in native mode — forward-auth enforced it, nginx silently did not; protect.inc now emits its limit_req next to the default's.  And overlapping zones counted first-match-only in forward-auth while nginx stacks every matching zone; the daemon now counts them all in parallel, which is also what makes the new per-IP + per-JA4 pairing work there, with a deny trip outranking a challenge trip when both fire on one request.
- (2026-08-01) **Hunt paging, round two.**  0.1.15 taught pages to read a little past their edges so sessions straddling a boundary arrive whole — but sized the margin to how many rows a session HAS, when what matters is how far those rows SPREAD once interleaved with concurrent traffic: on a busy node a four-row session can span hundreds of positions, and sessions kept arriving decapitated.  The margin now covers the spread distribution measured against production traffic, with the remaining tail still marked.  Separately, the 1000-rows-per-page option never worked: the fetch layer reset any out-of-range request back to 100 rows, and the margin pushed 1000 past the cap — limits now clamp instead of resetting.  And the fragment marker's hover text stopped claiming the missing rows are "on a previous page": chasing a report of many markers proved the dominant cause on a load-balanced fleet is the session's serve being recorded on a *different node* — an HTTP LB picks a backend per request, so one client's challenge can straddle machines — and the hint now names all three causes (adjacent page, outside the time range, another node).
- (2026-08-01) **Saving a geo or ASN row no longer wipes the pills out of its confirmed view.**  Confirming an edit rewrote the whole cell as plain text, which destroyed the country name and both action pills until the next full page load.  The confirm now rewrites only the value.

## [0.1.15] - 2026-08-01

### Added
- (2026-07-31) **Crawlers that publish their egress ranges are now verified by address rather than by name — as standing policy, on by default.**  Googlebot, Bingbot, GPTBot and the rest publish machine-readable IP ranges precisely because their names are the most-spoofed strings on the web.  unmask has had the per-pattern rule since 0.1.7 — the UA rescue drops away while the vendor's range presets are live — but it was per-row state: saving the UA-filter tab pinned whatever was on screen, so an opt-in ticked months earlier quietly kept a vendor-branded UA passing on the strength of the string.  The new switch on the UA-filter tab makes it policy: while it is on (the default), every range-backed bot with its presets live is judged by address alone, however its row is ticked — a genuine crawler passes from the published ranges, a spoofed UA takes the challenge.  Switching it off restores the per-row choices untouched.  The policy only closes the UA path where addresses are actually loaded: a bot whose preset is disabled, or still unacknowledged after an upgrade, keeps its UA rescue rather than losing every path.  The 🛡 badge beside each range-backed pattern now states one absolute fact — the vendor's preset is enabled (green) or not (grey) — and the legend spells out what the switch does with a green-badged bot; the previous badge folded the row's own checkbox into the colour, which left it changing for two unrelated reasons and made every wording of the legend contradict the switch above it.  Both deploy modes enforce the same resolution, and an e2e scenario now walks it end-to-end through the config file: default outranks the opt-in, policy-off restores the either-axis pass.
- (2026-07-31) **Each row of the three network allowlists can carry a note.**  The admin-UI allowlist, the metrics allowlist, and the admin hostname list are all bare value lists, and address lists age badly — six months on, nobody remembers which office VPN `203.0.113.7` let in, and the safe-looking cleanup is exactly how an operator locks themselves out.  Every row now takes a free-text note next to the value, stored with the list and shown wherever the list is edited.  Purely for the operator's memory; nothing matches on it.
- (2026-07-30) **A collapsed challenge session shows how long the whole exchange took.**  The hunt log folds a session's rows into one line, and the popover now carries the total — first event to last — so "this client cleared PoW in 1.4s" or "this one sat on the CAPTCHA for two minutes" is read directly instead of being computed from timestamps.
- (2026-07-30) **Apple push-notification previews now pass out of the box — behind a TLS-fingerprint guard, because the UA alone would be an open door.**  When a site sends a push notification, each subscriber's Apple device fetches the article and its OGP image to build the rich preview — a burst of requests carrying a `NotificationExtension/... CFNetwork/... Darwin/...` user agent from ordinary residential IPs, minutes after publishing.  On a challenge-protected site those all got 403, so the notification went out with no title or image.  These clients differ from the unfurlers already shipped (Slack, Chatwork): they run on subscribers' OWN devices, so there are no vendor IP ranges to verify against, and a plain UA rescue would be one copied header line for every scraper.  The new `notification-preview` preset therefore rescues only when the UA is backed by Apple's TLS stack: the request's JA4 must carry Apple's cipher-suite hash (JA4_b).  Matching only that segment is deliberate — the other JA4 segments drift with each OS release, and a rescue pinned to full hashes would quietly break previews at every Apple update; the cipher list has held across CFNetwork builds on Darwin 24/25 over both HTTP/1.1 and 2.  A spoofer now has to mimic Apple's TLS stack rather than copy a string.  Both deploy modes enforce the same composite, the group appears in the UA-filter tab with the usual per-group / per-pattern controls, and a request whose JA4 is invisible (plain HTTP, or a TLS-terminating hop in front) simply takes the normal challenge flow rather than being rescued blind.
### Changed
- (2026-07-30) **The hunt log shows each user agent as "platform · browser version" instead of the raw string's first few inches.**  A raw UA is mostly boilerplate — `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 …` — and the cell's ellipsis fell exactly where the distinguishing part begins.  The column now renders what the operator actually reads off the string: `Windows 10 · Chrome 126`, `iOS 26.5 · Safari`, with the OS version wherever the UA carries one; the full string is in the row's popover, and a UA that does not parse as a browser keeps its raw form, which for bot UAs is the informative one.  The table also stopped reserving dead width beside the column, so the summary gets the room the truncation had been starved of.
- (2026-07-30) **A refused roaming rebind now appears inside the session it interrupts instead of as a stray row.**  `bv_rebind_reject` rows carried no session token, so the refusal (no_bvj / ja4_mismatch / asn veto / …) floated free of the challenge the client was then reissued — two entries the operator had to connect by eye and timestamp.  The hunt now folds the refusal into the session that follows it, so one line tells the story: pass cookie presented from a new address, rebind refused for this reason, fresh challenge served.
- (2026-07-30) **The site-scoped challenge preview moved from `/unmask/challenge/<site>/` to `/unmask/test/site/<site>/`.**  The old address put an operator test surface inside the production namespace: real visitors only ever reach the plain `/unmask/challenge/` (their site resolves from the Host header), while the `<site>` form exists solely so an operator can view a site's branding and challenge settings — from the test page's site picker and the theme tab's previews, both of which live under `/test/`.  Hosting it under `/challenge/` also forced dotted host ids into that path's grammar, which is exactly what produced 0.1.13's PoW loop: two regexes in challenge.js had to agree on what a site segment looks like, and they drifted.  Now `/unmask/challenge/` has exactly one shape, and the page's own "am I the challenge itself?" check covers the whole `/test/` subtree wholesale — a rule that cannot drift per-page.  The authorization is unchanged (admin session, or the public-test-pages + site-picker opt-in).  The old URL is gone rather than redirected: every link to it is generated by unmask's own UI, so they all switch with the upgrade, and bookmarks of an operator-only preview did not seem worth a permanent alias.
### Fixed
- (2026-07-31) **Paging through the hunt log is no longer corrupted by the log's own growth.**  Two symptoms, one cause: the log keeps being written while the operator reads it.  A challenge session whose rows straddled a page boundary rendered cut in half, with its pill chain incomplete — the window falls wherever it falls.  Each page now reads a few rows past both edges and assigns every session to exactly one page (the one holding its newest row), so sessions arrive whole and appear once.  And following "next" no longer shows rows already read: an offset means "skip the newest N", so every event that arrived while page 1 was being read pushed already-seen rows down past the mark — on a busy node half the next page was repeats.  Page 1 now pins the newest event id and the pager links carry it along, so paging walks the log as it stood when the operator started; "«" deliberately drops the pin, being the way back to the live view.
- (2026-07-31) **Looking up a support ref no longer reads the whole event table.**  The short code on the challenge / deny page — the one a blocked visitor quotes when they get in touch — was matched with a `LIKE` over the JSON payload column: 53 seconds against a 3.4M-row database, on the path an operator walks while that visitor waits.  Migration 0025 adds an indexed `ref_id` column the writer fills, and the same lookup is a seek: 9ms on the same database.  Deliberately not backfilled — events stored before the upgrade keep `ref_id` NULL and drop out of ref search.  A ref is quoted within hours of being shown, and the rows carrying old ones age out on the retention window, so the gap closes on its own within days; a backfill would have rewritten every stored event during the upgrade to buy those few days back.
- (2026-07-30) **Per-site checkboxes now show the value that is actually in effect.**  The per-site form stores "off here" and "inherit" differently, and the checkbox rendering confused the two in both directions.  A site that explicitly turned a flag off showed a ticked box (the template took "a stored value exists" for "on") — so unchecking "show the credit line" and saving answered with the box ticked again, and re-saving that form then silently turned the flag back on, because a ticked box submits as on.  A site that merely inherited an enabled global showed an empty box, so saving an untouched form silently pinned the flag off.  Checkboxes on the theme and challenge tabs now render the resolved value — what the challenge page actually serves for that site — and saving a form you did not touch stores nothing: posting back the inherited value collapses into "still inheriting", so the round trip is lossless.  Affected show-credit, public test pages, and the test-page site picker.
- (2026-07-30) **A per-site logo now appears in the theme previews, not just the thumbnail beside the upload field.**  The five theme preview iframes fetched the challenge page over the plain route, which resolves branding by request Host — the admin's own hostname — so they showed the wrong site's identity, and visibly: no logo.  A site name can ride a preview query parameter; a logo cannot, because the challenge page fetches it from its branding route.  After uploading a logo for a site the thumbnail showed the file but all five previews stayed logo-less, which reads as "the save did not take".  At a per-site scope the previews now load the site-scoped preview route, which resolves that site's branding server-side and is authorized the same way as the rest of the settings page; live edits keep the path instead of rebuilding it, so the first keystroke no longer snapped the previews back to the wrong site.

## [0.1.14] - 2026-07-30

### Changed
- (2026-07-29) **SQLite memory is now budgeted for the whole daemon instead of per connection, so unmask fits on a 1GB VPS.**  `cache_size` and `mmap_size` are per-connection settings, but the pool opens up to 8 connections — so the previous flat "128MB cache + 256MB mmap" was really up to 8× each once a few dashboard queries ran in parallel.  On a synthetic 2.2GB / 6.9M-row event database driven by the production query mix (hunt page, 30-day aggregate, funnel counts) at 8 concurrent workers, that peaked at **3.7GB RSS** — enough to OOM a small host outright, and unmask is meant to run on modest boxes.  Both knobs are now derived from the memory the process may actually use and split across the pool.  That figure is looked for in three places, because the daemon's own unit is hardened enough to hide the obvious one: the cgroup limit (checking the service's own cgroup path, not just the hierarchy root — on a host the root carries no `memory.max`, so a systemd `MemoryMax=` would otherwise go unnoticed), then `/proc/meminfo`, and finally `sysinfo(2)`, which needs no filesystem at all and so still answers under systemd's `ProcSubset=pid` — which removes `/proc/meminfo` outright.  The split is: about 6% of memory per knob, floored at 16MB and capped at 192MB, so a 1GB VPS lands on 8MB per connection and a large server on 24MB.  The same benchmark then peaks at **447MB (1/8 the memory) for 16% more wall-clock time** — a trade the small-host case is worth, and the gap narrows outside that all-8-connections-busy worst case.  The connection pool is sized to the CPUs the process may use (2-8) rather than a flat 8, which also concentrates the budget: a 1-vCPU box gets a couple of well-cached connections instead of eight thin ones that could not have run in parallel anyway.

### Added
- (2026-07-29) **A Performance tab, so the resource dials are visible and adjustable instead of implicit.**  The memory sizing above is derived per host (CPU count × memory limit), which means no fixed number in the documentation can tell an operator what their own box is doing.  The new tab shows exactly that — the detected memory limit and CPU count, what is in effect now, and how much each choice would use **on this host** — and lets you pick between **Conservative / Standard / Generous / Custom**.  The presets are a *resource* dial rather than a speed dial: the dashboard's range queries walk an index, so a larger page cache does not reduce the rows they read, and benchmarking the production query mix across the presets bore that out. "Generous" therefore buys headroom for concurrent access and unusual workloads rather than promising performance.  Custom exposes the cache budget and the pool size separately (an unusual but legitimate combination is a small cache with more connections), with a warning when the pool is pushed past twice the CPU count — beyond that, connections add no parallelism and only thin each one's share of the cache.  Every estimate is rendered server-side from the same rule the daemon applies, so the page cannot drift from reality, and the tab states that DB changes take effect on restart.  The event write-batching settings (batch size / flush interval) moved here from Log management, where they sat next to data-retention policy despite being resource tuning; that tab now links across.

### Fixed
- (2026-07-29) **The header-integrity axis no longer charges genuine pre-2021 browsers for a header they never had.**  The axis reads a Chromium-family UA that sends no `Sec-CH-UA` over HTTPS as a spoof tell — but user-agent client hints only shipped in **Chromium 89** (2021-03), so every older browser was flagged for something it could not send.  A valid `_bv` cookie is a veto-pass evaluated before any axis, so clearing the challenge did buy the ordinary cookie lifetime; this was not a permanent lockout.  What made it worse than a routine false positive is that the tell is a *permanent* property of the browser — it never stops being true, so the same visitor is asked again every time that cookie lapses, for as long as they keep the device.  And the behavioural CAPTCHA is hardest to clear on precisely the old touch handsets this caught, so the visitors least able to get through were the ones asked most often.  The axis now stays silent below Chromium 89 — the same "the header is legitimately absent here" fence it already applies to plain HTTP and HTTP/1.1 — while continuing to fire for modern Chromium that omits the header, which is the population it was built for.  Both deploy modes are fixed together: the daemon's axis and the rendered nginx map now encode the same version floor.

## [0.1.13] - 2026-07-29

### Changed
- (2026-07-28) **A per-site setting no longer freezes everything else about that site.**  A site's record used to be inherited whole or owned whole: setting one knob for one site quietly detached it from the global record for every *other* knob too.  Raise the global proof-of-work difficulty afterwards and it reached every site except the ones you had ever configured — with nothing on the page saying so.  The settings page made this worse by design, because storing a single value meant seeding the site with a complete copy of the global record, which is what froze it.  A site record now holds only what you actually set for that site, and everything else keeps following the global — so changing a global value reaches the sites that override something unrelated.  Fields you have not set are marked on the per-site form, since a value the site pins and one it is borrowing look identical otherwise.  Turning a flag *off* for one site while the global has it on is now expressible; it previously could not be told apart from "not set".  One trade: setting a value to what the global already says reads as "unchanged", so the site follows if the global later moves — pinning a matching value would need a control on every field, and that cost would land on everyone.
- (2026-07-28) **The challenge page's theme, colours and credit line moved to the design settings, where the logo already lived.**  They had been sitting in the *challenge behaviour* record — which is why choosing a theme for one site made that site show up as having challenge overrides nobody created, and pinned its proof-of-work and cookie settings to a snapshot from that moment.  Design custom with challenge inherited is an ordinary combination and was not representable.  The theme tab now writes only to the design record.  Existing config files are read in their old shape and moved across on load, so nothing is lost and no edit is required; a site record left saying nothing after the move is dropped, returning that site to inheriting.  A record that had already drifted from the global is kept as-is — from the file alone there is no way to tell a deliberate difference from one the site was frozen into, and guessing would change live behaviour.
- (2026-07-28) **The header-integrity axis is now on by default, and it outranks the stale-browser tier.**  A User-Agent claiming Chrome / Edge / Opera that carries no `Sec-CH-UA` over HTTPS is contradicting itself, and the population that catches is almost purely non-human: across a day of production traffic on two sites, only a small fraction of what it escalated ran the page's JavaScript at all and almost none completed a challenge — a markedly lower false-positive rate than the stale-browser tier beside it.  Forging a User-Agent is a one-liner; sending the whole coherent header set a real browser sends is not, and this axis charges for that difference out of the box.  It stays clamped to a challenge, never a hard block, so the rare miss — a TLS-intercepting proxy that strips the header — costs one solvable screen rather than a lockout; `header_integrity: false` turns it off.  When a request trips both this axis and the stale-browser tier at the same strength, it is now reported as `header` in **both** deploy modes: forward-auth used to name whichever axis was evaluated first and told a different story than native about the same visitor, which left the per-axis dashboards disagreeing about which wall did the work.  A genuinely stronger action on the other axis still wins.

### Added
- (2026-07-29) **The audit log now records where each admin action came from.**  It answered who, when and what, but not from where — and nothing else on the box filled that gap: nginx's admin access log keeps only the load-balancer hop, so on a node behind a load balancer the operator's real address was written down nowhere at all.  That blocks the work it is needed for.  Setting an admin IP allowlist means knowing which addresses legitimately reach the UI, and with no record of them the choice was to guess and risk locking yourself out, or leave it open.  After an incident, "which of these logins was not us" is the first question, and it had no answer.  Every audited action now carries the client IP, resolved the same way the rest of the admin resolves it — including failed logins, which is the row whose origin matters most.  Actions with no request behind them (CLI, cron) record no address rather than a misleading one, and rows written before this release show a dash.
- (2026-07-28) **You can now delete a site's settings, not just switch them off.**  The per-site override toggle only ever meant "inherit for now, remember my values" — deliberately, so unchecking it does not destroy what you typed.  But nothing in the UI ever removed the record itself, so a site configured once kept an entry forever, including sites that no longer exist.  Both the design and challenge tabs now offer a delete beside the toggle, shown only when there is actually something stored.  (The endpoints had been present and permission-gated all along; no page referenced them.)
- (2026-07-28) **The cookie-reuse ranking now covers PoW cookies, not just CAPTCHA ones.**  A request that carries a valid `_bv` cookie fires no challenge, so it writes no event — and every per-IP view in the dashboard is built on the event log.  A client that solved the transparent proof-of-work once and then rode that single cookie was therefore invisible in every screen unmask has, which is precisely the shape of a scraper that found the cheap door: solving a djb2 proof-of-work is trivial for a headless browser, and the reward is unmetered access until the cookie expires.  The reuse card already held the only record of that traffic and was discarding everything that had not come from a CAPTCHA.  It now shows both, as separate rankings, because they are read differently.  Holding a CAPTCHA cookie is itself a suspicion signal, so volume alone tells the story.  A PoW cookie is what every first-time visitor earns, so volume alone says nothing — a mobile carrier's NAT will out-request any scraper simply by having thousands of people behind it.  The PoW ranking therefore carries a **JA4 count**: shared egress shows many fingerprints, one client riding one solve shows exactly one.  A high request count next to a count of 1 is the row worth looking at.  Nothing changes on the request path — nginx already logs the client and the cookie kind on every line, and the aggregate is written once a minute — so a passed visitor is served as fast as before.  PoW rows are kept 8 days rather than the 32 the CAPTCHA rows get: a `_bv` lives 3 days, so a longer window stops measuring one cookie's reuse and starts summing unrelated cookies into a number that reads the same for a scraper and for a regular reader.
- (2026-07-28) **An abandoned challenge now says whether the visitor went back or left for good.**  Browsers refuse to tell JavaScript which gesture ended a page, and the one hint they do give — the bfcache `persisted` flag — is structurally false here, because a challenge page must be served `no-store` and is therefore never eligible for that cache.  Recording it was evidence-shaped and empty, so it is gone.  The server can answer the question anyway: going back lands the visitor somewhere and produces another request, while closing produces silence.  Each departure row now reports whether the same client sent anything else within the next 30 seconds, shown in the bot-hunt log as **stayed** or **gone**.  The beacon's own `abandon_via` keeps the other useful split — `pagehide` means they left the page, `hidden` means the tab was merely backgrounded and they may return.
- (2026-07-28) **The abandonment report now separates when the visitor left from when unmask noticed.**  `elapsed_ms` is the moment unmask ran the handler, and an action taken while the PoW holds the main thread cannot be handled until the loop releases it — so someone who gave up mid-solve was recorded a few milliseconds after the solve finished, reading as "left right after passing".  The beacon now also carries `left_at_ms`, the browser's own creation time for the event, which does not move when the handler is delayed (measured 474ms apart on a deliberately blocked thread), plus their difference as `notice_delay_ms`.  Wait-time questions should be read from `left_at_ms`; the gap between the two doubles as a read on how much the proof-of-work is blocking the UI.
- (2026-07-28) **You can now see visitors who gave up on the challenge instead of failing it.**  A visitor who closes the tab or hits Back mid-challenge used to leave no trace: the phase chain simply stopped, which reads exactly like a bot that fetched the page and never ran the JavaScript.  With only counts to go on, "load happened, pass never did" could not distinguish someone who waited three seconds and left from something that was never going to solve it — so the one question worth asking, *are we losing real people to the wait, and at which step*, had no answer.  The challenge page now reports an `abandon` phase on departure, carrying the step it left from and how long the visitor had been waiting.  It uses `pagehide` plus `visibilitychange` rather than `beforeunload`, which is unreliable on mobile and blocks the bfcache, and a successful pass suppresses it so the redirect that means success is not counted as a departure.  Which gesture it was — Back or close — is deliberately not guessed: browsers do not expose that, and a wrong label is worse than none.  Shows in the bot-hunt log as its own (grey, not red — leaving is not a rejection) phase with a filter.
- (2026-07-28) **Link-preview bots that are ordinary in Japan now pass out of the box.**  The bundled crawler list comes from upstream, which carries Slack / Twitter / Facebook / Discord unfurlers but not Chatwork — so a site on the defaults quietly challenged Chatwork's preview fetcher and links pasted into chat rendered bare, with nothing in the UI hinting why.  Whitelisting one class of unfurler and challenging another is not a policy, so unmask now ships its own supplement (Chatwork LinkPreview, WebexTeams, NotionEmbedder) alongside the upstream file.  It is a separate file, tagged `social-preview` like the upstream unfurlers: refreshing upstream stays a plain file replace, and the entries travel the ordinary rescue path, so they appear in the UA-filter tab and can be switched off per pattern like any other.  (These UAs are forgeable and their vendors publish no IP ranges — the same trade-off already accepted for Slackbot.)

### Fixed
- (2026-07-28) **`unmask doctor` reported nginx config as out of date when it was not.**  The freshness check re-rendered the config to compare against the live one, but skipped the step that loads the crawler IP ranges pulled from the hub — which `render-nginx` and the daemon both perform, because without them a re-render drops the search-bot bypass list.  It was therefore comparing a different, smaller config against the real one, and every node that had ever pulled ranges was told it was stale (a sizable block of Google range lines was missing from the comparison).  The advice it gave was to re-render and reload nginx for a config that was already correct.  The check now renders the same way, and when something genuinely differs the warning says which line and what it says on each side rather than only that something changed.
- (2026-07-28) **Previewing a site from the test page looped on the PoW forever.**  After a visitor passes, the challenge page decides where to send them: a page that IS the challenge — direct access, the test pages — has no original page to return to and goes to `/`, because reloading it just serves another challenge.  That decision used a pattern for the site segment that allowed letters, digits and hyphens but not dots, while the parser at the top of the same file (which routes the page's API calls) already accepted them.  So `/unmask/challenge/shop.example.jp/` — any real host name — was mistaken for an ordinary page and reloaded itself: solve, redirect here, get a challenge, solve, forever.  The two patterns now accept the same ids.  (Site ids without a dot, and the plain `/unmask/challenge/` form, were unaffected, which is why this survived earlier fixes to the same page.)
- (2026-07-28) **A per-site logo could be saved correctly and still look like it had failed.**  The settings page built its thumbnail URL from the host-resolved logo route, so while editing site A from an admin served on host B it asked for B's logo and got a 404 — a correct save rendered as a broken image.  Operators reasonably read that as "the save did not work" and saved again, sometimes into whichever scope the picker happened to hold.  A per-site scope now points at the site-scoped route it already had.
- (2026-07-28) **The scope picker did not show the host you had just added.**  Its "add a host" prompt jumps straight to that host's form, but the host exists in none of the sources the option list is built from until something is saved for it — so the dropdown fell back to displaying "Default" while the banner beside it and the form itself were on the new host.  The scope being edited is now always in the list, and the host from the URL is normalized the same way the save handler normalizes it, so a name typed with different case, a port, or a trailing dot no longer renders one row while writing another.
- (2026-07-28) **A per-site save whose override toggle was off reported success while discarding the form.**  The page disables those fields when the toggle is off, so the intended "uncheck and save to drop the override" still arrives empty and still works; but when that script had not run, the values — logo upload included — were thrown away behind a "saved" banner.  That save now stops and says what to do instead.

## [0.1.12] - 2026-07-28

### Fixed
- (2026-07-27) **The header-integrity axis now works behind a TLS-terminating load balancer.**  The axis (shipped in 0.1.11) required HTTPS on HTTP/2·3 *as seen by nginx itself* — but a load balancer that terminates TLS re-originates the backend hop as plain HTTP/1.1, so on LB-fronted deployments the modern-protocol precondition was unsatisfiable and the axis never fired, silently, even when enabled (measured: 5000/5000 backend requests HTTP/1.1 behind a cloud LB).  With a trusted LB configured, the rendered config now keys off the LB-forwarded scheme (`X-Forwarded-Proto`) and treats any LB-forwarded request as a modern context — a real Chromium over https sends `Sec-CH-UA` regardless of the HTTP version the LB re-originates on the inside — while direct-TLS deployments keep the original strict keys.  The nginx-computed verdict rides an `X-Header-Mismatch` header into the challenge serve (set with `proxy_set_header`, so a client cannot forge it) for attribution and for clamping the screen to CAPTCHA; the forward-auth snippets blank the same header defensively.  Within minutes of going live the axis was catching real spoofed-Chromium scrapers that had been sailing through.

### Added
- (2026-07-27) The overview's challenge-serves / PoW-pass / CAPTCHA-pass KPI tiles now carry the same colours as the "all requests" chart's buckets (a legend dot in the label, a darker matching tone on the number), so the tiles read as that chart's buckets at a glance and the overview, dashboard and stats views speak one colour language.
- (2026-07-27) **That warning now fires only when the running code actually differs from what is on disk.**  Replacing a shared object under a running process is done by writing a temp file and renaming it into place — the only way that does not risk tearing a library a process is executing — so reinstalling the *same* build leaves the same unlinked mapping while the bytes in memory are perfectly current.  Across a seven-host fleet that turned out to be most of what the marker found: four hosts carried a deleted module whose content was byte-identical to the file on disk, and reporting those would have left a warning permanently lit on healthy installs until nobody read it any more.  Each candidate is now compared against the current file and dropped when the bytes match; a comparison that cannot be made keeps the finding, because a difference that cannot be ruled out should not be dismissed and the fix is a restart either way.

- (2026-07-27) **unmask now warns when a reload cannot apply what you just changed, because nginx is still running on libraries that were replaced underneath it.**  `nginx -s reload` re-reads the config but does not re-exec the master process, so when a package upgrade swaps a shared library (glibc, OpenSSL, an NSS module, a dynamic nginx module) under a running nginx, the master keeps the old — now unlinked — file mapped and every worker it forks inherits that image.  A reload in that state is not merely insufficient: it hands live traffic to fresh workers built from the broken image, which can jump into an address the kernel no longer backs and die with SIGSEGV, so clients get an empty reply and monitoring sees a flapping host.  `unmask doctor` gains a check that reads the running master's memory map and names the replaced files, and `unmask render-nginx` — which package postinstalls run, moments before the operator decides how to apply — prints the same warning next to its "To apply: nginx -s reload" line, pointing at `systemctl restart nginx` instead.  Both stay silent unless something is actually stale, and both stay silent when the running nginx cannot be inspected at all (the memory map belongs to root), so a non-root run never reports a clean bill it could not verify.  The detector deliberately reports only shared libraries and nginx binaries: a healthy nginx always keeps deleted mappings for its shared-memory zones and AIO ring, and warning on those would fire on every install.  The unmask plugin package now draws the same reload-vs-restart distinction its web package already did, since placing a new module `.so` is itself one of the two ways to reach this state.

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
- (2026-07-27) **Verify a claimed crawler by reverse DNS, not just its User-Agent.**  A request whose UA claims to be Googlebot / Bingbot / YandexBot / Applebot / Baiduspider can now be confirmed against the vendor's reverse DNS — PTR lookup → the vendor's own domain → forward-confirm back to the same IP, the check the vendors themselves publish.  A genuine crawler is rescued even when it falls outside its published IP-range preset (ranges drift); a forged one is challenged (forward-auth) or auto-banned off the access log (native).  The lookup is asynchronous so it never adds latency to the request, range-aware (a crawler already covered by an enabled IP-range preset is skipped — no redundant DNS), and each crawler is individually toggleable on the Bypass-IPs tab, which shows whether it is rescued by range, by rDNS, or both.
- (2026-07-27) **Throttle a network or country instead of blocking it.**  ASN and country rules gain a per-minute rate: rather than acting on every request, cap the network or country at N req/min and apply the rule's action only to the overage.  A config-level default rate is inherited by any rule left blank, and a per-row override (including `0` = never throttle) tunes individual entries.  It works in both modes — native renders one `limit_req` zone per throttled network/country with verified crawlers and bypass IPs exempted (so SEO is never rate-limited), forward-auth counts live, and the overage serves the rule's own action (challenge or deny) on both paths.
- (2026-07-27) **Exempt a path from the country or ASN decision only.**  RSS/Atom feeds are pulled by datacenter and overseas readers (Feedly, Inoreader from AWS/GCP) that a country or ASN policy would otherwise sweep up.  A per-axis exempt path — on the Country tab or the ASN tab — drops just that one axis for the matching path while ja4, honeypot, UA filter, rate limit, and ban all keep running, unlike a full bypass path which skips every check.  List a path on both tabs to exempt it from both.
- (2026-07-27) **Challenge a Chromium browser that is missing its client-hint header (opt-in).**  A new header-integrity axis flags a request whose User-Agent claims Chrome / Edge / Opera but, over HTTPS on HTTP/2 or HTTP/3, carries no `Sec-CH-UA` header — which a real Chromium always sends in that context.  Spoofing a User-Agent is easy; sending the full, consistent header set a real browser sends is not, and this exploits that asymmetry.  The axis fires only under those exact preconditions, so it never touches plain HTTP, HTTP/1.1, Firefox / Safari, or a corporate TLS-intercept proxy that legitimately strips the header — and it is clamped to a challenge, never a hard block.  Off by default; enable it on the UA-filter tab.

### Changed
- (2026-07-27) **The stale-browser tier's lag is now set per browser.**  Chrome and Firefox release at about the same pace today, so one "how many majors behind counts as stale" number spanned both — but if the paces diverge, one major stops meaning the same amount of time per family, so the threshold is now settable independently for Chrome and Firefox (each defaults to the built-in value; either can be pinned manually).

- (2026-07-25) **Block or challenge traffic by network (ASN), not just by country.**  A country block is often too coarse — you can't stop a cloud/VPS/proxy provider's scrapers without blocking a whole country's real users.  The new ASN axis (Geo tab → "Per-ASN rules") acts on the autonomous system number: challenge or deny AS16509 (Amazon), AS14061 (DigitalOcean), a bulletproof host, etc., while the residential ISPs of the same country pass untouched.  It's the by-network sibling of the country axis — same actions (skip / pow_only / captcha_only / pow_then_captcha / deny), same evaluation, same both-modes support (native nginx renders a `$unmask_asn` geo block from the ASN mmdb; forward-auth looks the ASN up live).  Crucially it runs **after** the bypass-IP check, so blocking a cloud ASN never challenges Googlebot / GPTBot — they pass on their published vendor ranges first, and the search-bot-safety rule holds.  Requires an ASN mmdb (GeoLite2-ASN / DB-IP ASN) on the Network tab; without one the axis stays inert and the UI says so.

### Fixed
- (2026-07-25) **Hover popovers no longer vanish mid-hover and go dead until you leave and re-enter.**  The stuck-popover watchdog dismisses the hover popover when its owning trigger is no longer hovered — but most pages never told it the trigger, so it was derived by hit-testing the entry coordinates, which lands on whatever child the cursor happened to enter over (the flag icon in an IP cell, a code snippet).  Moving off that child while staying inside the cell dismissed the popover, and since the cursor never left the cell, no new mouseenter fired — the popover stayed dead until the cursor left and came back.  Every hover popover now names its real trigger element (21 call sites across hunt, the events table, overview, dashboard, bans, community-bans, and settings), so it stays up anywhere inside the triggering cell.


### Added
- (2026-07-25) **`unmask doctor` now warns when config.yml has been hand-edited without re-rendering.**  A config change applied by editing config.yml directly (rather than through the web UI) does nothing until `render-nginx` regenerates the nginx conf and nginx reloads — until then nginx serves the old rules and the change is silently not in effect (a contributing factor in the 2026-07-21 config incident).  doctor now compares the conf nginx actually loads against a fresh render of the current config.yml and warns, naming the stale files, when they diverge.  The comparison ignores the per-render `generated_at` / `unmask_version` stamps and normalizes the output-dir path, so a routine hourly community-bans write-back (which re-saves config.yml without re-rendering) does not false-positive; and the dry-run now loads the same hub-synced bypass-IP ranges and browser baselines the daemon renders from, so a hub-enriched install is not flagged as stale.

## [0.1.10] — 2026-07-25

### Changed
- (2026-07-25) **Both deploy modes now share ONE daemon upstream, `upstream unmask_daemon`, defined only in upstream.conf; the daemon-down hook is `@unmask_daemon_down`.**  The daemon was renamed from `unmask-admin` to `unmask` before GA, but the nginx identifiers diverged: native said `upstream unmask` (defined at http.inc's tail) while forward-auth kept the legacy `upstream unmask_admin` (defined again in upstream.conf, so loading both never collided — by accident, not by design).  Now http.inc carries no upstream at all, upstream.conf is the single shared definition both modes' `proxy_pass http://unmask_daemon` points at, and the down hook pairs with it as `@unmask_daemon_down`.  No compatibility aliases are kept.  A native setup that includes the rendered files by hand needs `include <output-dir>/upstream.conf;` alongside http.inc (the unmask-web-nginx package already wires it in both modes).  **Upgrade note (forward-auth installs only):** the shipped `/etc/unmask/forward-auth/server.inc` and the rendered `upstream.conf` both move to the new names on upgrade + next render, staying consistent; but if you edited server.inc (rpm leaves your copy and drops an `.rpmnew`), or defined your own `@unmask_admin_down` override in a vhost, update those references to `unmask_daemon` / `@unmask_daemon_down` — `nginx -t` will point at any leftover.
- (2026-07-25) **FHS cleanup: the nginx module survives an immutable /usr, the Apache Lua hook's payload moved out of /etc, and the vts example moved to /usr/share/doc.**  The module placer still prefers the distro's nginx modules path, but when that path is not writable at runtime (Fedora Silverblue / ostree-style hosts with a read-only /usr) it now falls back to `/var/lib/unmask/plugin/` and points `load_module` there — previously the copy simply failed and the native module never loaded; the placer also migrates the `load_module` path when the module moves between the two locations, and prints the one-line SELinux labeling hint the fallback may need.  `/etc/httpd/unmask.lua` and `/etc/apache2/unmask.lua` are now symlinks to the copy under `/usr/share/unmask/snippets/` — Lua code is a program, not configuration, so the payload belongs in /usr/share while every documented `LuaHookAccessChecker` path (and every existing vhost citing it) keeps working.  `vts.conf.example` ships under `/usr/share/doc/unmask/` instead of `/etc/unmask/`.
- (2026-07-25) **SQLite page cache raised from 20MB to 128MB.**  Production event databases run multi-GB, where a 20MB cache thrashed on every cold hunt / stats scan; 128MB is still modest next to the existing 256MB mmap window and the OS reclaims it under memory pressure.

### Fixed
- (2026-07-25) **Saving settings from the web UI no longer deletes config sections owned by other programs.**  `feed_server` (unmask-site's block) and any other top-level key the daemon does not recognize used to be silently dropped by the next settings save — on unmask.sh this ate the feed server's config and only surfaced when the process restarted.  Save now carries every unrecognized top-level section over verbatim (comments included), appended under a "not managed by unmask" banner.
- (2026-07-25) **The forward-auth decision endpoint no longer rebuilds its bypass matchers on every request.**  The matcher cache's key was the address of a per-call settings copy, which never matched — so every `/api/check` re-assembled ~100 preset/operator matchers under a lock (an unauthenticated CPU sink; the regex compiles themselves were already memoized).  The cache now keys on the published settings snapshot, so it hits until the operator actually saves a change.
- (2026-07-24) **The test-page site picker no longer serves a challenge that can't be passed, and now shows the previewed site's logo.**  Two bugs in the 0.1.9 site picker: (1) the previewed page embedded the *site's* PoW difficulty, but the pass cookie it yields is verified after the redirect by the physical host (the native module / forward-auth check), which resolve the *host's* difficulty — so a site whose difficulty differed (typically lower) produced a proof the verifier rejected, and the visitor looped on the challenge forever.  The difficulty now stays the host's on a site preview (the CAPTCHA provider, theme, and branding still follow the site — the CAPTCHA is verified by this daemon, which honors the site, and its cookie is host-bound, not difficulty-bound).  (2) The previewed page pointed the logo at the plain `/branding/logo` route, which resolves the request host's branding, so the previewed site's logo never appeared; a site-scoped `/branding/<site>/logo` route now serves the previewed site's logo (same authorization gate as the site-scoped challenge/verify).

## [0.1.9] — 2026-07-24

### Added
- (2026-07-23) **The test pages can now exercise a specific site's challenge end-to-end.**  On a multi-site install, the test pages always rendered the challenge with the settings of the host you were browsing — a site with its own settings (branding / PoW difficulty / CAPTCHA provider) could not be verified without exposing that site's own public test pages.  The admin-side test page (`/unmask/admin/test/`) now has a Site picker that serves the force-PoW / force-CAPTCHA pages via the site-scoped challenge route (`/unmask/challenge/<site>/`), resolving that site's values for the whole flow — the page, its CAPTCHA provider, and the verify call all stay consistent — while the issued pass cookie stays bound to the host you are actually on.  For intranet-style installs where "public" is already private, an opt-in checkbox (challenge tab → public test pages) shows the same picker on the public test pages too; it is off by default because it reveals the list of sites with custom settings and lets a visitor pick between sites' difficulty settings.  Site-scoped challenge URLs remain behavior-identical for everyone else.

- (2026-07-23) **The admin now tells you when the daemon cannot write its own database.**  A DB the daemon can read but not write is invisible from the outside: challenges keep serving (they run on config and signatures alone) while stats, bot hunt, and events silently record nothing.  The classic cause is a root-owned `unmask.sqlite` left behind by running `unmask migrate` as root.  The retention tab's Database card now runs a real write probe **from inside the daemon process** on every view and shows a green "write check: OK" — or a red "NOT writable — events are not being recorded" with the driver error, the daemon user vs. DB file owner, and a copy-pasteable `chown … && systemctl restart unmask` fix.  `unmask doctor` gains the matching check: on MariaDB a live probe (the DSN credentials are the daemon's, so it is definitive), on SQLite a file-owner comparison against the packaged `unmask` user (doctor's own uid — often root — would make a live probe lie).

### Fixed
- (2026-07-23) **The setup-wizard token moved from /etc/unmask to /var/lib/unmask.**  The one-time token that guards the install wizard is transient state, not configuration, so it now lives at `/var/lib/unmask/.setup-token` (FHS) instead of next to config.yml.  The install-time message prints the new path; the daemon still reads — and on completion removes — the old `/etc/unmask/.setup-token` as a fallback, so an install that upgraded mid-setup finishes the wizard unchanged.  A relocated install (`-config` elsewhere) keeps its token next to its own config as before.  Also unified an internal fallback for the community-bans map directory that could point at `/etc/unmask` instead of `/var/lib/unmask/nginx` (unreachable with a normal config; aligned for consistency).
- (2026-07-23) **Per-site challenge logos now actually work, and uploaded logos moved out of /etc.**  The theme tab has always offered a per-site override form with its own logo upload, but every upload — Default or a site override — was written to the same file (`branding/logo.<ext>` next to config.yml), so uploading a site's logo silently replaced the Default logo (and vice versa; an extension change even deleted the other record's file): per-site branding appeared broken even though the challenge page resolves branding per site.  Each record now gets its own file (`logo.<ext>` for Default, `logo.<site>.<ext>` per site), and uploads are stored under `/var/lib/unmask/branding/` — binary uploads are variable data and belong in /var/lib, not next to config.yml in /etc.  Existing configs keep working unchanged (the logo route reads the absolute path stored in the config); the next upload from the UI writes to the new location and cleans up the record's old file wherever it was.

## [0.1.8] — 2026-07-22

### Added
- (2026-07-22) **The UA-filter checkbox and the Bypass-IP range presets are now independent axes, and the UA-filter tab shows each range-backed crawler's true rescue path.**  Since 0.1.7 a vendor with published IP ranges (Google, Bing, OpenAI, ...) was verified by IP instead of UA — but the UA-filter tab still displayed its pattern as ON while the render silently dropped it, and turning a range preset off on the *other* tab silently restored UA-only rescue: one tab's state changed the other tab's behavior, invisibly.  The axes are now decoupled: the UA checkbox controls exactly one thing (pass by UA string) and the range presets control exactly one thing (pass by vendor IP) — both on simply means either match passes.  The tab now tells the truth: a range-backed pattern shows **unchecked by default** with a green **🛡 IP-verified** badge (the genuine crawler passes by IP; a spoofed UA is challenged), and every range-backed row carries a live 4-state badge — 🛡 IP-verified / **UA+IP pass** (amber: the operator opted the UA string back in, so a spoofed UA passes too) / **UA only** (grey: range presets inactive) / **⚠ no rescue** (red: both axes off — genuine crawler challenged; reachable only through explicit choices, and `unmask doctor` warns about it).  The badge recomputes as you click, so "no rescue" is visible before saving, not after.  Checking a range-backed pattern records an explicit UA opt-in (new `search_bots.upstream_ua_enabled` list); saving the tab makes the shown state explicit, after which the IP tab can no longer move this axis.  A config that has never saved the tab keeps the exact 0.1.7 behavior (IP-verification while every backing preset is live, UA-only rescue otherwise) — no install's effective behavior changes until an operator saves what the screen already shows.
- (2026-07-22) **The AI-crawler drill-down now shows that a range-verified crawler's "served" is spoofed traffic, not the real bot being blocked.**  Since 0.1.7, a vendor that publishes IP ranges (Google, Bing, OpenAI, ...) has its genuine crawlers rescued by those ranges — bypassed before they can be served a challenge — so the only requests left carrying its UA into the "served" column are the ones from OUTSIDE the range: spoofs.  The category drill-down popover now marks each such crawler with a prominent 🛡 shield badge (wordless on the row; a one-line legend at the foot of the popover spells out what it means), and the column counting challenged requests is renamed from "served" to **"challenge"** for clarity — for these vendors it reads as spoof volume.  Without this a row like "Googlebot — challenge" read as unmask blocking Googlebot, when it was blocking forged Googlebots while letting the genuine ones straight through.  The mark follows the same fallback contract as the rescue: a crawler is flagged only when every preset backing its range is enabled and past the NEW gate, so a vendor reverted to UA-only rescue is never labelled (its challenge count could then include genuine traffic).  Display-only — the aggregation and stored counts are unchanged.
- (2026-07-21) **The stale-browser tier's current-major baselines now auto-follow an unmask.sh feed.**  unmask.sh aggregates the vendors' official version feeds (the Chrome versionhistory API filtered to the ≥50%-rollout stable, Mozilla product-details including FIREFOX_ESR / FIREFOX_ESR_NEXT) once a day into a single document at unmask.sh/dl/feed/iprange/browser-majors.json — the same hub model as the bypass-IP ranges, so the vendors see one fetch a day total instead of one per install.  Each install subscribes daily (± jitter), persists the last good document under /var/lib/unmask (a restart and the render-nginx CLI start from it), and resolves its effective baselines as: operator-pinned value first, else the NEWER of the hub value and the shipped built-in — a hub outage, a stale cache, or a rollback can never drag a baseline below what the binary shipped with.  The Firefox ESR exemption is the union of the built-in and the hub's list, so both the old and the new ESR stay exempt through a transition window.  The UA-filter tab's current-major fields are now explicit automatic/manual choices: automatic shows the effective value and where it came from (the unmask.sh fetch time, or "built into this release"); manual pins a number.
- (2026-07-22) **Bot-hunt rankings can now filter the raw log in one click, gained a User-Agent search, and step out of the way once a filter is active.**  Each IP / JA4 / UA ranking row folds a 🔍 link into its req count — clicking it filters the raw event log below by that exact IP, JA4, or UA (previously only the UA ranking had a standalone 🔍, and it cost a whole column; now all three share the req cell so nothing widens).  The filter bar gains a **UA substring** box, so an operator chasing a spoofed-crawler flood ("Googlebot — challenge") can pull every request carrying that UA and read off the source IPs — the fake `163.51.x` addresses, not the genuine `66.249.x` ones.  And because the three rankings are window-wide top-30s that intentionally ignore the raw-log filters, they now **hide themselves whenever a value filter (IP / JA4 / UA / ref / phase) is active** — on page 1 too — so a narrowed search no longer shows rankings that quietly disagree with it; the live tail and the filtered event table stay.
- (2026-07-21) **The stale-browser tier now covers Firefox too.**  Firefox shares Chromium's ~4-week major cadence, so the same lag N applies over Firefox's own built-in current-stable baseline (152 as of this release; override it with the new "Current major (Firefox)" field on the UA-filter tab).  The current **Firefox ESR major (140) is always exempt**: ESR is a fully patched long-term release that legitimately trails stable by up to ~15 majors — the enterprise and Linux-distribution default — so challenging it would CAPTCHA a large population of real users.  Edge / Opera / Brave / Vivaldi needed no change: every Chromium-family browser already carries the shared `Chrome/<major>` token the tier reads.  Safari stays out of scope by design — its numbering jumped (18 → 26 in 2025), breaking the "N majors behind" arithmetic, and its version is pinned to the OS, so old-but-genuine Safari UAs are common; a UA carrying neither token is never touched.  The native nginx map and the forward-auth axis take the identical decision.

### Fixed
- (2026-07-22) **A protected path's mode now actually picks the challenge screen it serves.**  The per-path mode (pow / captcha / strict) was rendered into the nginx `$protected_mode` map but never drove the served page: the daemon recognized only `captcha`/`strict` (a `pow` path fell through to the Operating-mode pick), and the forward-auth axis passed no mode at all.  Both gaps were masked by the black-list default-action leak fixed above — scoping that leak surfaced a PoW-only gate serving the full PoW→CAPTCHA chain.  The served screen now follows the path's mode on both axes (`pow` → PoW only; `captcha`/`strict` → straight CAPTCHA; an explicit protected-paths default action still overrides), the forward-auth daemon resolves the protected rule from the original URI, and the Apache snippet's challenge redirect carries that URI (`_orig`) — which also makes apache-mode serves show the original URL on the hunt page.  Admin HTML responses carried no `Cache-Control` header, so browsers applied heuristic caching and kept painting an old dashboard after a redeploy — and because a page's inline `<style>` and markup ride in its HTML, that hid every UI change until a manual hard-reload.  The shared admin auth middleware now sets `Cache-Control: no-store, no-cache, must-revalidate` on every admin response (the challenge path already did; the dashboard was the gap); handlers that serve cacheable bytes — preview images, short-poll JSON — still override it with their own value.  Deployed UI changes now appear on the next normal load.
- (2026-07-21) **Saving a settings tab no longer silently rewrites settings you did not touch.**  A new regression test drives every settings tab through a browser-faithful no-op save (GET the form, submit it back unchanged) and asserts the persisted config is byte-identical; it flushed out — and this release fixes — a family of long-standing save bugs: the geo tab's save button had never worked (its section was missing from the save handler's allowlist, so every save returned 400); saving the ua-filter tab forced `challenge_targets.all` to `false` because the handler read a checkbox that no longer exists on the form; the theme/appearance save mutated a fresh install's stored challenge theme (`default` — a value outside the theme allowlist — was snapped to `auto`); and every default-action style dropdown (UA black-list, JA4, honeypot, protected paths, Operating-mode known/unknown, stale-browser action, deny-page copy presets) displayed a fallback for "never set" and then persisted that fallback on any save of the tab — the exact mechanism that pinned `pow_then_captcha` onto the black-list default across the fleet.  Those dropdowns now offer an explicit "(unset — follows the built-in default)" choice that round-trips; number fields with built-in defaults (PoW difficulty, roaming cap, WBA cache TTL, stale-browser lag) accept blank = follow-the-default with the effective value shown as a placeholder; and values that equal their resolve default (geo `skip`, rate-limit key `ip`, sites mode `auto`, roaming rebind `asn`) are stored as the non-deviation.  A malformed Operating-mode value now falls back to the strict default instead of `pass` (the old path turned a garbled POST into a wave-everyone-through).
- (2026-07-21) **The UA black-list's default action no longer leaks onto every challenge.**  `challenge_targets.default_action` is documented as "the chain used when a black-list UA match triggers a challenge", but the native challenge page applied it to every challenge it served — including plain browsers that merely hit the standard bot gate.  Because the ua-filter tab's selector displays `pow_then_captcha` when the field was never set, saving anything on that tab (for example enabling the stale-browser tier) silently pinned that value, and from then on a current-stable Chrome that failed the transparent PoW was walked into the CAPTCHA leg the operator only meant for black-listed UAs — overriding the Operating-mode pick (`known_browser_action: pow_only`).  The action now fires only when the UA actually matches a challenge target (preset / extra rule / upstream black group, or the catch-all "all" toggle); every other challenge keeps the Operating-mode pick.  The forward-auth axis honours the same setting on a black-list hit too (previously a fixed `captcha_only`), so both deploy modes serve the same screen.

## [0.1.7] — 2026-07-21

> **Upgrade note**: crawler UA patterns whose vendors publish official IP ranges (Google, Bing, DuckDuckGo, OpenAI, Perplexity, Apple, Amazon) are **no longer rescued by their User-Agent string alone** once the matching IP-range presets are enabled.  Genuine crawlers keep passing — their published ranges are folded into the bypass-IP allowlist (on by default) — but a spoofed Googlebot from outside Google's ranges now gets the challenge.  For installs upgrading from 0.1.6 or earlier this applies immediately to the vendors whose presets shipped in 0.1 (Google, Bing, DuckDuckBot, OpenAI, PerplexityBot); the four presets added in this release (Applebot, Amazonbot, DuckAssistBot, Perplexity-User) stay off until reviewed in settings (NEW badge).  To restore the old UA-only behavior for a vendor, disable its IP-range preset on the Bypass IPs tab — that vendor then falls back to UA-only rescue, exactly as before.

### Changed
- (2026-07-21) **The admin dashboard is dramatically faster on large multi-site installs.**  The 30-day stats charts (unique IPs, the pass/challenge breakdown, the per-country split) and the funnel's rate-limit row used to scan or HLL-merge the full per-site, per-minute history on every page load — on a node fronting hundreds of sites, tens of thousands of sketches or hundreds of thousands of rows each time.  They now read compact hourly install-wide rollups that a background pass maintains, so a stats page that took six to eight seconds on a busy node returns in about two, and the funnel's rate-limit row drops from ~3 s to well under one.  The landing overview issues its cards concurrently instead of back-to-back and reads the same install-wide rollup for its non-human-traffic figure; the host / site pickers and the settings "sites" tab use index seeks in place of full-table scans.  Every day-bucketed chart still folds hours into the operator's own timezone, so nothing about what the charts show changes — only how fast they arrive.
- (2026-07-20) **The stats page's rate-limit card** now lists the top 30 source IPs and the top 30 hit paths (each with its query-string breakdown), collapsed to 10 rows apiece behind a show-more expander so the common case stays compact.
- (2026-07-16) **A spoofed crawler User-Agent no longer walks through the challenge.**  UA-based rescue existed to prevent search-ranking accidents, but it trusted the one thing an attacker chooses freely: during the 2026-07-15 incident a 94k-IP botnet crawled with a fake `Googlebot` UA and was waved through by UA match alone.  The rescue for range-publishing vendors is now inverted — the UA patterns are dropped from the rendered UA whitelist (`$is_search_bot`) and from the forward-auth `search_ai` pass, and the vendor's official IP ranges (already folded into the bypass-IP allowlist) carry the rescue instead.  The mapping is deliberately union-wide for Google (common + special + user-triggered fetchers, since Google moves products between its three files) and covers the vendors' legacy UAs too (`Google Web Preview`, `msnbot`, ... — genuine traffic for those no longer exists, so a match from outside the ranges is a spoof by definition).  Fallback contract: if any of a vendor's range presets is disabled or not yet reviewed (NEW), that vendor reverts to UA-only rescue — never "UA required with the ranges turned off", so an operator can always restore the old behavior per vendor.  An operator-added Extra UA row still rescues unconditionally (explicit wins).  The rendered conf notes how many patterns were inverted; the settings UA detail modal marks them with a 🛡 badge (green = range-verified now, grey = falls back to UA-only) and explains the mechanism.
- (2026-07-16) `PresetIsNew` / `VersionLess` now compare the patch segment, so presets added by a patch-step release (v0.1.6 → v0.1.7) correctly show the NEW badge and stay off until reviewed; previously only major.minor were compared and a patch-added preset silently skipped the review gate.  Preset `AddedIn` values are now written in full `vMAJOR.MINOR.PATCH` form (a present segment must be numeric — no lenient fallback), and the settings UI's "since" labels show the same 0.0.1-granularity version.

### Added
- (2026-07-19) **A browser pinned to an outdated Chrome version can now be escalated to a CAPTCHA (off by default).**  The a scraper spread across thousands of residential-proxy IPs, sent a real-looking JA4, and solved the transparent PoW headlessly — its one tell was a frozen `Chrome/139` while stable was 150.  The new stale-browser tier (UA-filter tab) escalates any UA whose Chromium-family major (Chrome, Edge, Opera, Brave — all share the `Chrome/<major>` token and release cadence) is at least N releases behind an operator-maintained "current stable" to a CAPTCHA, even when the Global known-browser action is `pass` or `pow_only`.  A CAPTCHA rather than a block: the genuine long tail of old-browser humans can still solve it, while a headless PoW-solver hits a wall.  The release ships a built-in current-stable baseline, so enabling the toggle alone works out of the box; `current_chrome_major` is an optional override for operators who want to track newer Chrome (an aging binary's baseline only drifts safely — it challenges fewer browsers, never more).  `stale_browser_lag` (default 10) tunes how far behind counts as stale, and `unmask doctor` surfaces the effective threshold.  (Auto-fetching the current stable is the planned next step.)  Firefox and Safari carry no Chrome token and are never affected, bypass IPs (monitoring probes) are evaluated first and never challenged, and search/AI crawlers keep their rescue.  Enforced identically on the native module path (a rendered `$unmask_stale_browser` map escalates the challenge decision; the daemon picks the CAPTCHA screen) and the forward-auth path (`uaDecide`).
- (2026-07-19) **Stats-exclude IPs can now carry a title, like the bypass list.**  The list typically holds monitoring probes and fleet addresses — exactly the entries that become unidentifiable months later — but it was a bare value list while the bypass editor next to it labels every row.  The Bypass IPs tab now edits stats-exclude entries with the same view/edit rows (title + IP; no enable toggle or timestamps, which stats exclusion does not carry).  Titles are stored in a parallel `stats_exclude_ips_title` array; existing configs load unchanged, and everything that consumes the exclusion (the rendered geo block, stats aggregation, the forward-auth matcher) still reads the IP strings alone.
- (2026-07-16) **Four new official IP-range presets**: Apple (Applebot — Siri / Spotlight / Safari suggestions), Amazon (Amazonbot — Alexa answers), DuckDuckGo (DuckAssistBot — AI answers, a list separate from DuckDuckBot's), and Perplexity (Perplexity-User — user-triggered fetch, separate from PerplexityBot's).  All four ship as embedded snapshots, are mirrored by the unmask.sh range aggregator (Amazon publishes its list embedded in an HTML page; the aggregator extracts it), and back the UA-rescue inversion above.  On by default for fresh installs; existing installs enable them from the NEW-badged rows on the Bypass IPs tab.
- (2026-07-16) `unmask doctor` now checks crawler IP-range freshness: when UA rescue is riding the vendor ranges, it warns if the synced range files are missing (never synced from the hub) or older than 30 days — a stale snapshot can eventually challenge genuine crawlers arriving from newly added vendor IPs.

### Fixed
- (2026-07-20) **The Community Bans tab no longer hangs on first load.**  The 30-day "impact" figure walks every serve row in the window through the ban matcher — tens of seconds on a large install — and the first page view ran it synchronously, blocking the tab until it finished or timed out.  It now computes in the background and the card shows a spinner that swaps itself for the figure when ready, so the page paints immediately.
- (2026-07-20) **The retention tab no longer times out on a multi-gigabyte database.**  The stored-event count was a full `COUNT(*)` over the event table; it is now an O(1) id-range estimate (shown with a leading "≈"), and the oldest-event and database-size figures are likewise constant-time.  If any figure genuinely can't be read within the deadline it now shows "??" rather than a misleading zero.

## [0.1.6] — 2026-07-15

> **Upgrade note**: this release fixes a critical connection leak in the nginx module's compose flow (0.1.5, nginx 1.17.6+).  After upgrading, **restart nginx** (`systemctl restart nginx`) — a plain reload does not load the replaced module, and any connections already orphaned by 0.1.5 are only released by a restart.

### Fixed
- (2026-07-15) **Compose mode leaked every challenged connection, exhausting nginx's fd budget and taking the node down within hours.**  `ngx_http_internal_redirect()` takes a reference on the request (`r->main->count++`) that its caller must release by passing the returned `NGX_DONE` on to `ngx_http_finalize_request()` — the CONTENT-phase checker does exactly that with a content handler's return value, which is why `ngx_http_index_module` may return the redirect's value bare.  The compose ACCESS-phase handler did the same — but the ACCESS-phase checker maps `NGX_DONE` to "waiting for an event" *without* finalizing, so every composed redirect (challenge and rate-route alike) stranded one reference.  The redirected response completed normally — the visitor saw the challenge, health checks got their 200 — but `r->count` never fell to zero, `ngx_http_set_keepalive()` was never reached, and the connection was orphaned holding its fd, its read handler parked at `ngx_http_block_reading`: any request the client sent on the kept-alive connection afterwards sat unread in the socket buffer forever (GCP's load-balancer front ends and health probers, which multiplex and reuse backend connections aggressively, hit this on every probe cycle).  Orphans accumulated until the worker's `worker_connections`/`RLIMIT_NOFILE` (1024) ran out, at which point nginx could no longer `accept()` — the accept queue overflowed and **every** port the worker served, admin and public alike, timed out.  All three native-mode production nodes went down this way within ~2 hours of the first compose deploy; the forward-auth node, which loads no module, was untouched.  The redirect is now paired with an explicit `ngx_http_finalize_request(r, NGX_DONE)` — the idiom nginx itself uses for X-Accel-Redirect (`ngx_http_upstream_process_headers`), which likewise runs outside the CONTENT checker's finalize.  Verified against a `--with-debug` nginx: the reference count now closes (`3 → 2 → 1 → set keepalive`), a kept-alive second request is answered, and thirty consecutive challenges leave zero orphaned connections.

## [0.1.5] — 2026-07-14

> **Upgrade note**: this release updates the nginx module (`ngx_http_unmask_module.so`) for the first time since 0.1.2.  After upgrading the packages, **restart nginx** (`systemctl restart nginx`) — a plain reload does not load the replaced module and can leave nginx running a config/module mix.  On nginx 1.17.6+ the rendered config also switches from the classic to the compose rate-limit flow automatically at the next render; no configuration change is needed, and older nginx keeps the classic flow.

### Fixed
- (2026-07-14) **On AlmaLinux / RHEL 8 the nginx plugin was reading the wrong request fields, and on a compose-mode host that meant protected locations let every bot through.**  Those distributions patch nginx with `max_headers`, which inserts a counter at the top of `ngx_http_headers_in_t` — a struct embedded *by value* in `ngx_http_request_t`.  Every member after it (`r->uri`, `r->args`, `r->unparsed_uri`, `r->main`, `r->headers_in.cookie`, …) therefore sits eight bytes further along than a module compiled against vanilla nginx sources computes.  The patch changes neither `nginx_version` nor `NGX_MODULE_SIGNATURE`, so nginx's load-time compatibility check passes and the module is loaded anyway — it then reads the neighbouring field instead of the one it asked for, with no error anywhere.  The consequences were severe and silent: `r->main` read back as NULL, so the compose ACCESS handler took its "not the main request" exit on **every** request, and because a compose `protect.inc` carries no `error_page`/`rewrite` fallback and runs `limit_req` in dry-run, a protected location served bots straight through with no challenge and no rate limit at all.  `_bv` cookie lookup resolved to the wrong header, so a visitor who solved a challenge was challenged again on the next request, forever.  The plugin now reaches request state exclusively through nginx's own entry points (`ngx_http_get_variable`, `ngx_http_internal_redirect`, `ngx_http_get_module_ctx`), which live in the nginx binary and therefore use the host's real offsets — `$uri`, `$args`, `$request_uri`, `$limit_req_status` and `$http_cookie` in place of the struct members, and a POST_READ context marker in place of `r == r->main`.  Verified end to end on AlmaLinux 8 (patched nginx 1.24.0, SELinux enforcing): a bot request that previously passed through with 200 now receives the challenge.
- (2026-07-14) **On a SELinux-enforcing host without `semanage`, native mode silently recorded zero events.**  nginx (`httpd_t`) may not write the daemon's log socket while it carries the default `var_run_t` label, so the relabel matters — but the whole SELinux block in the `unmask-web-nginx` postinstall was gated on `command -v semanage`, and `semanage` (`policycoreutils-python-utils`) is not installed on a minimal RHEL / AlmaLinux 8.  On exactly those hosts the block skipped without printing anything, and the only trace was `connect() failed (13: Permission denied) while logging to syslog` in the nginx error log while every access-log-derived dashboard card sat at zero.  The postinstall now falls back to `chcon` (in coreutils, always present) plus a `unmask.service` drop-in that re-applies the label on each boot, since `/run` is tmpfs; when neither tool is available it says so loudly instead of failing quietly.  `Manager.Start()` writes the ban file immediately, and that write resolves any row whose action column is empty — meaning "inherit the source's default" — through the per-source action resolver.  The resolver was registered about a hundred lines *after* `Start()`, so the first flush of every daemon start ran without it and fell back to its safe hard-ban default: a honeypot ban the operator had configured as `pow_then_captcha` or `captcha_only` was rewritten as `deny`.  The effect was that on **every** restart — a package upgrade, a reboot, a config reload — recoverable challenges silently became unappealable 403s, until some later ban write happened to re-flush the file with the resolver in place.  Over-blocking, in production, invisibly.  The resolver is now seeded from the boot settings before `Start()`; an end-to-end scenario pins the wiring order (which no unit test can reach) and a unit test pins the ban package's own contract.
- (2026-07-14) **A honeypot probe on the plaintext port no longer earns a whole-IP auto-ban.**  With `https_redirect` on, nginx answers a `:80` request with a 301 and never serves it — but the access log is still evaluated at request completion, and the honeypot check only looks at the URI.  A scanner poking a trap path over `:80` therefore produced a fingerprint-less log line and earned an `ip_only`-scope auto-ban covering its **entire IP**: both broader than, and a duplicate of, the precise (IP, JA4) ban its HTTPS visit already earns.  The log reader now recognizes those redirect-only lines and leaves them to the HTTPS path.
- (2026-07-10) **The admin dashboard no longer redirect-loops (ERR_TOO_MANY_REDIRECTS) when the CSRF cookie expires before the session.**  The session cookie slides forward on every request, but the CSRF cookie was only minted at login — so about 30 days after logging in, an operator's CSRF cookie expired alone.  The middleware "backfilled" it by setting a fresh cookie and 303-redirecting to the same URL, a pattern with no terminating condition when the client doesn't return the cookie: Chrome withholds `SameSite=Strict` cookies from every hop of a redirect chain initiated cross-site (an external link or bookmark, and any reload of the resulting error page) while still sending the `Lax` session cookie, so the server saw "session present, CSRF absent" forever and answered 303 until the browser gave up.  The backfill now issues the cookie and renders the page directly — the response's forms embed the same token its `Set-Cookie` carries, so there is no redirect to loop.  The CSRF cookie also becomes `SameSite=Lax`, matching the session cookie; the double-submit check (cookie value echoed in a hidden field an attacker cannot read cross-origin) is what provides the CSRF protection, so the relaxation does not weaken it.  A POST arriving in this state still fails closed with 403.  Until the fix is deployed, the workaround is to open `/unmask/admin/login` directly and log in again (a fresh login mints both cookies).
- (2026-07-09) **The stats and bot-hunt pages no longer get slower as events accumulate.**  SQLite ships no query-planner statistics until `ANALYZE` runs, and unmask never ran it.  With no estimate of how selective `date_created > ?` is, the planner answered the two pages' `GROUP BY` / `DISTINCT` over the event table by scanning an entire covering index rather than seeking the time range — so the cost tracked the *total* number of stored events instead of the window being viewed, and a one-hour bot-hunt view cost the same as a full-table sweep.  Two changes fix it.  Ranking by IP is now pinned to the `date_created` index: that column is far too high-cardinality for the planner to skip-scan even once statistics exist, so no amount of `ANALYZE` would have rescued it.  Everything else is fixed by the statistics themselves, which a new `unmask db-analyze` command builds; `unmask migrate` also builds them automatically on a small (freshly installed) database, and `unmask doctor` now warns when they are missing.  Measured on a 3.9M-event node: the bot-hunt IP ranking drops from 1.5s to 5ms, the verdict-distribution card from 2.2s to 0.24s, and the host filter list from 0.95s to under a millisecond.  `db-analyze` is a maintenance command rather than something the daemon does on its own, because `ANALYZE` reads every index end to end and holds a write lock while it does — a minute or so on a multi-GB database.  MariaDB is unaffected: InnoDB maintains its own index statistics.
- (2026-07-09) **The nginx module no longer floods `error.log` with "using uninitialized \"unmask_compose\" variable" warnings.**  Since compose mode became the default on nginx 1.17.6+, the plugin's ACCESS-phase handler reads `$unmask_compose` on every request, but the variable is only `set` inside a protected (compose) location — so any request to a location that does not include the generated `protect.inc` (static assets, the `/unmask/` machinery, an unrelated vhost) made nginx's rewrite module log an "uninitialized variable" warning at WARN, once per request (nginx's `uninitialized_variable_warn` defaults on).  The module now registers `unmask_compose` with a default handler that resolves cleanly to "off", so those requests read it without a warning while compose locations keep their `set` value.
- (2026-07-08) **Forward-auth mode now bypasses the challenge for stats-exclude IPs, matching native module mode — without making them unbannable.**  The native render folds `stats_exclude_ips` (and the private-networks preset) into the `geo $is_bypass_ip` block, so those IPs skip the challenge; but the forward-auth authcheck's IP-bypass matcher only collected the bypass presets + `bypass_ips` rows, omitting the stats-exclude list.  A monitoring probe from a stats-exclude IP was therefore challenged (HTTP 403) on a forward-auth host but passed (200) on the native hosts — a permanent monitoring false-positive on the one forward-auth node.  The forward-auth challenge matcher now derives its set from the same stats-exclude list the native `$is_bypass_ip` block uses.  The ban allowlist stays deliberately narrower (presets + `bypass_ips` only): stats-exclusion is a dashboard filter, not a ban-policy grant, so a stats-exclude IP still skips the challenge yet remains bannable and enforceable by community-ban feeds — turning on the private-networks preset no longer makes the whole RFC1918 space unbannable.

### Added
- (2026-07-14) **The dashboard shows what the Community Bans feed actually stopped.**  A new card reports how much traffic the hub-derived bans blocked on this install over the past 30 days, so the feed's value is visible rather than assumed.  The figures come from a cached background pass (refreshed on an interval, served from memory) — the underlying query walks every serve row in the window and would be far too slow to run on page load.

### Changed
- (2026-07-14) **The bot-hunt log lets you pick how many rows to show**, and the challenge page's "protected by unmask" credit now sends Japanese visitors to the Japanese landing page instead of the English one.
- (2026-07-10) **The stats page's data-source badge now explains itself.**  Three cards (CAPTCHA reuse, cookie pass status, and the 30-day trend) are fed from nginx's access log rather than the per-request challenge events, and were marked with a terse "🗄 access log → DB" badge that read as jargon.  The badge now says "from access log" and hovering (or keyboard-focusing) it opens a popover describing the pipeline per mode: in native mode nginx ships the access log to unmask over syslog, which trims it to the fields it needs and stores the aggregate in the database (only while the feed is on — Settings → retention); in forward-auth mode the same counters arrive through the decision requests.  It also notes that turning the feed off only zeroes these cards and never affects challenges, the bot hunt, or verdicts.  Compose (limit_req in dry-run + the plugin's ACCESS-phase composition, so a deny zone wins over a protected-path challenge that the classic REWRITE-phase gate would otherwise pre-empt) needs both `limit_req_dry_run` (nginx 1.17.1) and the `r->main->limit_req_status` field the plugin reads (nginx 1.17.6) — so the gate is **nginx 1.17.6+**.  Previously any deny zone rendered compose regardless of the target nginx, so a deny zone on older nginx (e.g. CentOS 6's 1.10.3) emitted a directive that fails `nginx -t` — a latent outage on the next reload.  Now the daemon probes `nginx -v` once at startup: nginx ≥1.17.6 renders compose (uniform deny-first semantics for every install), older nginx renders classic (never emits the unsupported directive).  A new `nginx.rate_compose_mode` (`auto` / `always` / `never`) overrides the probe; `auto` (default) falls back to classic when nginx can't be detected (an admin-only box), which is valid everywhere.  `unmask doctor`, the `serve` startup self-check, and `render-nginx` warn when a deny zone can't fully compose on the host nginx, attributing it to the actual cause (old nginx / nginx not on PATH / `rate_compose_mode=never`) rather than always blaming the version.
- (2026-07-08) **`unmask events` now prints a `reason=` column** (the challenge force-reason from the event payload: `rate_limit` / `ja4_bot` / `honeypot` / `banned` / `protected` / `test` / `none`).  The tail/dump output previously showed only phase / verdict / flags, so a rate-limit block was indistinguishable from a baseline "no `_bv` cookie" challenge at the CLI — both render as a 403 serve.  With the column, `unmask events --since 0 | grep reason=rate_limit` counts rate-limit blocks straight from the shell.  (The dashboard already had a dedicated rate-limit card; this closes the same gap for the CLI.)  When a row carries no force-reason it falls back to the payload's general `reason` field, so roaming-rebind rejects (`ja4_mismatch` / `asn_veto`) surface their cause instead of a bare `-`; the `force_reason` field is now populated consistently across the SSE, paged, and `--ref` event endpoints (previously only the SSE stream carried it).

## [0.1.4] — 2026-07-08

### Added
- (2026-07-05) **Stats-exclude "private networks" preset.**  The stats-exclude section (network bypass-IPs tab) gains a default-off preset that drops RFC1918 / loopback / link-local addresses (IPv4 + IPv6, not CGNAT) from statistics in one click, shown with the same preset / custom badges as the other lists.  Off by default on purpose: stats-exclude also bypasses the challenge, so an intranet site whose real users come from private addresses would lose protection and vanish from stats — the operator opts in only on an internet-facing site to drop internal-monitoring noise.
- (2026-07-04) **`unmask doctor` probes :80 as a load-balancer health checker and warns on a redirect.**  When `https_redirect` is on it sends a `GoogleHC`-user-agent request with no `X-Forwarded-Proto` (like a real LB probe reaching the backend directly) and warns if it comes back 301/302 -- a redirect to a health check is a failed check, so the LB drops the node.  Silent with the load-balancer-health exemption on (the default); fires only when that exemption was turned off.

### Changed
- (2026-07-05) **Custom IP / host list fields are now structured rows, not newline textareas.**  The admin-IP allowlist, admin-host allowlist, metrics allowlist, stats-exclude list, and defined-sites list each become an add/delete row list (one value per row), matching the whitelist-IP / bypass-path style.  The rate-limit zone paths (a compact cell in the zone table) and the Privacy-Pass issuer key (a multi-line key blob) stay as textareas — they are not standalone value lists.
- (2026-07-04) **Network-tab wording fixes.**  The IP-geo "not loaded" hint pointed at the wrong side ("the button on the right" -> "on the left"; the download button is to its left), and the trusted-LB custom-row placeholders now localize (the technical tokens CIDR / X-Client-JA4 stay as-is).
- (2026-07-04) **The last row of a custom rule list can now be deleted.**  Every rule list (bypass paths, trusted-LB extras, redirect exemptions, honeypot / protected paths, UA extras) used to keep one cleared row when the operator deleted the final entry, which read as a stray entry that could not be removed; an empty list is a legitimate state, and the Add button below each list starts a new one.
- (2026-07-04) **The HTTPS-redirect exemptions now use the same preset / custom two-badge layout as the trusted-LB section**, and the trusted-LB custom list no longer opens with a blank row by default (click Add to insert one).

### Fixed
- (2026-07-05) **The "already BANned" pill was clipped in the hunt raw-log table.**  The events table uses `table-layout:fixed` with the wrapper's horizontal scroll disabled, and the actions column was 4rem — too narrow for the ~6rem pill, so its right edge was cut off.  Widen the column to fit.  The pill label also moves to the i18n catalog (Japanese "BAN 済み"), replacing the hardcoded English.

## [0.1.3] — 2026-07-04

### Fixed
- (2026-07-04) **The theme-tab preview showed the actual site instead of the challenge for operators who had already passed it.**  The preview iframe loads `/unmask/challenge/?_preview=1`; the silent roaming-rebind guard in the challenge handler excluded the forced / rate-limit / `_test_ja4` paths but not `_preview`, so an operator whose browser carried a valid `_bvj` cookie hit the rebind path, whose page does `location.replace("/")` — navigating the preview iframe to the site.  Exclude the preview path from the rebind guard.
- (2026-07-04) **The over-block banner showed a literal `&mdash;` entity.**  The banner renders through the escaping template pipeline (unlike the safeHTML popovers), so the HTML entity was shown verbatim; use the literal em dash.

### Added
- (2026-07-04) **Configurable HTTPS-redirect exemptions (`nginx.https_redirect_exempt`).**  Requests that must not be 301'd now render as rewrite-phase `break`s before the redirect.  Two presets ship default-on: ACME HTTP-01 (matched by path) and load-balancer health checks (matched by user-agent: `GoogleHC` / `ELB-HealthChecker` / `kube-probe` / Azure).  Health probes reach the backend directly without `X-Forwarded-Proto`, so an un-exempted redirect 301s them — and a 301 is a failed health check, which drops the node from the LB (a silent traffic + stats outage, the way `https_redirect` on a GCP-fronted node stopped recording).  Custom rows on the network tab add either a path (`$request_uri`) or a user-agent (`$http_user_agent`) exemption, preset-checkbox style — no free-text list.
- (2026-07-04) **A preview-language selector on the theme settings tab.**  The theme card iframes previewed the challenge in the operator's own browser language only; a dropdown (all 18 shipped locales, native names) now lets them preview any locale.  It passes `_preview_lang` to the challenge iframes and the force-* preview links; `challenge.js` honors it only in a preview context (`?_preview=1` or an `/admin/test/` path), so a real visitor's path / Accept-Language detection is unchanged.
- (2026-07-04) **`unmask doctor` warns when `nginx.https_redirect` is enabled but the rendered `server.inc` has no 301 block** (the setting was turned on without re-rendering) — the same stale-render class as the existing bv_secret check.

## [0.1.2] — 2026-07-03

### Added
- (2026-07-03) **HTTP → HTTPS redirect option (`nginx.https_redirect`, off by default).**  Emitted at the very top of the rendered `server.inc`, so a plaintext request leaves with a 301 before the ban / honeypot / challenge gates see it — a no-TLS request carries no JA4, and challenging it would only record (and possibly ban) JA4-less rows.  Keys off `$unmask_forwarded_proto` (X-Forwarded-Proto behind a terminating LB, `$scheme` on a direct edge) so both topologies work, and exempts ACME HTTP-01 paths so webroot certbot renewals keep working.  Configurable from the network settings tab.
- (2026-07-03) **Bypass-path presets now declare per-preset factory defaults.**  Machine-access presets (ACME, robots.txt, health checks, browser metadata) default ON so a fresh install doesn't silently break them; anything that could plausibly be a protection target stays OFF.  The config stores only deviations from the default (enabled and disabled lists), presets added by an upgrade stay inert until the operator has seen them, and the renderer and the admin-side check share the same resolution.
- (2026-07-03) **A guard test for undefined `$unmask_*` template variables.**  nginx expands an undefined variable to the empty string without erroring, so a map removed while its uses remain silently no-ops the feature that referenced it — `nginx -t` and the render tests both stay green.  The new test cross-checks every referenced variable against the template and C-module definitions.

### Fixed
- (2026-07-03) **The access-log parser dropped `hpuri` and `ua` on TLS-resumption lines.**  `$effective_ja4` renders as `-` when the handshake yields no fingerprint; the parser's ja4 charset refused that, and the sequential regex chain then un-anchored every later field — so a resumption-visit honeypot ban lost its trip URL and UA.  The placeholder is now accepted and normalized to the internal "no fingerprint" value.
- (2026-07-03) **The events table stacked a native tooltip on top of the datetime popover.**  The shared datetime formatter sets a local/UTC `title` on every cell; the popover shows the same detail, so the title is stripped on cells that carry it.  The popover also gains Host / Port rows.
- (2026-07-03) **The sites tab implied DEFINED acceptance mode limits recording.**  Reworded: events are recorded for every Host in either mode — the mode only affects display (picker suggestions and ghost detection).

## [0.1.1] — 2026-07-02

### Fixed
- (2026-07-02) **A `remove`→`install` or reinstall of the package could leave the admin daemon running the old, deleted binary, causing an admin-UI redirect loop.**  The main postinstall now ends every init path (systemd / openrc / sysv) with a final-guarantee restart, so upgrade / reinstall / remove-install always converges on the new binary — `try-restart` alone is a no-op when the unit is inactive, and `enable --now` cannot always start a unit a prior remove left in an odd state.  Found by dogfooding the unmask.sh install.
- (2026-07-02) **`protect.inc` included at *server* scope (rather than inside a `location {}`) self-DoS'd the site.**  At server scope the challenge gate's rewrite runs before location selection and also caught the `/unmask/` machinery (`/unmask/api/verify`, `challenge.js`), so the challenge could never complete and every human looped — while bots still got 403, making it look like it was working.  `protect.inc` now exempts the `/unmask/` machinery via a negative-lookahead that keeps `/unmask/admin/` protected (admin is guarded by its own `location ^~ /unmask/admin/`).  `unmask doctor` also gained a check that warns when `protect.inc` is included at server scope.  New e2e scenario 48 asserts a server-scope include keeps the machinery alive while the site body stays challenged.
- (2026-07-02) **The plugin postinstall printed `WARNING: unrecognized libcrypto` on nginx built against a statically-linked OpenSSL** (e.g. `--with-openssl=`), where `ldd nginx` shows no libcrypto SONAME.  Detection now falls back to `nginx -V`'s "built with OpenSSL X" and then to the newest system libcrypto SONAME, warning only when all are inconclusive (LibreSSL / BoringSSL fall through to the SONAME probe instead of being mis-detected as OpenSSL).

### Added
- (2026-06-28) **Apache forward-auth now captures and LB-gates a forwarded JA4, at parity with nginx; the dead `ja4_source` / `trusted_forward_auth_proxies` settings are gone.**  `apache-unmask.lua` already forwarded a front LB's `X-Client-JA4` to the daemon, but nothing verified the JA4 actually arrived via a trusted LB, so a client reaching Apache directly could forge one.  The lua now also forwards the real connecting peer as `X-Unmask-Conn-Peer` — a per-vhost `mod_rewrite` rule exports `%{CONN_REMOTE_ADDR}` (the raw TCP peer, which `mod_remoteip` does not rewrite) into `UNMASK_CONN_PEER` — and the daemon (`resolveForwardedJA4`) honors the forwarded JA4 only when that peer is a configured trusted LB (`nginx.trusted_lb_presets` / `trusted_lb_extra`, the same list nginx uses).  So a forged JA4 from a non-LB client is dropped server-side, no operator header-stripping needed; nginx's rendered `forward-auth-lbtrust.conf` edge-gate strips `X-Unmask-Conn-Peer` since it gates at the edge instead.  The `nginx-forward-auth.conf` reference snippet and the `apache-unmask-auth.sh` CGI fallback gained the same `X-Unmask-Conn-Peer` forwarding, and the `ja4_source=header` / `trusted_forward_auth_proxies` references they carried — config keys never implemented in Go — were removed (the trusted-LB list has been the real mechanism since the `trust_forwarded_ja4` removal).  New e2e: scenario 42 drives a stock-nginx forward-auth vhost end-to-end (no plugin), and scenario 14 gained Apache JA4-capture cases.
- (2026-06-27) **The native plugin now emits a `q`-prefix JA4 for HTTP/3 (QUIC) requests instead of the TCP/TLS `t` prefix.**  A modern browser presents a different JA4 over QUIC than over TCP, and the JA4 spec marks the transport in the first byte, so labelling an HTTP/3 ClientHello as `t…` mis-fingerprinted every QUIC visitor.  The module flips `t`→`q` when the request rides a QUIC stream (`r->connection->quic != NULL`, the same marker nginx uses for HTTP/3); the rest of the JA4 (ciphers / extensions / ALPN) is transport-independent and already reflects the QUIC transport-parameters extension.  Guarded to nginx ≥ 1.25 built with QUIC or `--with-compat` and compiled out where HTTP/3 cannot be served, so `t` stays correct on older nginx.
- (2026-06-26) **Privacy Pass / Apple Private Access Token verification — an attested real client can skip the challenge.**  unmask now acts as a Privacy Pass *origin* (token verifier, never the issuer or attester): a client presenting a valid Private Access Token — most commonly an Apple device — is passed through with no PoW / CAPTCHA.  Only the publicly verifiable token type `0x0002` (Blind RSA 2048-bit, RFC 9577 auth scheme + RFC 9578 issuance) is supported, its RSASSA-PSS authenticator checked against a trusted issuer's public key with no issuer secret involved; well-known PAT issuers ship as default-off presets.  Pure-Go (no CGO), opt-in via its own `enabled` flag AND gated behind the Advanced master switch (see Changed), so it is inert — and the rendered nginx config byte-identical — until an operator opts in.
- (2026-06-22) **`trust_forwarded_ja4` is now a network-tab checkbox for forward-auth mode.**  In forward-auth mode nginx forwards a client-sent `X-Client-JA4` to `/api/check` verbatim, so a trusted (loopback) *peer* does not make the *value* trustworthy — a client can spoof a benign JA4 — which is why honoring it is a separate opt-in from the trusted-LB list.  That opt-in was previously `config.yml`-only while the trusted-peer list it pairs with was already a UI control; the LB card now carries the checkbox so forward-auth is fully UI-driven, with help text that leads with the peer-trust-vs-value-trust subtlety.  Read at request time, no render / reload.
- (2026-06-20) **Custom `[from,to]` date range on the stats dashboard, the hunt page, and the three daily-bucket queries.**  These views were fixed windows (e.g. last-N-days), so an operator investigating a past incident could not scope the dashboard or hunt to the day it happened.  An in-page range modal with a data-aware preset list now drives all of them, and the custom-range trigger renders as a preset-matching button so the active window is obvious.
- (2026-06-19) **Two CAPTCHA watchlist cards: a pass report and a cookie-reuse ranking.**  The dashboard now surfaces who *cleared* the CAPTCHA and which `_bv` cookies are reused across many IPs, grouped into the watchlist section with the standard show-more ranking affordance.  These are investigative signals, not verdicts — passing a CAPTCHA is not proof of a bot (Edge / corporate-proxy users legitimately cluster here), so the cards lead the operator to inspect rather than auto-conclude, and the verdict cells carry their explanation popover.
- (2026-06-19) **Roaming-rebind refusals are now visible in the hunt log.**  A silent `_bv` rebind that was *refused* (cross-ASN, JA4 mismatch, or per-lineage cap exhausted) previously left no trace, so a roaming client that got re-challenged instead of rebinding was impossible to diagnose.  Every refusal is now recorded as a `bv_rebind_reject` event carrying the reason plus the JA4 and original path, surfaced in the hunt log (the internal "veto" was renamed "reject").  This instrumentation is what surfaced the HTTP/2↔HTTP/3 false-positive fixed below.
- (2026-06-19) **Unix-socket admin bind is now fully operator-usable.**  When `socket_group` is empty the daemon auto-detects the web server's group (probing `nginx` / `apache` / `www-data` / `http` / `www` and warning if several exist) instead of hard-coding `nginx`, which broke Apache / `www-data` hosts.  `socket_mode` supports `0660` (group-only, recommended on shared hosts) and `0666` (setup-free — any local process can connect), and the admin now trusts the socket peer's forwarded `X-Real-IP` so `admin_allowed_ips` works over a socket (the web server in front sets the header; access is gated by the socket file's permissions, the same posture as gunicorn / nginx `set_real_ip_from unix:`).
- (2026-06-18) **Support "Ref ID" correlation id on every challenge / deny / ban page, with a reverse lookup.**  A blocked or looping visitor had no way to tell the operator *which* request to investigate, and the operator had no hook from a "I'm blocked" report back to the decision that produced it.  Each served page now prints a short, human-quotable Ref ID in its footer (16 hex / 64 bits, matching Cloudflare's Ray ID; hex to avoid 0/O, 1/l transcription traps) and stamps it on the serve event.  `unmask events --ref <id>` and the hunt page's Ref search resolve a reported id to the exact serve event and its decision context (verdict / flags / ip / ja4 / path).  No schema change — it rides `payload_json`.
- (2026-06-18) **Branded "blocked" deny page across native, nginx forward-auth, and Apache.**  A deny-action ban used to be a bare nginx `return 403` (no branding) while only rate-limit deny got a page; both now render a themed, localized deny shell.  The page has a light / dark / auto theme picker (a live preview-card grid in a dedicated "Page design" settings section), and a rate-limit deny — which clears once the client slows down — carries friendly / neutral / minimal copy presets and invites a retry, while a ban deny uses a single hard-block "blocked" tone (a persistent block needs no friendly spread), in 18 languages.  A dedicated `/unmask/_ban` location fails *closed* (403) during a daemon outage so a ban holds, and `/unmask/*` is ban-blanked so the rewrite cannot loop.
- (2026-06-17) **Native rate-limit "deny mode" — a hard cap that returns 403, and a valid `_bv` does not buy past it.**  A deny-mode zone is now a hard cap: over the limit it serves a 403 deny page, not a recoverable challenge.  A valid `_bv` (the visitor already passed a challenge) still exempts a client from *challenge*-mode zones, but it must NOT exempt a human who passed CAPTCHA from a deny zone — flooding is flooding — so deny zones count `_bv` holders; only trusted sources (bypass IP / verified search bot / signed agent) stay exempt.  On a protected path, where stock OSS nginx can't reorder phases the way NGINX Plus does, a new "compose mode" runs `limit_req` in dry-run and lets the plugin's ACCESS-phase handler compose the two axes (over-cap → deny, within-cap → captcha gate), so the deny zone correctly beats the protected captcha; non-deny configs keep the classic flow byte-for-byte.  Composes the same way in forward-auth mode, where the daemon already evaluates both axes.  The native protected-path compose uses `limit_req`'s `dry_run` (nginx 1.17.1+); on older nginx that one path is compiled out and every other axis is unaffected, so the module still builds and runs the full 1.10.3–1.30.0 fat-plugin range.
- (2026-06-14) **The `_bv` cookie and the native rate-limiter now bind to the IPv6 /64, not the full /128.**  IPv6 privacy extensions (default on iOS / Android / Windows / macOS) rotate a client's address within its /64 several times a day, so a /128 binding re-challenged on every rotation and let a v6 client multiply its rate budget by hopping source addresses.  Both layers now fold a pure-IPv6 address to its /64 (IPv4 and IPv4-mapped addresses are unchanged, so v4 `_bv` cookies stay byte-identical and never re-mint), so all of a client's rotating addresses count as one client.  The Go issuer and the C verifier are pinned together by fixed parity vectors in the `_bv` parser fuzz target; a v6 /64 is typically one device, so the replay surface barely widens while the re-challenge rate drops sharply.
- (2026-06-14) **Per-crawler drill-down on the AI / crawler card.**  The card grouped traffic by category (search / AI-training / …) with no way to see which individual crawler drove a category.  Each category tag now drills down — on hover or click — into a popover listing the individual crawlers behind it, each with a trend sparkline; per-crawler traffic is recorded hourly to back it, and crawler names that begin with a regex construct now resolve to a readable label.
- (2026-06-14) **Fuzz harnesses for the JA4 string builder and the `_bv` cookie parser.**  Both were extracted into standalone units with fuzz targets (ASan / UBSan, run in CI), so a malformed ClientHello-derived JA4 or a hostile `_bv` cookie cannot crash or corrupt the native plugin — the parser is the most exposed attacker-controlled surface in the module.  The `_bv` parser unit also doubles as the parity anchor that keeps the C verifier and the Go issuer in lockstep.
- (2026-06-14) **In-app update check, a low-key About tab, and a published `releases.json` update feed.**  The admin now checks for a newer release against a `releases.json` feed published alongside the repo (default on, 12-hour cache, non-blocking, toggleable from About) and surfaces the latest version, an update history, and the correct per-distro update command, so an operator learns about a security release without watching the repo.  Version / credit moved off the settings overview into a dedicated About tab under the Community group.
- (2026-06-13) **Superadmin reconfigure wizard — re-run setup to switch the database.**  `/admin/setup/` is now re-runnable on an already-configured install so an operator can change the DB connection through the wizard instead of hand-editing `config.yml`.  Once an admin exists the bootstrap setup token is gone, so the reconfigure path is gated by superadmin auth (IP allowlist + session + role) with CSRF on the POSTs; it pre-fills the current DB info, shows the target DB's record counts and an accurate "switching backends keeps the old DB and does not copy data" warning, always runs the idempotent non-destructive Migrate (adopts / creates, never wipes), and skips the admin-user step when the target DB already has one.
- (2026-06-13) **Every table and column now carries a DB comment in both dialects.**  The base schema, the numbered-migration tables, and the `schema_migrations` version-history table now ship `COMMENT` clauses on MariaDB and trailing `--` comments on SQLite, so an operator inspecting the database directly finds the schema self-documenting rather than having to cross-reference the Go models.
- (2026-06-13) **Branded `/dl/` landing page, a Japanese landing, and a themed download index.**  `unmask.sh/dl/` is now a custom branded browse page (the install steps moved out) with a Japanese landing under `/ja/dl/` that auto-deploys with the rest of the site; the autoindex sub-directory listings are themed, with icon type badges and full-cell click targets, and the raw listing is hidden before paint to kill the flash-of-unstyled-content.
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
- (2026-06-15) **Dropped Traefik as a shipped integration — nginx and Apache only.**  Removed the `traefik-forward-auth.yml` snippet and its packaging entry, plus every README / UI / docs mention that presented Traefik (and the HAProxy / Envoy enumerations) as a supported, shipped integration, since only nginx and Apache are integration-tested end-to-end.  Forward-auth itself stays HTTP-server-agnostic: `/unmask/api/check` still speaks the standard `200/401/403` + `X-Unmask-Action` / `X-Unmask-Reason` contract, so Traefik's `forward_auth` — like Envoy `ext_authz` or HAProxy — can still be wired by hand; it is simply no longer a shipped, documented sample.  Completes the Caddy removal earlier this cycle, which had left the Traefik sample in place.
- (2026-06-12) **Dropped Caddy support** (the `unmask-web-caddy` package,
  the shipped `Caddyfile-forward-auth` snippet, and every install-path /
  docs / UI mention) to keep the supported-surface honest about what is
  actually maintained and exercised — the install matrix covers nginx and
  Apache end-to-end, while the Caddy artifacts were never integration-tested.
  Forward-auth itself is unchanged and HTTP-server-agnostic: `/unmask/api/check`
  still speaks the standard contract (200/401/403 + `X-Unmask-Action` /
  `X-Unmask-Reason`), so Caddy's `forward_auth` — like Envoy `ext_authz` or
  HAProxy — can still be wired against it by hand; it is simply no longer a
  shipped, documented integration.  The Traefik sample config remains.

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
- (2026-06-28) **Forward-auth JA4 trust is now driven by the trusted-LB list, and the `trust_forwarded_ja4` toggle is gone.**  Previously forward-auth honored a forwarded `X-Client-JA4` only when an operator flipped a separate opt-in, because a trusted (loopback) *peer* does not make a client-supplied *value* trustworthy.  unmask now gates the value in nginx instead: `render-nginx` emits `forward-auth-lbtrust.conf` (a `geo`/`map` chain keyed on `$realip_remote_addr`, the same source native's http.inc uses) that resolves `$unmask_fa_ja4` to the real client JA4 only when the request's original peer is inside a configured trusted-LB range and `""` otherwise; the shipped `forward-auth/server.inc` forwards that gated variable to `/api/check`.  So a direct visitor's spoofed JA4 is dropped at the edge, the daemon trusts only a value that reached it through the local proxy, and `nginx.trusted_lb_presets` / `trusted_lb_extra` is the single source of truth for both modes — one setting, no toggle.  The unmask-web-nginx postinstall auto-wires the new file (a no-op `default ""` ships so `nginx -t` passes before the first render).
- (2026-06-26) **Web Bot Auth and Privacy Pass are now behind an Advanced master switch, off by default.**  `nginx.advanced_enabled` reveal-gates both standards-based feature tabs and `AND`s with each feature's own `enabled` flag, so when the switch is off the features are not just hidden but inert (`WebBotAuthActive` / `PrivacyPassActive` are false regardless of per-feature config, which is preserved for re-enabling), and the rendered nginx config is byte-identical to before.  Both are low-adoption today, so this keeps the default operator surface simple while letting anyone who wants them opt in explicitly.
- (2026-06-26) **The admin settings and challenge copy were rewritten in native Japanese.**  The Japanese strings were rewritten away from translation-ese into natural phrasing, with technical and product terms (JA4 / PoW / CAPTCHA / bot) kept in English; no behavior change, but the UI reads as written-in-Japanese rather than machine-translated.
- (2026-06-19) **Default raw-event retention dropped from 90 to 30 days.**  The dashboard keeps its own ≤30-day aggregate and hunt is capped at 24 hours, so raw events older than 30 days only serve `--ref` lookups and audit — 90 days of raw rows was mostly dead weight on the database.  The retention intro was rewritten (ja / en) to explain why 30 days is the sweet spot, and the current-size rows now annotate the oldest timestamp with an "N days ago" hint so an operator can read the age at a glance.
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
- (2026-06-19) **`ja4_mismatch` false-positives from HTTP/2 ↔ HTTP/3 drift on roaming rebind.**  A real browser presents a different JA4 over HTTP/2 (TCP) than over HTTP/3 (QUIC) — they differ in every field — and the single-JA4 `_bvj` refused a silent rebind on whichever transport it had not been minted under, so on `tool1-jp` (~300 rejects/day, 0 bots over 7 days) a large share of authenticated roaming rebinds fell through to a needless challenge.  `_bvj` now stores a `~`-joined set of JA4s — one appended per transport, capped at 3 — and matches any member, and a non-bot verdict soft-passes.  Go-only; the native C plugin never parses `_bvj`.
- (2026-06-19) **Stats queries warn instead of returning a silent zero on timeout.**  A dashboard query that hit its deadline used to return 0, which an operator reads as real data ("no traffic in this window") rather than "couldn't compute it" — actively misleading.  The overview, sites, retention, and AI cards now detect the timeout and show a warning or "—" instead of a fabricated zero, and a slow retention `COUNT(*)` on a large database no longer times out and hides the entire retention size card (its budget was raised and made independent of the DB-size probe).
- (2026-06-18) **A roaming `_bvj` whose fingerprint had drifted stranded the holder on repeated PoW.**  `IssueBVJ` treated any signature-valid `_bvj` as "present" and skipped re-minting, so a cookie minted under an old fingerprint kept verifying there but was rejected by the rebind's JA4 / UA match on every roam — PoW after PoW with no escape.  It now re-mints whenever the stored JA4 + UA no longer match the current connection, refreshing a fingerprint-stale cookie on the next solve, while keeping the *full*-JA4 roaming match (a brief JA4-prefix experiment was reverted as too weak a fingerprint).
- (2026-06-15) **The Daily-Unique-IPs card timed out on large databases.**  It merged every per-minute HLL sketch in Go — about 65k rows / 67 MB for the 30-day view — which took ~15s under pure-Go SQLite and tripped the card's query timeout.  The per-minute IP sketches are now pre-merged into hourly sketches by the same 60s aggregate goroutine (backed by a new index), and the card splits the window at the rollup cursor: settled hours come pre-merged (~24/day) and only the short tail after the cursor is read live, so it reads ~720 hourly sketches plus a tail instead of 65k rows and current hours never lag.
- (2026-06-15) **Two `nginx -t` failures from unmask's rendered config.**  unmask's many maps (rate-limit, per-site honeypot / bypass / protected, the challenge axes) push the variable count past nginx's 1024 default, which logged a "could not build optimal variables_hash" warning on every reload; it now emits `variables_hash_max_size 2048` / `variables_hash_bucket_size 128`.  And it now skips the community-bans `map_hash_*` directives when the host `nginx.conf` already opens a `map` / `geo` block before the unmask include (Alpine 3.23's stock conf opens `map $http_upgrade` first, making the directive a *fatal* duplicate that silently tripped the placer's fail-safe and disabled native mode).  Both emissions are guarded against duplicating an operator-set value.
- (2026-06-13) **Several setup-wizard papercuts.**  Pressing Enter on a field no longer triggers the Skip button, a client-side password-match check was added, a duplicate username is now rejected at the user step instead of failing at install, the entered username survives a validation error, validation errors are localized (ja / en), and skip-user is only offered when the target DB already has an admin.
- (2026-06-13) **Admin authentication hardening (several low-severity items).**  The session signature widened from 64-bit to 128-bit (and the verify length-gate was fixed in the same change so cookies actually validate — it had briefly broken login); the setup password is now hashed with argon2id the instant the user step is submitted, so the plaintext never outlives the request instead of sitting in memory for the wizard's TTL, and a stored hash is transparently re-hashed on login when the cost parameters rise; reset-token consumption is now an atomic conditional `UPDATE` so the same token cannot be redeemed twice; and an unknown / empty role now denies instead of admitting everyone.
- (2026-06-13) **Data-integrity and input-sanitization hardening.**  A `UNIQUE` index on user email enforces one account per address (so forgot-password can't act on an ambiguous lowest-id match; existing duplicates are logged and skipped rather than failing startup); a manually-banned `ip` / `ja4` now rejects `|` and newline so it can't corrupt or smuggle a line of the flushed ban file; operator directory paths are sanitized before they're written into an nginx `include`; community-bans feed free-text is length-capped; logo upload is atomic (`tmp` + rename) so the serve never reads a half-written file; and feed-URL logging strips `user:token@` userinfo.  `unmask doctor` also now warns when the admin IP or Host allowlist is empty.
- (2026-06-13) **The challenge primitives are hardened against replay and overflow.**  The CAPTCHA math token is now IP-bound with a 15-minute freshness window, so a solved `(answer, token)` pair can no longer be replayed across IPs or after expiry; an auto-generated `_bv` secret is persisted to a `0600` sidecar so the `render-nginx` CLI and the daemon converge on one signing key (a per-process key made render and verify disagree and looped every visitor); the native `ngx_unmask_atoll` cap dropped to 18 digits to remove an int64 sign-overflow on a hostile 19-digit input; and the rate-limiter now measures its window on the monotonic clock (an NTP step can't move the window backward and corrupt counts) with a hard map cap that evicts the oldest keys so a key-rotation flood can't grow memory unbounded.
- (2026-06-13) **The admin web surface is hardened against XSS and cookie leakage.**  An uploaded SVG logo now ships a strict `default-src 'none'; sandbox` CSP, so a script-carrying logo opened at its top-level URL can't execute; the challenge page's unauthenticated preview overrides (`_preview_site_name` / `_preview_footer_text`) are now gated on a same-origin `/admin/` referrer, so a phishing link can no longer rewrite the visible site name or footer; the pinned info-tip clone copies node-for-node instead of through `innerHTML`; the admin flash cookie carries `Secure` on an HTTPS admin; and event-payload field extraction is escape-aware, so a value containing an escaped quote can no longer truncate and corrupt the extracted string.
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
- (2026-06-12) **The live settings hot-swap is now race-free.**  The web
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

- (2026-05-07) **Fixed `admin_allow_from` IP restriction having no effect**.
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

- (2026-05-07) **Fixed JA4 / verdict always NULL in check-phase events**.
  In `auth_check.go`, `events.Insert` was missing the `JA4` / `JA4Verdict`
  fields (= the values were already extracted into local variables but not
  passed through). Now check events also record the JA4 hash and verdict, and
  rows that showed "-" in the bot-hunt verdict column are resolved.<br>
  Note: requests where the upstream LB does not provide X-Client-JA4 (= TLS
  resumption, some bot-specific handshakes) remain empty. That is an upstream
  concern.

- (2026-05-07) **Fixed UTC appearing under TZ picker "browser auto"**.
  The production server runs in UTC, and `events.Row.Date` was the server-local
  (= UTC) string. To reformat client-side using the picker's TZ, we needed unix
  seconds. Added an <code>Ts int64</code> field to Row. The hunt raw-log table,
  overview recent, and live-tail SSE now format via <code>data-ts</code> +
  <code>js-datetime</code> using the picker timezone (including browser
  default).

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
- (2026-05-07) **Resolved frequent "(connection error)" on SSE**.<br>
  - Heartbeat 30s → 20s: the default backend response timeout on GCP HTTPS LB
    is 30s, so 30s heartbeats race with LB cutoff. 20s comfortably keeps
    keepalive.<br>
  - In JS onerror, added <code>readyState</code> check: 0 (CONNECTING / auto
    retry) is shown discreetly as "(reconnecting)". Only 2 (CLOSED / true end)
    shows "(SSE connection error)". EventSource auto-retry is normal behavior;
    users shouldn't think it's broken.

- (2026-05-07) **Live-tail lightening, round 2**, on the hunt tab. Three
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

- (2026-05-07) **Lightened live tail under high traffic** on the hunt
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

- (2026-05-07) **Tabbed the docs page** (= overview / install / help /
  faq). The install guide moved out of the standalone nav into the
  <code>/admin/docs/?tab=install</code> sub-tab. The help tab has a shortcut
  grid to other tabs / settings; the faq tab has 8 Q&amp;A items ("JA4
  empty?", "what's stealth?", "are verdict names free-form?" etc.). More
  help / faq items planned.<br>
  The old <code>/admin/install/</code> URL 301-redirects to
  <code>/admin/docs/?tab=install</code>. The "Install" link in all-page nav
  was removed (one less link is one less link).

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
