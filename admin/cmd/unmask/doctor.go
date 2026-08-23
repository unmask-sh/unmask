// `unmask doctor` — self-check right after install / upgrade.
//
// Each check reports one line of [OK] / [WARN] / [ERR].  Prints a summary at
// the end; if any [ERR] is present, exits with code 1 (= machine-checkable
// from automation).
//
// Checks:
//  1. config.yml is readable / parses
//  2. nginxconf.Render() dry-run succeeds
//  3. DB pings + the major tables exist
//  4. If the IP-geo mmdb path is set, the file is readable
//  5. The dir of ban_file_path is writable
//  6. If challenge_html_path is set, the file is readable
//  7. challenge cookie validity windows are sensible
//  8. nginx output_dir is writable
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	iofs "io/fs"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/unmask-sh/unmask/admin/assets"
	"github.com/unmask-sh/unmask/admin/internal/browsermajors"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

type doctorCheck struct {
	level   string // "ok" | "warn" | "err"
	title   string
	message string
}

func (c doctorCheck) String() string {
	mark := "[OK]"
	switch c.level {
	case "warn":
		mark = "[WARN]"
	case "err":
		mark = "[ERR]"
	}
	if c.message == "" {
		return fmt.Sprintf("%s  %s", mark, c.title)
	}
	return fmt.Sprintf("%s  %s — %s", mark, c.title, c.message)
}

func cmdDoctor(args []string) error {
	fs := flag.NewFlagSet("doctor", flag.ExitOnError)
	configPath := fs.String("config", os.Getenv("UNMASK_CONFIG"), "path to admin.yml")
	if err := fs.Parse(args); err != nil {
		return err
	}

	checks := []doctorCheck{}
	addOK := func(t, m string) { checks = append(checks, doctorCheck{"ok", t, m}) }
	addWarn := func(t, m string) { checks = append(checks, doctorCheck{"warn", t, m}) }
	addErr := func(t, m string) { checks = append(checks, doctorCheck{"err", t, m}) }

	resolved := settings.ResolvePath(*configPath)
	fmt.Printf("unmask doctor (config: %s)\n\n", resolved)

	// 1. load + parse config
	s, err := settings.Load(resolved)
	if err != nil {
		msg := err.Error()
		// config.yml is usually root/admin-owned (it holds bv_secret etc.),
		// so a plain-user run hits EACCES.  Nudge toward sudo rather than
		// leaving the operator to decode "permission denied".
		if errors.Is(err, iofs.ErrPermission) {
			msg += " — try: sudo unmask doctor"
		}
		addErr("config load", msg)
		_ = printSummary(checks)
		return errors.New("doctor failed at config load")
	}
	addOK("config load", resolved)

	// Upgrade review: surface enforcement presets a later release added that are
	// held inert on the "review" policy, so they are not silently off forever.
	// Empty under the "apply" policy or when nothing is held.
	if held := nginxconf.HeldEnforcementPresets(s); len(held) > 0 {
		addWarn("upgrade review", fmt.Sprintf("%d enforcement preset(s) held pending review (inert until acknowledged) — run `unmask upgrade-review` to list and apply them", len(held)))
	}

	// Probe nginx so the render dry-run below (and the daemon) resolve the same
	// rate-compose flow, and flag when a deny zone can't compose on this nginx.
	dryOK, ngxVer, ngxDetected := nginxconf.DetectDryRunSupport()
	if ngxDetected {
		nginxconf.SetDryRunSupported(dryOK)
	}
	switch diag := nginxconf.DiagnoseComposeMode(s, ngxVer, ngxDetected, dryOK); diag.Level {
	case nginxconf.ComposeDiagError:
		addErr(diag.Label, diag.Message)
	case nginxconf.ComposeDiagWarn:
		addWarn(diag.Label, diag.Message)
	case nginxconf.ComposeDiagOK:
		if diag.Message != "" {
			addOK(diag.Label, diag.Message)
		}
	}

	// Load the same hub-pulled state render-nginx loads before rendering: the
	// bypass IP ranges (Googlebot / Bingbot / AI crawlers) and the browser
	// baselines behind the stale-browser tier.  Without this the dry-run below
	// renders from the embedded snapshot alone, which is a different -- and
	// smaller -- conf than the daemon and render-nginx produce.  The freshness
	// check then compared that against the real conf and reported every node
	// that had ever pulled ranges as stale, sending operators to re-render a
	// conf that was already correct.  (Seen in production: a hundred-odd Google
	// range lines missing from a set of several thousand.)
	nginxconf.SetOverrideDir(nginxconf.SyncDefaultDir)
	if err := browsermajors.LoadState(""); err != nil {
		addWarn("browser baselines", fmt.Sprintf("%v (render check falls back to the built-in baselines)", err))
	}

	// 2. nginxconf render dry-run.  Render into a private 0700 temp dir and
	// remove it -- the rendered http.inc carries bv_secret, so writing it into
	// the shared, predictable os.TempDir() (0644) would leak the key to every
	// local user.  (Mirrors render-nginx -dry-run.)
	if tmpDir, terr := os.MkdirTemp("", "unmask-doctor-"); terr != nil {
		addErr("nginx-rendered.conf render", terr.Error())
	} else {
		defer os.RemoveAll(tmpDir)
		if err := nginxconf.Render(s, tmpDir, Version); err != nil {
			addErr("nginx-rendered.conf render", err.Error())
		} else {
			addOK("nginx-rendered.conf render (dry-run)", "")
			// 2c. render freshness: does the conf nginx actually loads match what
			// config.yml renders NOW?  A hand-edit to config.yml that skips
			// `render-nginx` (or the web UI) leaves nginx serving the stale conf --
			// the config change is silently not in effect.  Compare the fresh
			// dry-run to the live output_dir copy, ignoring the generated_at /
			// unmask_version stamp lines (which differ every render even when the
			// substance is identical, so an mtime check would false-positive on a
			// hourly community-bans write-back that re-Saves without re-rendering).
			checkRenderFreshness(tmpDir, s.Nginx.OutputDir, addWarn, addOK)
		}
	}

	// 2b. community-bans map_hash sizing.  When enforcement is active, the ipja4
	// maps need map_hash_bucket_size >= 256 (IPv6 keys ~76 chars).  http.inc emits
	// it unless the host nginx.conf already declares one -- which may be too small.
	if w := nginxconf.MapHashAdvice(s); w != "" {
		addWarn("nginx map_hash", w)
	} else if s.CommunityBans.ApplyActive() {
		addOK("nginx map_hash", "community-bans maps sized (host or http.inc)")
	}

	// 2c. crawler IP-range freshness.  Range-verified crawler UAs (uarange.go)
	// are rescued by their vendor's published IP ranges instead of the UA
	// string, so a range snapshot that stops refreshing eventually challenges
	// genuine crawlers arriving from newly added vendor IPs.  The embed
	// snapshot carries no fetch date (vendors' creationTime can sit for years,
	// e.g. Applebot), so the synced override files' mtime is the signal.
	if inverted := nginxconf.EffectiveUpstreamUAOff(s.Nginx); len(inverted) > 0 {
		need := map[string]bool{}
		for pat := range inverted {
			for _, id := range nginxconf.UARangePresets[pat] {
				need[id] = true
			}
		}
		var missing []string
		var oldestID string
		var oldest time.Time
		for i := range nginxconf.BypassIPGroups {
			g := &nginxconf.BypassIPGroups[i]
			if !need[g.ID] {
				continue
			}
			fi, err := os.Stat(filepath.Join(nginxconf.SyncDefaultDir, filepath.Base(g.File)))
			if err != nil {
				missing = append(missing, g.ID)
				continue
			}
			if oldest.IsZero() || fi.ModTime().Before(oldest) {
				oldest, oldestID = fi.ModTime(), g.ID
			}
		}
		sort.Strings(missing)
		const staleAfter = 30 * 24 * time.Hour
		switch {
		case len(missing) > 0:
			addWarn("crawler IP ranges", fmt.Sprintf(
				"%d crawler UA pattern(s) rely on vendor IP ranges, but these presets have never been synced (serving the compiled-in snapshot): %s. Check the daemon log for 'iprange sync' errors; a stale snapshot can eventually challenge genuine crawlers from new vendor IPs.",
				len(inverted), strings.Join(missing, ", ")))
		case time.Since(oldest) > staleAfter:
			addWarn("crawler IP ranges", fmt.Sprintf(
				"synced range files are stale (oldest: %s, %d days) — %d crawler UA pattern(s) rely on them. Check the daemon's iprange sync against %s.",
				oldestID, int(time.Since(oldest).Hours()/24), len(inverted), nginxconf.SyncDefaultHubURL))
		default:
			addOK("crawler IP ranges", fmt.Sprintf(
				"%d preset(s) back %d range-verified crawler UA pattern(s); oldest sync %dd ago",
				len(need), len(inverted), int(time.Since(oldest).Hours()/24)))
		}
	}

	// 2d. crawler patterns with no rescue path at all (UA rescue explicitly
	// off AND the backing range presets inactive).  Auto resolution never
	// lands here, so this is always the product of explicit choices — but a
	// genuine crawler is challenged, which usually means an SEO accident.
	if uaOff := nginxconf.EffectiveUpstreamUAOff(s.Nginx); len(uaOff) > 0 {
		var none []string
		for pat := range nginxconf.UARangePresets {
			if uaOff[pat] && !nginxconf.RangePresetsActive(s.Nginx, pat) {
				none = append(none, pat)
			}
		}
		if len(none) > 0 {
			sort.Strings(none)
			addWarn("crawler rescue", fmt.Sprintf(
				"%d crawler UA pattern(s) have NO rescue path (UA rescue off + range presets inactive) — a genuine crawler gets challenged: %s. Re-enable the pattern on the UA-filter tab or the vendor's range preset on the Bypass IPs tab.",
				len(none), strings.Join(none, ", ")))
		}
	}

	// 2d2. feed signature: what the last pull established.  Recorded by the
	// pull itself in snapshot-meta.json -- "the daemon verified a signature"
	// is a fact about that pull, not something doctor can re-derive offline.
	if b, err := os.ReadFile(filepath.Join(nginxconf.SyncDefaultDir, "snapshot-meta.json")); err == nil {
		var meta struct {
			GeneratedAt string `json:"generatedAt"`
			Signature   string `json:"signature"`
		}
		if json.Unmarshal(b, &meta) == nil && meta.Signature != "" {
			if strings.HasPrefix(meta.Signature, "verified:") {
				addOK("feed signature", fmt.Sprintf("last sync verified (key %s, doc %s)",
					strings.TrimPrefix(meta.Signature, "verified:"), meta.GeneratedAt))
			} else {
				addOK("feed signature", fmt.Sprintf(
					"last sync was unsigned (%s) — transport trust only; the hub publishes signatures since 0.1.33", meta.GeneratedAt))
			}
		}
	}

	// 2e. auto address-verification (autobypass.go): say what it derived, and
	// say loudly when it is standing down.  The operator who leaves the
	// feature on believes vendors they pass by UA are being address-verified;
	// a stale snapshot silently returns those vendors to name-only rescue,
	// which is exactly the state this feature exists to end.
	if s.Nginx.BypassIPAutoFromUAEnabled() {
		if ids, dataAt, suspended := nginxconf.AutoBypassSuspended(s.Nginx); suspended {
			addWarn("auto range verification", fmt.Sprintf(
				"suspended: address data is %d days old (ceiling %d) — %d preset(s) fall back to name-only UA rescue: %s. Run `unmask update-iprange` (or -file with an out-of-band copy) and re-render.",
				int(time.Since(dataAt).Hours()/24), int(nginxconf.AutoBypassMaxSnapshotAge.Hours()/24),
				len(ids), strings.Join(ids, ", ")))
		} else if auto := nginxconf.AutoBypassPresetIDs(s.Nginx); len(auto) > 0 {
			ids := make([]string, 0, len(auto))
			for id := range auto {
				ids = append(ids, id)
			}
			sort.Strings(ids)
			addOK("auto range verification", fmt.Sprintf(
				"%d preset(s) enabled from the UA policy: %s",
				len(ids), strings.Join(ids, ", ")))
		}
	}

	// 3. DB ping + tables
	conn, err := db.Open(s.DB)
	if err != nil {
		addErr("DB connect", err.Error())
	} else {
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := conn.PingContext(ctx); err != nil {
			addErr("DB ping", err.Error())
		} else {
			addOK("DB ping", string(s.DB.Driver))
		}
		// Confirm the major tables exist (= a 1-row SELECT without error is OK).
		ctx2, cancel2 := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel2()
		tables := []string{"unmask_event", "unmask_ban", "unmask_user"}
		var missing []string
		for _, tn := range tables {
			row := conn.QueryRowContext(ctx2, "SELECT 1 FROM "+tn+" LIMIT 1")
			var v int
			if err := row.Scan(&v); err != nil && !strings.Contains(err.Error(), "no rows") {
				missing = append(missing, tn)
			}
		}
		if len(missing) > 0 {
			addErr("DB table check", fmt.Sprintf("missing: %s (= run unmask migrate)", strings.Join(missing, ", ")))
		} else {
			addOK("DB tables", strings.Join(tables, " / "))
		}
		// DB write access.  A DB the daemon can read but not write keeps
		// serving challenges (config + HMAC only) while recording NOTHING —
		// empty stats with a healthy-looking gate.  The classic cause is a
		// root-owned unmask.sqlite left behind by running `unmask migrate` as
		// root.  What is provable depends on the backend:
		//   - MariaDB: permissions ride the DSN credentials — the same ones
		//     the daemon uses — so a live no-op write (PK seek, O(1)) is
		//     definitive in both directions, whoever runs doctor.
		//   - SQLite: permissions ride the FILE owner, and doctor's own uid
		//     (root writes anywhere; another user may fail where the daemon
		//     succeeds) makes a live probe misleading — compare the file owner
		//     against the packaged service user (unmask) instead, which is
		//     definitive regardless of who runs doctor.
		if conn.Driver != db.DriverSQLite {
			ctxW, cancelW := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancelW()
			if _, werr := conn.ExecContext(ctxW, `DELETE FROM unmask_event WHERE id = -1`); werr != nil {
				addErr("DB write", fmt.Sprintf("cannot write (%v) — challenges keep serving but no events/stats are recorded; check the DB user's grants", werr))
			} else {
				addOK("DB write", "writable with the configured credentials")
			}
		} else if s.DB.SQLitePath != "" {
			owner, ownerOK := fileOwnerUID(s.DB.SQLitePath)
			svc, svcErr := user.Lookup("unmask")
			switch {
			case ownerOK && svcErr == nil && strconv.FormatUint(uint64(owner), 10) != svc.Uid:
				addWarn("DB file owner", fmt.Sprintf("%s is not owned by the unmask user — a daemon running as unmask cannot record events (stats stay empty, challenges still serve); run: chown unmask: %s*  &&  systemctl restart unmask", s.DB.SQLitePath, s.DB.SQLitePath))
			case ownerOK && svcErr == nil:
				addOK("DB write", "DB file owned by the unmask user")
			default:
				// Source/dev install without an unmask system user: the
				// admin UI's retention tab runs an in-daemon probe, which is
				// the definitive check there.
				addOK("DB write", "no unmask system user — see the write check on the admin retention tab")
			}
		}
		// Query-planner statistics.  Without sqlite_stat1 the planner cannot judge
		// how selective the event tables' date filter is, so the stats and bot-hunt
		// pages scan whole covering indexes -- they stay correct, but their cost
		// grows with the total event count instead of the window being viewed.
		ctx3, cancel3 := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel3()
		switch ok, err := conn.HasPlannerStats(ctx3); {
		case err != nil:
			// A locked/slow DB must WARN, not silently drop the check line —
			// that is exactly the state where the stats may be degrading.
			addWarn("DB planner stats", fmt.Sprintf("could not check (%v) — if the stats/hunt pages are slow, run `unmask db-analyze` while traffic is low", err))
		case conn.Driver != db.DriverSQLite:
			addOK("DB planner stats", "n/a (InnoDB maintains its own index statistics)")
		case !ok:
			addWarn("DB planner stats", "no index statistics (sqlite_stat1) — the stats and bot-hunt pages "+
				"scan whole indexes and get slower as events accumulate; run `unmask db-analyze` "+
				"while traffic is low (it takes a write lock for up to a minute on a large DB)")
		default:
			addOK("DB planner stats", "index statistics present")
		}
	}

	// 4. IP-geo mmdb (= optional).  When set, check existence + freshness
	// (WARN at 35+ day age — DB-IP publishes monthly so anything older
	// indicates a missed cron run) and surface vendor / build date.
	if s.IPGeo.MMDBPath == "" && s.IPGeo.MMDBASNPath == "" {
		addWarn("IP-geo mmdb", "not set (= no per-country chart / ASN popover); run `unmask install-ipgeo` to fetch DB-IP Lite (CC BY 4.0)")
	} else {
		r := ipgeo.Open(s.IPGeo.MMDBPath, s.IPGeo.MMDBASNPath)
		checkMMDBPath("IP-geo city mmdb", s.IPGeo.MMDBPath, addOK, addWarn, addErr)
		if s.IPGeo.MMDBASNPath != "" {
			checkMMDBPath("IP-geo ASN mmdb", s.IPGeo.MMDBASNPath, addOK, addWarn, addErr)
		}
		if r != nil {
			r.Close()
		}
	}

	// 4.5. Geo rule sanity: every rule's country must be a known ISO code
	// (= ipgeo master).  Catches typos like "JA" instead of "JP" silently
	// neutralizing a rule.
	checkGeoRules(s, addOK, addWarn)

	// 4.6. Roaming rebind: surface how the silent-rebind gates resolve.  The
	// feature still works without an ASN mmdb (the per-lineage cap alone
	// bounds replay), but the operator should know the ASN veto is inactive
	// and how to enable it.
	if s.Rebind.RebindEnabled() {
		if v := strings.TrimSpace(s.Rebind.ASNVeto); v != "" && v != "auto" && v != "off" {
			addWarn("roaming rebind", fmt.Sprintf("rebind.asn_veto %q is not auto|off; treated as auto", v))
		} else if s.Rebind.ASNVetoResolved() == "auto" && s.IPGeo.MMDBASNPath == "" {
			addWarn("roaming rebind", "active without the ASN veto (= per-lineage cap only); set ipgeo.mmdb_asn_path to also pin rebinds to the solve-time network")
		} else if s.Rebind.ASNVetoResolved() == "off" {
			addOK("roaming rebind", "active, ASN veto off (= per-lineage cap only)")
		} else {
			addOK("roaming rebind", "active with ASN veto + per-lineage cap")
		}
	} else {
		addOK("roaming rebind", "disabled (rebind.disabled: true); IP changes re-challenge")
	}

	// 4.6b. Stale-browser tier: the current-major baseline is operator-
	// maintained (unmask can't discover it), so a value left frozen slowly
	// widens the net as real stable advances.  Surface the effective threshold
	// and warn when the toggle is on but the baseline is missing (= inert) or
	// looks stale itself.
	if s.Global.StaleBrowserChallenge {
		cur := s.Global.CurrentChromeMajorResolved()
		threshold := cur - s.Global.StaleBrowserLagN()
		src := fmt.Sprintf("current %d", cur)
		if s.Global.CurrentChromeMajor <= 0 {
			// Riding the shipped baseline: it only goes stale in the safe
			// direction (challenges fewer browsers as it ages), but flag it so
			// an operator on an old binary can set current_chrome_major to keep
			// the net current.
			src = fmt.Sprintf("current %d — built-in baseline (set current_chrome_major to track newer Chrome releases)", cur)
		}
		addOK("stale-browser tier", fmt.Sprintf("active: challenge Chrome-family major <= %d (%s, lag %d) with %s",
			threshold, src, s.Global.StaleBrowserLagN(), s.Global.StaleBrowserResolvedAction()))
	}

	// 4.7. Admin allowlists: empty = "allow all" (reasonable behind a trusted
	// proxy, but easy to leave open by accident).  Surface it so the operator
	// knows the admin UI is reachable from any IP / Host (A-1 / A-2).
	if len(s.Nginx.AdminAllowedIPs) == 0 {
		addWarn("admin IP allowlist", "empty = admin UI reachable from any IP; set nginx.admin_allowed_ips (or rely on an upstream network ACL)")
	} else {
		addOK("admin IP allowlist", fmt.Sprintf("%d entr(ies)", len(s.Nginx.AdminAllowedIPs)))
	}
	if len(s.Nginx.AdminAllowedHosts) == 0 {
		addWarn("admin Host allowlist", "empty = any Host header accepted for the admin UI; set nginx.admin_allowed_hosts when serving admin on a dedicated hostname")
	} else {
		addOK("admin Host allowlist", fmt.Sprintf("%d entr(ies)", len(s.Nginx.AdminAllowedHosts)))
	}

	// 5. ban file directory writable
	if p := s.Nginx.Honeypot.BanFilePath; p != "" {
		dir := filepath.Dir(p)
		if err := writableDir(dir); err != nil {
			addErr("ban file dir", err.Error())
		} else {
			addOK("ban file dir", dir)
		}
	} else {
		addWarn("ban file path", "not set (= honeypot persistent BAN feature disabled)")
	}

	// 6. challenge html override (= optional).  Doctor reports the global
	// default only; per-site challenge_html_path overrides are surfaced in
	// the admin UI's per-site card list.
	chDefault := s.Challenge.Default
	if p := chDefault.ChallengeHTMLPath; p != "" {
		if _, err := os.Stat(p); err != nil {
			addErr("challenge html override", err.Error())
		} else {
			addOK("challenge html override", p)
		}
	}

	// 7. challenge settings sanity.  Per-kind validity windows resolved via
	// the helpers so an unset value falls back to its hard default.
	powSec := chDefault.PowCookieValidSecondsResolved()
	powDays := powSec / 86400
	if powDays <= 0 || powDays > 365 {
		addWarn("pow_cookie_valid_seconds", fmt.Sprintf("value %d (= %d days) is outside the sensible range (1-365 days)", powSec, powDays))
	} else {
		addOK("pow_cookie_valid_seconds", fmt.Sprintf("%d days (= %d seconds)", powDays, powSec))
	}
	capSec := chDefault.CaptchaCookieValidSecondsResolved()
	capDays := capSec / 86400
	if capDays <= 0 || capDays > 365 {
		addWarn("captcha_cookie_valid_seconds", fmt.Sprintf("value %d (= %d days) is outside the sensible range (1-365 days)", capSec, capDays))
	} else {
		addOK("captcha_cookie_valid_seconds", fmt.Sprintf("%d days (= %d seconds)", capDays, capSec))
	}
	if th := chDefault.CaptchaProvider.BuiltinScoreThreshold; th < 0 || th > 1 {
		addWarn("captcha.builtin_score_threshold", fmt.Sprintf("value %.2f is outside (0.0-1.0)", th))
	} else {
		addOK("captcha.builtin_score_threshold", fmt.Sprintf("%.2f", th))
	}

	// 8. nginx output_dir writable
	if p := s.Nginx.OutputDir; p != "" {
		if err := writableDir(p); err != nil {
			addErr("nginx output_dir", err.Error())
		} else {
			addOK("nginx output_dir", p)
		}
	} else {
		addWarn("nginx output_dir", "not set (= cannot save from the web UI)")
	}

	// 9. Ensure the secret is not still the default (= a weak seed lets attackers forge cookies)
	// Read the RAW config first: Load() fabricates a per-process random key when
	// the file omits secret.bv_secret, so s.Secret.BVSecret here would look like
	// a healthy 24-byte value (false green) while render-nginx and the daemon
	// actually sign with different keys -> permanent challenge loop.
	if !settings.RawBVSecretPresent(resolved) {
		addErr("bv_secret", "not set in config — the daemon falls back to a per-process random key that render-nginx can't match, so every visitor loops on the challenge. Set secret.bv_secret or run `unmask config-init`.")
	} else if isDefaultSecret(s.Secret.BVSecret) {
		addErr("bv_secret", "still default.  regenerate via unmask config-init")
	} else if len(s.Secret.BVSecret) < 16 {
		addWarn("bv_secret", "too short (= recommend 16+ chars)")
	} else {
		addOK("bv_secret", "set (length="+fmt.Sprint(len(s.Secret.BVSecret))+")")
	}

	// 10. notifications url (= optional)
	if !s.Notifications.Disabled && s.Notifications.URL != "" {
		if !strings.HasPrefix(s.Notifications.URL, "https://") && !strings.HasPrefix(s.Notifications.URL, "http://") {
			addErr("notifications.url", "does not start with https:// or http://")
		} else {
			addOK("notifications.url", s.Notifications.Format)
		}
	}

	// 10b. over-block breaker alert deliverability.  The breaker is armed by
	// default, but its trip alert only reaches the operator through the
	// webhook or mail; with neither configured, a trip shows nowhere but the
	// daemon log and the admin overview banner -- the shape of the 2026-06-08
	// incident, where a challenge loop over-blocked visitors for ~14h before
	// anyone looked.  (Mail delivery also needs alert recipients on admin
	// users; this check covers the transport being configured at all.)
	if !s.OverBlock.Disabled {
		if via := overBlockAlertRoute(s); via != "" {
			addOK("over-block alerts", "deliverable via "+via)
		} else {
			addWarn("over-block alerts", "the breaker is armed but its trip alert has nowhere to go (no webhook URL, no SMTP host) — a challenge-loop trip only shows in the daemon log and the admin overview banner. Configure Settings → Notifications, or SMTP.")
		}
	}

	// 11. runtime SLO self-curl (= measure /unmask/healthz round-trip latency
	// + error rate on the configured admin bind).  When admin is not running,
	// produces a single WARN and skips.  When running, fires 30 sequential
	// curls and reports p50 / p95 / max latency.
	checkDataOwnership(s, addOK, addWarn)
	checkChallengeAssets(addOK, addWarn)
	checkAdminBind(s, addOK, addWarn)
	checkRealIPReminder(s, addWarn)
	checkApacheConnPeer(addWarn)
	checkNativeFailsafe(addWarn)
	checkNginxConfTest(addOK, addWarn, addErr)
	checkNginxStaleLibs(addWarn)
	checkNginxReloadLag(s, addOK, addWarn)
	checkNginxProtectScope(addWarn)
	checkHTTPSRedirectApplied(s, addOK, addWarn)
	checkHTTPSRedirectHealthCheck(s, addOK, addWarn)
	checkBVSecretSync(s, addOK, addWarn)

	runSLOCheck(s, addOK, addWarn, addErr)

	return printSummary(checks)
}

// checkAdminBind warns when the admin API (cleartext HTTP — TLS is the front
// proxy's job) is bound to something routable.  A loopback / unix bind keeps
// it private; a wildcard (0.0.0.0 / ::) or routable IP exposes the cleartext
// admin port directly.
// checkDataOwnership reports files under the daemon's directories that its
// service user cannot write.  These are the residue of management commands run
// as root before the privilege drop existed (or with UNMASK_NO_PRIVDROP set),
// and they fail in ways that do not look like a permission problem: a
// root-owned mmdb makes every country lookup return nothing while the file
// itself is present and current, and a root-owned render output makes a
// settings save appear to succeed while nginx keeps serving the old config.
//
// doctor is the right place for it precisely because doctor was the tool that
// missed it: reading a file as root says nothing about whether the daemon can.
// Package-deployed challenge assets: the paths the RPM / deb install to.  The
// runtime does NOT read them -- 0.1.32 made the embedded copies authoritative
// -- so they are checked here only because a copy that differs is an edit
// nobody is serving.  Vars so the doctor test can point them at fixtures.
var (
	challengeAssetHTMLPath = "/usr/share/unmask/challenge/challenge.html"
	challengeAssetJSPath   = "/usr/share/unmask/challenge/challenge.js"
)

// checkChallengeAssets compares the package-deployed challenge assets against
// the ones embedded in this binary, and reports a difference as an edit that
// is going nowhere.
//
// The check was written for the opposite world.  A deployed copy used to WIN
// at serve time, which is how 2026-08-02 happened: the fleet ran a new binary
// while every node served the previous day's challenge.js, so a proof-of-work
// fix reached nobody.  0.1.32 answered that by making the embedded assets
// authoritative, and this check kept its old wording for three weeks -- it
// told operators visitors were running the deployed file when the runtime had
// stopped reading it.  A doctor that is confidently wrong is worse than one
// that is silent, so the message now says what actually happens.
//
// The check still earns its place, for the case the runtime's own one-shot
// startup log covers: an operator who customised the packaged file and cannot
// see why their edit does nothing.  doctor is where they can ask on demand,
// and the answer names both exits -- delete the file, or point
// challenge_html_path / challenge_js_path at it.
//
// It is NOT a warning.  doctor has two levels, and a warning has to mean
// "this needs your attention"; here nothing does, because the install serves
// this binary's assets whatever sits in that directory.  The packaging drops
// the file as a template to copy, and a binary upgraded ahead of its package
// makes it differ with no mistake involved -- which on a fleet deployed by
// swapping the binary is every node, permanently.  A warning nobody can clear
// is how a tool teaches people to stop reading it, and the next one that
// matters goes with it.
// overBlockAlertRoute reports how an over-block trip alert can reach the
// operator: "webhook", "mail", "webhook + mail", or "" when no transport can
// deliver.  Notifications.Disabled gates both transports (notifier's OverBlock
// returns before either path when the section is off), and each channel's
// pause flag mutes just that one -- a paused channel is configured but not a
// route.
func overBlockAlertRoute(s settings.Settings) string {
	if s.Notifications.Disabled {
		return ""
	}
	via := ""
	if s.Notifications.URL != "" && !s.Notifications.WebhookDisabled {
		via = "webhook"
	}
	if s.SMTP.Host != "" && !s.Notifications.MailDisabled {
		if via != "" {
			via += " + "
		}
		via += "mail"
	}
	return via
}

func checkChallengeAssets(addOK, addWarn func(t, m string)) {
	type pair struct {
		name     string
		deployed string
		embedded string
	}
	var ignored, missing, current []string
	for _, p := range []pair{
		{"challenge.html", challengeAssetHTMLPath, "static/challenge.html"},
		{"challenge.js", challengeAssetJSPath, "static/challenge.js"},
	} {
		onDisk, err := os.ReadFile(p.deployed)
		if err != nil {
			// Not deployed at all is the normal case for a binary install: the
			// embedded copy is served and cannot go stale.
			missing = append(missing, p.name)
			continue
		}
		want, err := assets.Static.ReadFile(p.embedded)
		if err != nil {
			continue
		}
		if bytes.Equal(onDisk, want) {
			current = append(current, p.name)
			continue
		}
		ignored = append(ignored, fmt.Sprintf("%s (%s)", p.name, p.deployed))
	}
	if len(ignored) == 0 {
		switch {
		case len(current) > 0:
			addOK("challenge assets", fmt.Sprintf("deployed %s match this binary", strings.Join(current, " + ")))
		case len(missing) > 0:
			addOK("challenge assets", "none deployed on disk; serving the copies embedded in this binary")
		}
		return
	}
	addOK("challenge assets", fmt.Sprintf(
		"%s differ from the copies embedded in this binary and are NOT being served — the embedded copies are, so visitors are on this binary's assets. "+
			"An edit to those files is doing nothing: delete them, or set challenge.challenge_html_path / challenge.challenge_js_path to those paths if it was deliberate.",
		strings.Join(ignored, ", ")))
}

func checkDataOwnership(s settings.Settings, addOK, addWarn func(t, m string)) {
	uid, gid, name, err := daemonIdentity()
	if err != nil {
		return // no data dir yet: nothing to own
	}
	dirs := []string{dataDirForOwner}
	if d := filepath.Dir(s.DB.SQLitePath); d != "" && d != dataDirForOwner {
		dirs = append(dirs, d)
	}
	bad := ownershipProblems(dirs, uid, gid)
	if len(bad) == 0 {
		addOK("data ownership", fmt.Sprintf("every file under %s is usable by the daemon user (%s)", dataDirForOwner, name))
		return
	}
	show := bad
	const maxShow = 5
	suffix := ""
	if len(show) > maxShow {
		show, suffix = show[:maxShow], fmt.Sprintf(" (+%d more)", len(bad)-maxShow)
	}
	addWarn("data ownership", fmt.Sprintf(
		"%d file(s) under the daemon's directories are not writable by its user (%s): %s%s — left by a command run as root; fix with `chown -R %s %s` (the CLI now drops to that user by itself)",
		len(bad), name, strings.Join(show, ", "), suffix, name, dataDirForOwner))
}

func checkAdminBind(s settings.Settings, addOK, addWarn func(t, m string)) {
	rawBind := strings.TrimSpace(s.Server.Bind)
	isUnix := strings.HasPrefix(rawBind, "unix:") || strings.HasPrefix(rawBind, "/")
	bindHost := rawBind
	if !isUnix {
		if h, _, err := net.SplitHostPort(rawBind); err == nil {
			bindHost = h
		}
	}
	loopback := isUnix || bindHost == "" || bindHost == "127.0.0.1" ||
		strings.HasPrefix(bindHost, "127.") || bindHost == "::1" || bindHost == "localhost"
	if loopback {
		addOK("admin bind", rawBind+" (loopback/unix — not directly exposed)")
		return
	}
	addWarn("admin bind exposure", fmt.Sprintf("server.bind=%q is not loopback/unix; the admin API talks cleartext HTTP, so a routable bind exposes it without TLS. Bind to 127.0.0.1 or a unix socket and front it with a TLS-terminating proxy.", rawBind))
}

// checkRealIPReminder fires when a trusted LB is configured (native mode):
// the LB's X-Client-JA4 is trusted, but the visitor IP still comes from
// $remote_addr unless nginx is told to rewrite it.  Without set_real_ip_from
// + real_ip_header every visitor resolves to the LB IP, so challenge / ban /
// rate-limit apply to all of them at once.  doctor can't read the vhost, so
// this is a reminder rather than a hard check.
func checkRealIPReminder(s settings.Settings, addWarn func(t, m string)) {
	if len(s.Nginx.TrustedLBPresets) > 0 || len(s.Nginx.TrustedLBExtra) > 0 {
		addWarn("real client IP (LB)", "a trusted LB is configured; confirm nginx has set_real_ip_from + real_ip_header for it, otherwise every visitor resolves to the LB's IP and challenge / ban / rate-limit hit all clients at once.")
	}
}

// checkApacheConnPeer warns when Apache forward-auth is wired but the per-vhost
// conn-peer RewriteRule is missing.  In forward-auth mode the daemon honors a
// forwarded X-Client-JA4 only when it can confirm the request entered through a
// trusted LB.  nginx edge-gates that in the web server (forward-auth-lbtrust.conf)
// and strips the header; Apache has no geo/map, so apache-unmask.lua reports the
// real TCP peer in X-Unmask-Conn-Peer, populated by a per-vhost
//
//	RewriteRule .* - [E=UNMASK_CONN_PEER:%{CONN_REMOTE_ADDR}]
//
// (mod_remoteip does NOT rewrite CONN_REMOTE_ADDR, and the rule does not inherit
// into vhosts, so it must be repeated per protected vhost).  Without it the
// header is empty, the daemon's conn-peer gate is skipped, and the JA4 falls
// back to the proxy-peer check alone (= loopback Apache) -- so a client reaching
// Apache directly could forge X-Client-JA4.  doctor can't parse vhost blocks, so
// this is a best-effort line scan of the httpd config tree (comment lines
// ignored, to skip the shipped snippet's commented example): an active
// LuaHookAccessChecker for unmask + no UNMASK_CONN_PEER => WARN.
func checkApacheConnPeer(addWarn func(t, m string)) {
	roots := []string{
		"/etc/httpd",   // RHEL / Rocky / Alma
		"/etc/apache2", // Debian / Ubuntu / Alpine
	}
	var hasLuaHook, hasConnPeer, scanned bool
	for _, root := range roots {
		if st, err := os.Stat(root); err != nil || !st.IsDir() {
			continue
		}
		_ = filepath.WalkDir(root, func(path string, d iofs.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil // best-effort: skip unreadable subtrees
			}
			if strings.ToLower(filepath.Ext(path)) != ".conf" {
				return nil // config files only (skip logs / binaries)
			}
			b, rerr := os.ReadFile(path)
			if rerr != nil {
				return nil
			}
			scanned = true
			for _, line := range strings.Split(string(b), "\n") {
				t := strings.TrimSpace(line)
				if t == "" || strings.HasPrefix(t, "#") {
					continue // ignore comments (the shipped snippet ships a commented example)
				}
				if strings.Contains(t, "LuaHookAccessChecker") && strings.Contains(t, "unmask") {
					hasLuaHook = true
				}
				if strings.Contains(t, "UNMASK_CONN_PEER") {
					hasConnPeer = true
				}
			}
			return nil
		})
	}
	if !scanned || !hasLuaHook {
		return // no Apache forward-auth detected (or no read access) -> silent
	}
	if !hasConnPeer {
		addWarn("apache JA4 gate", "Apache forward-auth is active (LuaHookAccessChecker) but no conn-peer RewriteRule (E=UNMASK_CONN_PEER:%{CONN_REMOTE_ADDR}) was found in the httpd config; without it X-Unmask-Conn-Peer is empty and the daemon can't confirm a forwarded X-Client-JA4 arrived via a trusted LB, so a client reaching Apache directly could forge one. Add `RewriteEngine On` + the RewriteRule to each protected <VirtualHost> (see snippets/apache-forward-auth.conf).")
	}
}

// checkNginxConfTest runs `nginx -t` against the LIVE host config (not the
// isolated dry-run render above) and surfaces the result -- the highest-signal
// install-time check that the actually-wired config loads.  A failing nginx -t
// means the operator's nginx cannot reload AND, when the error references unmask,
// the plugin's place-module fail-safe may have stripped the native wiring (silent
// unprotect -- the 2026-06-28 map_hash class).  Skipped when nginx is not on PATH
// (admin-only box / central forward-auth).  nginx -t needs root (reads 0640
// http.inc, bind-tests), so a non-root permission failure is a WARN nudging sudo,
// not a hard ERR.
// nginxTestPermissionAdvice builds the warning for an nginx -t that could not
// read what it needs.
//
// Do not send the operator round in a circle: doctor is not exempt from the
// privilege drop, so `sudo unmask doctor` arrives here as the daemon user just
// the same and prints the identical line.  Advice that cannot be followed reads
// as a broken check -- observed across a 7-node fleet, where re-running under
// sudo changed nothing.  Name the account that actually ran the test, and a
// command that works.
func nginxTestPermissionAdvice(msg string) string {
	if droppedFromRoot != "" {
		return "not validated: unmask drops to " + droppedFromRoot +
			" before running checks, and nginx -t needs root to read the host's keys (" +
			msg + ") — run `sudo nginx -t` directly"
	}
	return "couldn't validate as non-root (" + msg + ") — re-run as root"
}

func checkNginxConfTest(addOK, addWarn, addErr func(t, m string)) {
	nginxBin, err := exec.LookPath("nginx")
	if err != nil {
		return // no nginx on this host -> nothing to validate
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, terr := exec.CommandContext(ctx, nginxBin, "-t").CombinedOutput()
	if terr == nil {
		addOK("nginx -t", "live host config valid")
		return
	}
	msg := nginxErrLine(string(out))
	low := strings.ToLower(string(out))
	if os.Geteuid() != 0 && (strings.Contains(low, "permission denied") || strings.Contains(low, "operation not permitted")) {
		addWarn("nginx -t", nginxTestPermissionAdvice(msg))
		return
	}
	if strings.Contains(low, "unmask") || strings.Contains(string(out), "/var/lib/unmask/nginx/") {
		addErr("nginx -t", "live config FAILS and the error references unmask ("+msg+"). Run `unmask render-nginx` then `nginx -t`; a duplicate/bad directive trips the plugin fail-safe and silently disables native protection (see the 'native module disabled' check above if it already fired).")
		return
	}
	addErr("nginx -t", "live nginx config FAILS to load ("+msg+") — nginx cannot reload until fixed; run `nginx -t` for the full output.")
}

// checkNginxProtectScope warns when protect.inc is included at SERVER scope
// rather than inside a location {} block.  At server scope the challenge gate's
// rewrite runs before location selection and also catches /unmask/* machinery
// (challenge.js / verify API), so the challenge can never complete and every
// human loops — bots still 403, so it looks "working" to the operator.  This is
// the self-DoS that hit unmask.sh on 2026-07-02 (the render-side fix exempts
// /unmask/ machinery, but a server-scope include is still a misconfiguration
// worth flagging).  Best-effort: parse `nginx -T` (full dumped config), track
// brace depth, and remember whether the innermost open block is a location {}.
// An `include .../protect.inc` seen while NOT inside a location => WARN.
// `nginx -T` needs root; a non-root failure is silent (checkNginxConfTest
// already nudges sudo).  Comment lines are ignored.
func checkNginxProtectScope(addWarn func(t, m string)) {
	nginxBin, err := exec.LookPath("nginx")
	if err != nil {
		return // no nginx here
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, terr := exec.CommandContext(ctx, nginxBin, "-T").CombinedOutput()
	if terr != nil {
		return // can't dump config (non-root / broken config already flagged elsewhere)
	}
	// blockStack records the directive that opened each currently-open { } — we
	// only need to know if any open block is a "location".
	var blockStack []string
	inLocation := func() bool {
		for _, b := range blockStack {
			if b == "location" {
				return true
			}
		}
		return false
	}
	serverScope := false
	for _, raw := range strings.Split(string(out), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// Detect an include of protect.inc BEFORE we mutate the stack for this
		// line, so the current context reflects where the include sits.
		if strings.Contains(line, "include") && strings.Contains(line, "protect.inc") &&
			!strings.HasPrefix(line, "#") {
			// A single-line `location ... { include .../protect.inc; }` is
			// location scope, but the location "{" on this same line hasn't been
			// pushed onto the stack yet at this point in the scan — so treat a
			// same-line location-opening as being in a location too.
			sameLineLoc := strings.HasPrefix(line, "location") && strings.Contains(line, "{")
			if !inLocation() && !sameLineLoc {
				serverScope = true
			}
		}
		// Track brace depth.  A block-opening directive ends with "{"; grab its
		// first word as the block kind (server / location / http / ...).  Lines
		// may contain both (rare in a dump) so handle each brace.
		for _, ch := range line {
			switch ch {
			case '{':
				kind := strings.Fields(line)
				k := ""
				if len(kind) > 0 {
					k = kind[0]
				}
				blockStack = append(blockStack, k)
			case '}':
				if len(blockStack) > 0 {
					blockStack = blockStack[:len(blockStack)-1]
				}
			}
		}
	}
	if serverScope {
		addWarn("nginx protect.inc scope", "protect.inc is included at server scope (not inside a location {} block). At server scope the challenge gate also catches /unmask/ machinery, which can loop human visitors (the 2026-07-02 unmask.sh self-DoS). Move `include .../protect.inc;` INSIDE the `location / {}` (or the specific locations) you want protected. The current unmask render exempts /unmask/ machinery so it still works, but location-scope is the intended placement.")
	}
}

// nginxErrLine returns the first emerg/error line of `nginx -t` output, falling
// back to the last non-empty line.
func nginxErrLine(out string) string {
	var last string
	for _, ln := range strings.Split(out, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" {
			continue
		}
		last = ln
		if strings.Contains(ln, "[emerg]") || strings.Contains(ln, "[error]") {
			return ln
		}
	}
	return last
}

// checkNativeFailsafe warns when the plugin's place-module fail-safe stripped the
// native nginx wiring (nginx -t failed referencing unmask) and left a breadcrumb
// at /var/lib/unmask/nginx/.native-failsafe.  In that state nginx starts fine but
// unmask's native protection is silently OFF -- exactly what the 2026-06-28
// map_hash regression caused (a conf.d ordering bug tripped nginx -t, the
// fail-safe stripped the .so + http.inc, and the site served unprotected with no
// obvious symptom).  place-module clears the marker on the next successful
// `nginx -t`, so its presence means native is still disabled now.
func checkNativeFailsafe(addWarn func(t, m string)) {
	b, err := os.ReadFile("/var/lib/unmask/nginx/.native-failsafe")
	if err != nil {
		return // no breadcrumb -> native not fail-safe-disabled (or forward-auth mode)
	}
	reason := ""
	for _, ln := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(ln, "reason:") {
			reason = strings.TrimSpace(strings.TrimPrefix(ln, "reason:"))
			break
		}
	}
	msg := "the plugin's place-module fail-safe stripped the native nginx wiring (`nginx -t` failed referencing unmask), so native protection is OFF until fixed."
	if reason != "" {
		msg += " cause: " + reason + "."
	}
	msg += " Fix the nginx config, run `unmask render-nginx`, then `nginx -t` (or reinstall unmask-plugin-nginx); the marker clears once nginx -t passes."
	addWarn("native module disabled (fail-safe)", msg)
}

// checkNginxStaleLibs warns when the running nginx still maps libraries that a
// package already replaced on disk -- the state in which `nginx -s reload` is
// not merely insufficient but harmful, because it forks fresh workers from a
// master that kept the unlinked mapping and those workers can segfault.
//
// Silent unless it fires (an alarm, not a status line), and silent when the
// running nginx cannot be inspected at all: /proc/<pid>/maps belongs to root,
// so a non-root `unmask doctor` proves nothing either way and must not claim
// the install is clean.
func checkNginxStaleLibs(addWarn func(t, m string)) {
	paths, checked := staleNginxLibs()
	if !checked || len(paths) == 0 {
		return
	}
	addWarn("nginx running on outdated files", fmt.Sprintf(
		"the running nginx is still executing %d %s whose contents no longer match the file on disk, "+
			"or that could not be compared (%s) — a package upgrade replaced %s after nginx started. "+
			"`nginx -s reload` does NOT re-exec the master, so it keeps the stale mapping and every "+
			"worker forked from it inherits the same image; when a replaced library is one the C library "+
			"reloads at runtime, those workers segfault mid-response and clients see an empty reply. "+
			"Run `systemctl restart nginx` (or `service nginx restart`) — a reload will not clear this. "+
			"(A reinstall that wrote back identical bytes is not reported.)",
		len(paths), plural(len(paths), "file", "files"),
		staleNginxLibsList(paths), plural(len(paths), "it", "them")))
}

// checkHTTPSRedirectApplied warns when nginx.https_redirect is enabled but the
// rendered server.inc carries no 301 block — the operator turned the setting on
// and never re-rendered (or the render failed), so plaintext HTTP requests are
// still being challenged instead of redirected.  The same stale-render class as
// the bv_secret desync below, for the redirect option.  Silent when the option
// is off or nothing is rendered yet (forward-auth mode / fresh install — the
// render checks above already cover those).
func checkHTTPSRedirectApplied(s settings.Settings, addOK, addWarn func(t, m string)) {
	if !s.Nginx.HTTPSRedirect {
		return
	}
	dir := strings.TrimSpace(s.Nginx.OutputDir)
	if dir == "" {
		dir = "/var/lib/unmask/nginx"
	}
	b, err := os.ReadFile(filepath.Join(dir, "server.inc"))
	if err != nil {
		return
	}
	if strings.Contains(string(b), "return 301 https://") {
		addOK("https redirect", "enabled and present in the rendered server.inc")
		return
	}
	addWarn("https redirect", "nginx.https_redirect is enabled but the rendered server.inc has no 301 block — the render predates the setting. Run `unmask render-nginx`, then reload nginx; until then plaintext HTTP requests are still challenged instead of redirected.")
}

// httpsRedirectProbeURL is the plaintext-HTTP URL checkHTTPSRedirectHealthCheck
// probes as a health checker.  A package var so tests can override it.
var httpsRedirectProbeURL = "http://127.0.0.1:80/"

// checkHTTPSRedirectHealthCheck probes the plaintext HTTP port as a
// load-balancer health checker would — a GoogleHC user-agent, no
// X-Forwarded-Proto (health probes reach the backend directly, bypassing the
// LB proxy that would set it) — and warns if it gets a 301.  A 301 to a health
// check is a FAILED check: the LB marks the node unhealthy and drops it from
// rotation, so its traffic (and stats) go silent.  This is what stopped web1-jp
// recording on 2026-07-04 before the load-balancer-health redirect exemption
// existed.  With that exemption on (the default) the probe is not redirected and
// this is silent; it fires only when the redirect is on and the exemption was
// turned off (or a custom config leaves the probe uncovered).  Best-effort:
// silent when the redirect is off or nginx is not reachable on the port.
func checkHTTPSRedirectHealthCheck(s settings.Settings, addOK, addWarn func(t, m string)) {
	if !s.Nginx.HTTPSRedirect {
		return
	}
	// GCP/AWS/k8s health probes hit the plaintext HTTP backend on :80; a
	// non-80 plaintext port is rare enough that a missed probe (silent) beats
	// parsing nginx -T for the listen port.  A package var so tests can point
	// it at an httptest server.
	req, err := http.NewRequest(http.MethodGet, httpsRedirectProbeURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "GoogleHC/1.0")
	// Hit a declared vhost when one exists so the probe reaches a server block
	// that includes server.inc (= carries the redirect); otherwise the default
	// server answers, which is still a valid signal for single-site installs.
	if len(s.Sites.Defined) > 0 {
		req.Host = s.Sites.Defined[0]
	}
	client := &http.Client{
		Timeout: 3 * time.Second,
		// Don't follow the redirect -- we want to observe the 301 itself.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return // nginx not listening on :80 here, or unreachable -- nothing to assert
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusMovedPermanently || resp.StatusCode == http.StatusFound {
		addWarn("https redirect health check", "a load-balancer health check (GoogleHC user-agent) on :80 is answered with a "+strconv.Itoa(resp.StatusCode)+" redirect — a health check that gets a 3xx is a FAILED check, so the load balancer will drop this node from rotation and its traffic (and stats) stop. Enable the \"Load-balancer health checks\" redirect exemption under Settings > Network (it is on by default), or point the LB health check at the HTTPS port.")
		return
	}
	addOK("https redirect health check", "a GoogleHC health check on :80 is not redirected (the load-balancer-health exemption is working)")
}

// checkBVSecretSync compares the bv_secret baked into the rendered http.inc
// against the daemon's config.  A mismatch means the rendered nginx config is
// stale: the native plugin verifies the _bv cookie against http.inc's secret
// while the daemon signs with its config secret, so every _bv is rejected and
// the visitor loops on the challenge — the 2026-06-08 incident's root cause.
// A reload won't fix it (the module isn't reloaded either); it needs a
// re-render plus an nginx restart.  The daemon runs the same check at startup
// (main.go) so a deploy that forgets the restart surfaces in the log too.
func checkBVSecretSync(s settings.Settings, addOK, addWarn func(t, m string)) {
	if strings.TrimSpace(s.Secret.BVSecret) == "" {
		return // nothing to compare against
	}
	rendered := nginxconf.RenderedBVSecret(s.Nginx.OutputDir)
	if rendered == "" {
		return // not rendered (forward-auth mode / fresh install) or directive absent
	}
	if rendered == s.Secret.BVSecret {
		addOK("bv_secret sync", "rendered http.inc matches the daemon config")
		return
	}
	addWarn("bv_secret desync", "http.inc's unmask_bv_secret differs from the daemon config — the rendered nginx config is stale. Run `unmask render-nginx` and then RESTART nginx (a reload won't reload the module), otherwise the native plugin rejects every _bv the daemon issues and visitors loop on the challenge (the 2026-06-08 root cause).")
}

// runSLOCheck probes the locally-configured admin bind with N HTTP GETs to
// /unmask/healthz and classifies the result:
//   - admin not running (= connect refused on first probe)  -> WARN, skip
//   - some probes fail                                       -> ERR (flaky)
//   - all probes succeed but p95 > 100ms                     -> WARN
//   - all probes succeed and p95 <= 100ms                    -> OK
//
// The dialer auto-detects TCP (= host:port) vs unix socket (= unix:/path or
// the "/" prefix on socket-style binds).
func runSLOCheck(s settings.Settings,
	addOK, addWarn, addErr func(string, string)) {
	const samples = 30
	const slowP95 = 100 * time.Millisecond

	url, dialer := sloTarget(s.Server)
	if url == "" {
		addWarn("SLO self-curl", "could not derive target URL from server.bind")
		return
	}
	client := &http.Client{
		Timeout:   2 * time.Second,
		Transport: &http.Transport{DialContext: dialer},
	}

	// Quick probe: classify "admin not running" cleanly.
	if _, err := client.Get(url); err != nil {
		var ne *net.OpError
		if errors.As(err, &ne) && (strings.Contains(err.Error(), "refused") ||
			strings.Contains(err.Error(), "no such file") ||
			strings.Contains(err.Error(), "permission denied")) {
			addWarn("SLO self-curl", "admin not running (or unreachable on "+url+") — skipped")
			return
		}
		// other error -> still try the full run; one transient failure is
		// expected to be visible in the percentile output.
	}

	latencies := make([]time.Duration, 0, samples)
	failures := 0
	for i := 0; i < samples; i++ {
		t0 := time.Now()
		resp, err := client.Get(url)
		dur := time.Since(t0)
		if err != nil || resp.StatusCode != http.StatusOK {
			failures++
			if resp != nil {
				resp.Body.Close()
			}
			continue
		}
		resp.Body.Close()
		latencies = append(latencies, dur)
	}
	if failures > 0 {
		addErr("SLO self-curl",
			fmt.Sprintf("%d/%d failures hitting %s/unmask/healthz", failures, samples, url))
		if len(latencies) == 0 {
			return
		}
	}
	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p50 := latencies[len(latencies)/2]
	p95 := latencies[len(latencies)*95/100]
	maxLat := latencies[len(latencies)-1]
	fmtMs := func(d time.Duration) string { return fmt.Sprintf("%.1fms", float64(d.Microseconds())/1000.0) }

	if p95 > slowP95 {
		addWarn("SLO self-curl",
			fmt.Sprintf("p50=%s p95=%s max=%s (= p95 > %s; check admin load / I/O wait)",
				fmtMs(p50), fmtMs(p95), fmtMs(maxLat), fmtMs(slowP95)))
		return
	}
	addOK("SLO self-curl",
		fmt.Sprintf("/unmask/healthz × %d samples: p50=%s p95=%s max=%s",
			len(latencies), fmtMs(p50), fmtMs(p95), fmtMs(maxLat)))
}

// sloTarget returns (urlForGet, customDialer) for the admin's configured
// bind.  TCP binds produce a normal http://host:port URL with default dialer;
// unix-socket binds produce a placeholder http://unmask.local URL plus a
// dialer that always connects to the socket.
func sloTarget(server settings.Server) (string, func(ctx context.Context, network, addr string) (net.Conn, error)) {
	bind := strings.TrimSpace(server.Bind)
	port := server.Port
	base := strings.TrimSpace(server.BasePath)
	if base == "" {
		base = "/unmask"
	}
	// Unix-socket bind formats accepted: "unix:/path" or "/path".
	socket := ""
	if strings.HasPrefix(bind, "unix:") {
		socket = strings.TrimPrefix(bind, "unix:")
	} else if strings.HasPrefix(bind, "/") {
		socket = bind
	}
	if socket != "" {
		dialer := func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 2 * time.Second}).DialContext(ctx, "unix", socket)
		}
		return "http://unmask.local" + base + "/healthz", dialer
	}
	// TCP form.  Empty bind means "0.0.0.0"; for the self-curl we hit 127.0.0.1.
	host := bind
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if port <= 0 {
		port = 9477
	}
	return fmt.Sprintf("http://%s:%d%s/healthz", host, port, base), nil
}

// checkRenderFreshness compares the freshly re-rendered conf (in freshDir,
// the doctor dry-run) against the live copy nginx loads (in outputDir).  A
// mismatch means config.yml has changed since the conf was last rendered --
// typically a hand-edit that skipped `render-nginx` -- so nginx is serving a
// stale conf and the config change is not in effect.  Compares http.inc +
// server.inc (the substantive native outputs); the daemon re-renders on every
// save, so a match is the normal state.
func checkRenderFreshness(freshDir, outputDir string, addWarn, addOK func(string, string)) {
	if outputDir == "" {
		return // output_dir unset already flagged elsewhere
	}
	var stale []string
	compared := 0
	for _, name := range []string{"http.inc", "server.inc"} {
		fresh, e1 := os.ReadFile(filepath.Join(freshDir, name))
		live, e2 := os.ReadFile(filepath.Join(outputDir, name))
		if e1 != nil || e2 != nil {
			continue // not rendered yet / not this mode -- nothing to compare
		}
		compared++
		// The rendered conf echoes its own output dir in a usage-example
		// comment, so a dry-run into a temp dir always differs on that line;
		// normalize the fresh copy's dir back to the live one before comparing.
		freshS := strings.ReplaceAll(stripRenderStamps(fresh), freshDir, outputDir)
		liveS := stripRenderStamps(live)
		if freshS != liveS {
			stale = append(stale, name+" ("+firstDifference(liveS, freshS)+")")
		}
	}
	switch {
	case compared == 0:
		// No live conf to compare (fresh install pre-render, or output_dir empty).
		// Silent: the render dry-run above already reports render health.
	case len(stale) > 0:
		addWarn("nginx render freshness", fmt.Sprintf(
			"%s in %s %s out of date with config.yml — a config change has not been applied to nginx. Run `unmask render-nginx` then reload nginx (the web UI does this automatically on save).",
			strings.Join(stale, "; "), outputDir, plural(len(stale), "is", "are")))
	default:
		addOK("nginx render freshness", "rendered conf matches config.yml")
	}
}

// firstDifference summarises how the live conf and a fresh render diverge, so
// the warning says WHAT changed rather than only that something did.  Without
// it an operator has no way to tell a real pending change from a check that
// rendered under different inputs -- which is how a false "stale" reading cost
// an afternoon of looking for a config edit nobody had made.
func firstDifference(live, fresh string) string {
	ll := strings.Split(live, "\n")
	fl := strings.Split(fresh, "\n")
	for i := 0; i < len(ll) && i < len(fl); i++ {
		if ll[i] != fl[i] {
			return fmt.Sprintf("first change at line %d: %s -> %s",
				i+1, truncLine(ll[i]), truncLine(fl[i]))
		}
	}
	// Identical up to the shorter one: the difference is purely length.
	return fmt.Sprintf("%d lines live vs %d rendered", len(ll), len(fl))
}

// truncLine keeps a sample line short enough for one terminal row, and marks
// an empty line so "-> " does not read as a truncation.
func truncLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "(blank)"
	}
	if len(s) > 60 {
		return s[:57] + "..."
	}
	return s
}

// stripRenderStamps removes the per-render generated_at / unmask_version
// header lines so two renders of the SAME config compare equal (those stamps
// change every render even when the substance is identical).
func stripRenderStamps(b []byte) string {
	lines := strings.Split(string(b), "\n")
	out := lines[:0]
	for _, ln := range lines {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "#  generated_at:") || strings.HasPrefix(t, "#  unmask_version:") ||
			strings.HasPrefix(t, "# generated_at:") || strings.HasPrefix(t, "# unmask_version:") {
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func writableDir(p string) error {
	if p == "" {
		return errors.New("path empty")
	}
	st, err := os.Stat(p)
	if err != nil {
		// Try the parent dir (= if a file path was passed in).
		parent := filepath.Dir(p)
		if pst, perr := os.Stat(parent); perr == nil && pst.IsDir() {
			return tryTouch(parent)
		}
		return err
	}
	if !st.IsDir() {
		return tryTouch(filepath.Dir(p))
	}
	return tryTouch(p)
}

func tryTouch(dir string) error {
	f, err := os.CreateTemp(dir, ".unmask-doctor-*")
	if err != nil {
		return fmt.Errorf("write check failed: %v", err)
	}
	name := f.Name()
	f.Close()
	os.Remove(name)
	return nil
}

func isDefaultSecret(s string) bool {
	if s == "" {
		return true
	}
	for _, sample := range []string{"change_me", "CHANGE_ME", "default", "secret"} {
		if strings.EqualFold(s, sample) {
			return true
		}
	}
	return false
}

func printSummary(checks []doctorCheck) error {
	var ok, warn, errCount int
	for _, c := range checks {
		fmt.Println(c.String())
		switch c.level {
		case "ok":
			ok++
		case "warn":
			warn++
		case "err":
			errCount++
		}
	}
	fmt.Printf("\n%d ok, %d warn, %d err\n", ok, warn, errCount)
	if errCount > 0 {
		return fmt.Errorf("doctor: %d errors", errCount)
	}
	return nil
}

// checkMMDBPath inspects one mmdb file and reports vendor / build / age.
// Empty path is a no-op (= caller has filtered already).
// fileOwnerUID returns the owning uid of path (false when it cannot stat or
// the platform stat carries no uid — doctor is linux-first, so this is rare).
func fileOwnerUID(path string) (uint32, bool) {
	st, err := os.Stat(path)
	if err != nil {
		return 0, false
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return sys.Uid, true
}

func checkMMDBPath(title, path string,
	addOK, addWarn, addErr func(t, m string)) {
	if path == "" {
		return
	}
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			addWarn(title, path+" missing — run `unmask install-ipgeo` to fetch DB-IP Lite")
		} else {
			addErr(title, err.Error())
		}
		return
	}
	_ = st
	info, ierr := ipgeo.InspectMMDB(path)
	if ierr != nil {
		// File exists but not valid mmdb (= corrupt or wrong format).
		addErr(title, path+" exists but is not a valid mmdb: "+ierr.Error())
		return
	}
	msg := path
	if info.Vendor != "" {
		msg += " (" + info.Vendor
		if info.DatabaseType != "" {
			msg += " · " + info.DatabaseType
		}
		msg += ")"
	}
	if !info.BuildTime.IsZero() {
		ageDays := int(time.Since(info.BuildTime).Hours() / 24)
		msg += fmt.Sprintf(" · build %s (%d days old)", info.BuildTime.Format("2006-01-02"), ageDays)
		if ageDays > 35 {
			// DB-IP publishes monthly; > 35 days = missed refresh.
			addWarn(title, msg+" — stale; run `unmask install-ipgeo` (cron)")
			return
		}
	}
	addOK(title, msg)
}

// checkGeoRules validates that every Nginx.Geo.Rules entry uses an ISO
// 3166-1 alpha-2 code from the master list.  Unknown codes silently
// neutralize the rule (LookupRule never matches), so we surface them as
// WARN with a fix hint.
func checkGeoRules(s settings.Settings,
	addOK, addWarn func(t, m string)) {
	rules := s.Nginx.Geo.Rules
	if len(rules) == 0 {
		return
	}
	var unknown []string
	for _, r := range rules {
		if !ipgeo.IsValidCountry(r.Country) {
			unknown = append(unknown, r.Country)
		}
	}
	if len(unknown) > 0 {
		addWarn("Geo rules", fmt.Sprintf("unknown country code(s): %s — these rules are silently inactive", strings.Join(unknown, ", ")))
		return
	}
	addOK("Geo rules", fmt.Sprintf("%d rule(s), all country codes valid", len(rules)))
}
