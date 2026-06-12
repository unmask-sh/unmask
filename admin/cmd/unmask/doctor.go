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
	"context"
	"errors"
	"flag"
	"fmt"
	iofs "io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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
		printSummary(checks)
		return errors.New("doctor failed at config load")
	}
	addOK("config load", resolved)

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

	// 11. runtime SLO self-curl (= measure /unmask/healthz round-trip latency
	// + error rate on the configured admin bind).  When admin is not running,
	// produces a single WARN and skips.  When running, fires 30 sequential
	// curls and reports p50 / p95 / max latency.
	checkAdminBind(s, addOK, addWarn)
	checkRealIPReminder(s, addWarn)
	checkBVSecretSync(s, addOK, addWarn)

	runSLOCheck(s, addOK, addWarn, addErr)

	return printSummary(checks)
}

// checkAdminBind warns when the admin API (cleartext HTTP — TLS is the front
// proxy's job) is bound to something routable.  A loopback / unix bind keeps
// it private; a wildcard (0.0.0.0 / ::) or routable IP exposes the cleartext
// admin port directly.
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
