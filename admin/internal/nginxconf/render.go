// nginxconf.Render: generate nginx config snippets for native mode
// from settings.
//
// Output (= unified under <OutputDir>/native/.  Restructured on 2026-05-13):
//   - native/http.inc       http scope: JA4 maps + assorted decision maps + log_format
//   - native/server.inc     server scope: access_log syslog etc.
//   - native/protect.inc    location/server scope: limit_req + final_challenge rewrite
//   - upstream.conf         upstream block (= stays at /etc/unmask/upstream.conf)
//
// The auth_request-mode static snippets (= /etc/unmask/auth_request/{server,protect}.inc)
// are placed by the unmask-web-nginx package (= this code does not touch them).
//
// Callers:
//   - CLI: `unmask-admin render-nginx [-config PATH] [-out-dir DIR]`
//   - web: will be called from the handler after settings are saved
//     (= no auto-reload, but render runs)
package nginxconf

import (
	"embed"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"text/template"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

//go:embed templates/*.tmpl
var templatesFS embed.FS

// Render: write the native-mode snippets from settings into
// <outDir>/native/.
//   - <outDir>/native/http.inc      http scope: JA4 maps / log_format / rate-zone
//   - <outDir>/native/server.inc    server scope: access_log syslog etc.
//   - <outDir>/native/protect.inc   location/server scope: protection trigger
//   - <outDir>/upstream.conf        upstream block (= included by the shipped conf.d/unmask-web.conf)
//
// If outDir is empty, settings.Nginx.OutputDir is used (= default /etc/unmask).
// version is for display (= written in the header of the generated file).
//
// Old files (= <outDir>/nginx-rendered{,.-server,.-protect}.{conf,inc}) are
// removed as a migration (= no backward compatibility; pre-v0.1 GA so a
// clean break is fine).
func Render(s settings.Settings, outDir, version string) error {
	if outDir == "" {
		outDir = s.Nginx.OutputDir
	}
	if outDir == "" {
		outDir = "/etc/unmask"
	}
	nativeDir := filepath.Join(outDir, "native")
	if err := os.MkdirAll(nativeDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", nativeDir, err)
	}

	data, err := buildRenderData(s, outDir, version)
	if err != nil {
		return err
	}

	// http scope: JA4 maps / log_format / rate-zone.  The postinstall
	// drops a symlink to /etc/nginx/conf.d/00-unmask.conf to auto-load it.
	if err := renderToFile(nativeDir, "http.inc",
		"templates/http.conf.tmpl", data); err != nil {
		return err
	}
	// upstream.conf — upstream block that supports TCP/socket switching.
	// The unmask-web-nginx-shipped conf.d/unmask-web.conf does
	// `include /etc/unmask/upstream.conf;`.  Existing installs that
	// hand-wrote the upstream into unmask-web-nginx.conf don't include
	// this file, so its presence is harmless (= no regression).
	if err := renderToFile(outDir, "upstream.conf",
		"templates/upstream.conf.tmpl", data); err != nil {
		return err
	}
	// server scope: access_log syslog etc.  The user's vhost has a
	// single line `include /etc/unmask/native/server.inc;`.
	if err := renderToFile(nativeDir, "server.inc",
		"templates/server.inc.tmpl", data); err != nil {
		return err
	}
	// location/server scope: protection trigger (= rate-limit + final_challenge rewrite).
	if err := renderToFile(nativeDir, "protect.inc",
		"templates/protect.inc.tmpl", data); err != nil {
		return err
	}
	// migration: clean up old-file residue (= leaving them included
	// in existing deploys causes nginx to fail to start due to duplicate
	// upstream / location, so delete during render).
	for _, stale := range []string{
		"nginx-rendered.conf",
		"nginx-rendered-server.conf",
		"nginx-rendered-server.inc",
		"nginx-rendered-protect.inc",
	} {
		_ = os.Remove(filepath.Join(outDir, stale))
	}
	return nil
}

// buildUpstreamServer: look at settings.Server.Bind and return the
// value for the upstream block's `server XXX;`.
//   - TCP    : "host:port"  (= existing behavior)
//   - unix   : "unix:/path/to.sock"
//
// If bind has a "unix:" prefix, it's socket mode.
func buildUpstreamServer(s settings.Settings) string {
	bind := strings.TrimSpace(s.Server.Bind)
	if strings.HasPrefix(bind, "unix:") {
		return bind
	}
	host := bind
	if host == "" || host == "0.0.0.0" || host == "::" {
		// Point upstream at localhost (= proxy to the same-host admin).
		// Even if bind covers every interface, nginx can just talk to loopback.
		host = "127.0.0.1"
	}
	port := s.Server.Port
	if port == 0 {
		port = 9477
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func renderToFile(outDir, outName, tmplPath string, data any) error {
	body, err := fs.ReadFile(templatesFS, tmplPath)
	if err != nil {
		return fmt.Errorf("read template %s: %w", tmplPath, err)
	}
	t, err := template.New(outName).Parse(string(body))
	if err != nil {
		return fmt.Errorf("parse template %s: %w", tmplPath, err)
	}
	dst := filepath.Join(outDir, outName)
	tmp := dst + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", tmp, err)
	}
	if err := t.Execute(f, data); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("exec template: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("fsync: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("close: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// renderData: flat struct passed to text/template.
type renderData struct {
	GeneratedAt           string
	Version               string
	OutputDir             string
	BVSecret              string
	BVPowValidSeconds     int // unmask_bv_pow_valid_seconds     (= per-kind seconds)
	BVCaptchaValidSeconds int // unmask_bv_captcha_valid_seconds (= per-kind seconds)
	PowDifficulty         int
	// Resolved Global-axis actions for the no-match fallback in the
	// final_challenge nginx map.  fall-back ladder is KnownBrowserAction →
	// DefaultAction → "pow_only" (= the same chain handlers.go uses when
	// rendering chMode for the challenge HTML).  Values are exactly the
	// settings enum ("pass" / "pow_only" / "pow_then_captcha" /
	// "captcha_only" / "deny").  nginx side only cares whether they are
	// "pass" or not; the actual chain choice happens admin-side.
	KnownBrowserAction string
	UnknownUAAction    string
	UpstreamAddr       string
	// UpstreamServer: value to write for `server XXX;` in upstream.conf.
	// Switches based on the bind format:
	//   TCP    : "127.0.0.1:9477"
	//   socket : "unix:/run/unmask/admin.sock"
	// Determined by looking at server.bind in config.yml.
	UpstreamServer string

	SearchBotPatterns       []string // flatten of enabled presets + extras
	JA4Verdicts             []JA4VerdictRule
	HoneypotPatterns        []string            // OR list of honeypot path patterns
	ProtectedPaths          []ProtectedPathRule // protected paths {Pattern, Mode, Site}
	BypassPaths             []BypassPathRule    // whitelist paths {Pattern, Site} (= source-of-truth list)
	// BypassPathsGlobal / BypassPathsPerHost are the rendered split:
	// global rules feed a `map $request_uri ...` block directly, while per-host
	// rules group by Site and are emitted as separate path-only maps + a host
	// dispatcher map.  Both keep the original Pattern (= `^/api/` form) intact;
	// no anchor stripping needed because no map ever concatenates host + uri.
	BypassPathsGlobal  []string             // patterns from rules with Site == ""
	BypassPathsPerHost []BypassPathHostMaps // one entry per unique non-empty Site
	// ProtectedPathsGlobal / ProtectedPathsPerHost are the rendered split for
	// the protected-paths `map $request_uri $protected_mode` blocks.  Phase 2.2
	// adds per-host scoping: the default rules feed a global map and each site
	// with an Overrides[site] entry gets its own path-only map plus a dispatcher
	// `map $host $protected_mode_perhost` that picks which per-host map's value
	// to surface, identical layering to BypassPathsPerHost above.
	ProtectedPathsGlobal  []ProtectedPathRule          // rules with Site == ""
	ProtectedPathsPerHost []ProtectedPathHostMaps      // one entry per unique non-empty Site
	// ProtectedPathsDisablePerHost: paths the site explicitly Removes from the
	// default global list.  Phase 2.2's dispatcher reads this to subtract a
	// matched global rule for that host (= blog.local removing /admin/ blanks
	// $protected_mode for blog.local even though the global map matches).
	ProtectedPathsDisablePerHost []ProtectedPathDisableHostMaps
	ChallengeAll            bool                // true -> $is_challenge_target = 1 (= UA-agnostic)
	ChallengeTargetPatterns []string            // OR list of UA patterns evaluated when false

	BypassIPs []string // whitelist that lets challenge / rate_limit pass through (= IP or CIDR)
	// StatsExcludeIPs: IP/CIDR list dropped entirely from statistics (= own
	// monitoring tools etc.).  Rendered into the $is_bypass_ip geo (so they
	// skip the challenge) and into a dedicated $unmask_stats_excluded geo that
	// gates the unmask_minimal access_log via `if=`.
	StatsExcludeIPs []string
	BanFilePath     string // ban list file watched by the unmask module (= "" disables it)

	NginxLogEnabled bool
	NginxLogSocket  string

	AdminAllowFrom   []string
	MetricsAllowFrom []string

	LBIPRanges []LBIPRange // per-vendor LB IP range presets (= expand as geo $unmask_lb_<id>)

	// RateZones: derived from settings.RateLimit.  Render limit_req_zone into http {}.
	// [0] is the default zone (= when there's no name, use "unmask_rate").
	RateZones []RateZoneRender
	// DefaultRateZone: name + burst used for limit_req zone= in protect.inc.tmpl.
	DefaultRateZoneName  string
	DefaultRateZoneBurst int
	// RateLimitKeyExpr: nginx variable expression for the limit_req zone key.
	//   "ip"     -> "$binary_remote_addr"
	//   "ja4"    -> "$effective_ja4"
	//   "ip+ja4" -> "$binary_remote_addr$effective_ja4"
	// Empty Key falls back to "ip" (= back-compat with pre-existing installs).
	RateLimitKeyExpr string

	// GeoCIDRs: pre-rendered "  <cidr> <ISO>;\n" lines for every IP range
	// resolving to one of the operator-registered Geo rule countries.
	// Embedded into a `geo $remote_addr $unmask_country { ... }` block in
	// http.inc so the native nginx plugin path picks up country without
	// needing libmaxminddb.  $remote_addr (not $binary_remote_addr) is used
	// so real_ip rewrites (= set_real_ip_from + X-Forwarded-For) apply.
	// Empty when no Geo rules exist or the mmdb is missing — the geo block
	// then degrades to default "" and the action map's default "skip"
	// carries the request through unchanged.
	GeoCIDRs string
	// GeoRules: pre-resolved per-country actions for the $unmask_geo_action
	// map.  One entry per rule.Enabled.  Action falls back to ResolvedDefault
	// when the rule's own Action is empty.
	GeoRules []GeoRuleRender
	// GeoDefaultAction: action applied to countries NOT in GeoRules (= the
	// long-tail of unlisted countries).  Mirrors settings.Geo.DefaultAction.
	GeoDefaultAction string

	// SharedFeed: the unmask.sh community feed (= submit + pull from the
	// distribution-side install).  Include the 3 map snippets only when
	// SubscribeEnabled=true.  MapDir is the base directory of the include
	// (= sharedfeed.WriteMapFiles output destination).
	SharedFeedSubscribe bool
	SharedFeedMapDir    string
}

// RateZoneRender: zone values used to generate the nginx config.
type RateZoneRender struct {
	Name           string
	RequestsPerMin int
	Burst          int
}

// GeoRuleRender: one entry of the $unmask_geo_action map.
type GeoRuleRender struct {
	Country string // ISO 3166-1 alpha-2 uppercase
	Action  string // resolved action (= rule.Action || geo.DefaultAction)
}

func buildRenderData(s settings.Settings, outDir, version string) (renderData, error) {
	d := renderData{
		GeneratedAt:           time.Now().UTC().Format(time.RFC3339),
		Version:               version,
		OutputDir:             outDir,
		BVSecret:              s.Secret.BVSecret,
		// TODO(multi-site phase 2.2 nginx wire): the Challenge scalars below
		// (BV PoW / CAPTCHA cookie windows, PoW difficulty) are install-wide
		// in the rendered nginx output; the per-site Challenge.Overrides
		// (= Theme / PowDifficulty / ShowCredit) take effect today only via
		// the admin-side ServeChallenge path which calls
		// Challenge.Resolve(site).  PowDifficulty is the only one of the
		// three that flows into nginx render output; routing it per-site
		// would require a map $host $unmask_pow_difficulty + plugin support
		// for reading the variable.  Until that lands, native-module sites
		// fall back to the default PoW difficulty.
		BVPowValidSeconds:     s.Challenge.PowCookieValidSecondsResolved(),
		BVCaptchaValidSeconds: s.Challenge.CaptchaCookieValidSecondsResolved(),
		PowDifficulty:         s.Challenge.ResolvedPowDifficulty(),
		KnownBrowserAction:    resolveGlobalAction(s.Global.KnownBrowserAction, s.Global.DefaultAction),
		UnknownUAAction:       resolveGlobalAction(s.Global.UnknownUAAction, s.Global.DefaultAction),
		UpstreamAddr:          defStr(s.Nginx.UpstreamAddr, "127.0.0.1:9477"),
		UpstreamServer:        buildUpstreamServer(s),
		BypassIPs:             mergeBypassIPs(s),
		StatsExcludeIPs:       sanitizeIPs(s.Nginx.StatsExcludeIPs),
		BanFilePath:           trimSpaceAndQuotes(s.Nginx.Honeypot.BanFilePath),
		NginxLogSocket:        s.NginxLog.SocketPath,
		NginxLogEnabled:       s.NginxLog.Enabled && s.NginxLog.SocketPath != "",
		AdminAllowFrom:        defaultAllow(s.Nginx.AdminAllowFrom),
		MetricsAllowFrom:      defaultAllow(s.Nginx.MetricsAllowFrom),
		LBIPRanges:            effectiveLBs(s.Nginx.TrustedLBPresets, s.Nginx.TrustedLBExtra),
	}

	// search bots: merge enabled presets + extras.
	// Skip "presets newer than the user's seen_version" (= prevents
	// silent activation.  Treated as disabled until the user reviews
	// + saves on the settings page).
	seenVer := s.Nginx.SeenVersion
	disabledBots := toSet(s.Nginx.SearchBots.DisabledPresets)
	for _, g := range SearchBotGroups {
		if disabledBots[g.ID] {
			continue
		}
		if VersionLess(seenVer, g.AddedIn) && !g.DefaultOnWhenNew {
			continue
		}
		d.SearchBotPatterns = append(d.SearchBotPatterns, g.Patterns...)
	}
	for i, p := range s.Nginx.SearchBots.Extra {
		// ExtraDisabled[i]=true means temporarily OFF.  Don't emit into rendered conf.
		if i < len(s.Nginx.SearchBots.ExtraDisabled) && s.Nginx.SearchBots.ExtraDisabled[i] {
			continue
		}
		if p = trimSpaceAndQuotes(p); p != "" {
			d.SearchBotPatterns = append(d.SearchBotPatterns, p)
		}
	}

	// Upstream rescue groups (= crawler-user-agents.json categories).  Each
	// group resolves to "white" / "black" / "none" via classify; collect
	// patterns into the corresponding nginx map.  Per-pattern disable
	// (= SearchBots.UpstreamDisabled) wins over both directions.
	upstreamDisabled := toSet(s.Nginx.SearchBots.UpstreamDisabled)
	upstreamGroupWhitePatterns, upstreamGroupBlackPatterns := collectUpstreamPatternsByMode(
		s.Nginx.SearchBots.UpstreamGroupMode, upstreamDisabled)
	d.SearchBotPatterns = append(d.SearchBotPatterns, upstreamGroupWhitePatterns...)

	// challenge target UA: all=true is UA-agnostic.  Otherwise enabled presets + extras.
	d.ChallengeAll = s.Nginx.ChallengeTargets.All
	if !d.ChallengeAll {
		disabledTgt := toSet(s.Nginx.ChallengeTargets.DisabledPresets)
		seen := map[string]bool{}
		for _, g := range ChallengeTargetGroups {
			if disabledTgt[g.ID] {
				continue
			}
			if VersionLess(seenVer, g.AddedIn) {
				continue
			}
			for _, p := range g.Patterns {
				if !seen[p] {
					seen[p] = true
					d.ChallengeTargetPatterns = append(d.ChallengeTargetPatterns, p)
				}
			}
		}
		for i, p := range s.Nginx.ChallengeTargets.Extra {
			if i < len(s.Nginx.ChallengeTargets.ExtraDisabled) && s.Nginx.ChallengeTargets.ExtraDisabled[i] {
				continue
			}
			if p = trimSpaceAndQuotes(p); p != "" && !seen[p] {
				seen[p] = true
				d.ChallengeTargetPatterns = append(d.ChallengeTargetPatterns, p)
			}
		}
		// upstream rescue groups resolved to "black" mode.
		for _, p := range upstreamGroupBlackPatterns {
			if !seen[p] {
				seen[p] = true
				d.ChallengeTargetPatterns = append(d.ChallengeTargetPatterns, p)
			}
		}
	}

	// JA4 verdicts: enabled presets + extras.
	disabledV := toSet(s.Nginx.JA4Verdicts.DisabledPresets)
	for _, g := range JA4VerdictGroups {
		if disabledV[g.ID] {
			continue
		}
		if VersionLess(seenVer, g.AddedIn) {
			continue
		}
		d.JA4Verdicts = append(d.JA4Verdicts, g.Rules...)
	}
	for i, r := range s.Nginx.JA4Verdicts.Extra {
		if r.Pattern == "" || r.Verdict == "" {
			continue
		}
		// ExtraDisabled[i]=true means temporarily OFF.  Don't emit into rendered conf.
		if i < len(s.Nginx.JA4Verdicts.ExtraDisabled) && s.Nginx.JA4Verdicts.ExtraDisabled[i] {
			continue
		}
		action := r.Action
		if !IsValidJA4Action(action) {
			action = JA4ActionOK
		}
		d.JA4Verdicts = append(d.JA4Verdicts, JA4VerdictRule{
			Pattern: r.Pattern, Verdict: r.Verdict, Action: action,
		})
	}

	// honeypot: enabled preset groups + extras (= skip ExtraDisabled[i]=true).
	//
	// TODO(multi-site phase 2.2 nginx wire): emit a per-site honeypot map so
	// the resolved Extra patterns for each Honeypot.Overrides[site] (= default
	// list minus Override.Remove + AppendExtra rows) gate $serve_bot_challenge
	// by Host header in native nginx mode.  Current render only walks the
	// default scope, matching phase 2.1 admin-only override behaviour; the
	// per-site append / remove is honoured today only via auth_request mode
	// (= AuthCheck calls HoneypotConfig.Resolve(site)).  Wiring path: walk
	// gatherSites(s.Nginx.Honeypot.Overrides) and emit one map $host block
	// per site with the resolved Extra patterns joined into a regex group,
	// then OR them into $serve_bot_challenge alongside the default map.
	honeypotSet := map[string]bool{}
	disabledHP := toSet(s.Nginx.Honeypot.DisabledPresets)
	for _, g := range HoneypotPresetGroups {
		if disabledHP[g.ID] {
			continue
		}
		if VersionLess(seenVer, g.AddedIn) {
			continue
		}
		for _, p := range g.Patterns {
			honeypotSet[p] = true
		}
	}
	for i, p := range s.Nginx.Honeypot.Extra {
		if i < len(s.Nginx.Honeypot.ExtraDisabled) && s.Nginx.Honeypot.ExtraDisabled[i] {
			continue
		}
		if p = trimSpaceAndQuotes(p); p != "" {
			honeypotSet[p] = true
		}
	}
	hp := make([]string, 0, len(honeypotSet))
	for p := range honeypotSet {
		hp = append(hp, p)
	}
	sort.Strings(hp)
	d.HoneypotPatterns = hp

	// Protected paths: presets (= enabled / preset carries {Pattern, Mode}) +
	// per-site resolved Paths via Overrides[site].
	// DisabledPresets == nil means an existing yml where the protected
	// tab was never saved.  In that case every preset is OFF
	// (= compat-first: don't silently start protecting new paths in
	// existing deploys).
	//
	// Multi-site phase 2.2: BypassPaths / ProtectedPaths use the
	// Overrides[site] map for per-host scoping (replaces the old per-row
	// Site column).  buildPerSiteProtectedPaths resolves the default
	// (= Site == "") plus one set per Overrides key, dedupes against the
	// default, and rolls everything into ProtectedPathRule{Pattern, Mode, Site}.
	// splitProtectedPathsForRender then splits the merged list into the
	// global map + per-host map shape http.conf.tmpl renders.
	pp := []ProtectedPathRule{}
	ppSeen := map[string]bool{}
	enabledPP := toSet(s.Nginx.ProtectedPaths.EnabledPresets)
	for _, g := range ProtectedPathPresetGroups {
		if !enabledPP[g.ID] {
			continue
		}
		for _, r := range g.Rules {
			pat := trimSpaceAndQuotes(r.Pattern)
			key := "|" + pat
			if pat == "" || ppSeen[key] {
				continue
			}
			ppSeen[key] = true
			mode := r.Mode
			if !IsValidProtectedMode(mode) {
				mode = ProtectedModeCaptcha
			}
			pp = append(pp, ProtectedPathRule{Pattern: pat, Mode: mode})
		}
	}
	for _, e := range s.Nginx.ProtectedPaths.Paths {
		if e.Disabled {
			continue
		}
		p := trimSpaceAndQuotes(e.Path)
		key := "|" + p
		if p == "" || ppSeen[key] {
			continue
		}
		ppSeen[key] = true
		mode := e.Mode
		if !IsValidProtectedMode(mode) {
			mode = ProtectedModeCaptcha
		}
		pp = append(pp, ProtectedPathRule{Pattern: p, Mode: mode})
	}
	// Per-site Overrides walk.  Each site that declares an Overrides[site]
	// entry contributes the diff against the default:
	//   - Append rows -> emitted as Site-scoped ProtectedPathRule
	//     (= nginx side puts them in the per-host map only).
	//   - Remove rows -> emitted into ProtectedPathsDisablePerHost so the
	//     dispatcher map can subtract the default-matched path for that
	//     specific host (= blog.local removing /admin/ blanks
	//     $protected_mode for blog.local while leaving the global map
	//     untouched for the other sites).
	//   - Replaced EnabledPresets -> preset-level diff is a v0.3 follow-up;
	//     the row-level diff already covers the common-case append/remove
	//     flow exercised by e2e multi-site-basic.
	//
	// Resolve(site) returns the merged Paths slice with Remove already
	// applied + Append concatenated.  Diff vs the default Paths set gives
	// (Append, Remove) pairs to emit per-host.
	defaultProtectedPathSet := protectedDefaultPathSet(s.Nginx.ProtectedPaths)
	for _, site := range gatherSites(s.Nginx.ProtectedPaths.Overrides) {
		resolved := s.Nginx.ProtectedPaths.Resolve(site)
		siteSeen := map[string]bool{}
		resolvedSet := map[string]bool{}
		// Append diff: any non-default row in resolved.Paths is a site Append.
		for _, e := range resolved.Paths {
			if e.Disabled {
				continue
			}
			p := trimSpaceAndQuotes(e.Path)
			if p == "" {
				continue
			}
			resolvedSet[p] = true
			if defaultProtectedPathSet[p] {
				continue // covered by the default global map already
			}
			if siteSeen[p] {
				continue
			}
			siteSeen[p] = true
			mode := e.Mode
			if !IsValidProtectedMode(mode) {
				mode = ProtectedModeCaptcha
			}
			pp = append(pp, ProtectedPathRule{Pattern: p, Mode: mode, Site: site})
		}
		// Remove diff: any default path missing from resolved -> emit into
		// the disable map so the dispatcher subtracts the global match.
		removed := []string{}
		for p := range defaultProtectedPathSet {
			if !resolvedSet[p] {
				removed = append(removed, p)
			}
		}
		if len(removed) > 0 {
			sort.Strings(removed)
			d.ProtectedPathsDisablePerHost = append(d.ProtectedPathsDisablePerHost,
				ProtectedPathDisableHostMaps{
					Host:     site,
					VarName:  hostToNginxVarSegment(site),
					Patterns: removed,
				})
		}
	}
	sort.Slice(d.ProtectedPathsDisablePerHost, func(i, j int) bool {
		return d.ProtectedPathsDisablePerHost[i].Host < d.ProtectedPathsDisablePerHost[j].Host
	})
	sort.Slice(pp, func(i, j int) bool {
		if pp[i].Site != pp[j].Site {
			return pp[i].Site < pp[j].Site
		}
		return pp[i].Pattern < pp[j].Pattern
	})
	d.ProtectedPaths = pp
	d.ProtectedPathsGlobal, d.ProtectedPathsPerHost = splitProtectedPathsForRender(pp)

	// Whitelist paths: enabled presets + per-site resolved Paths.
	//
	// Patterns are stored as path-anchored PCRE (e.g., `^/api/`) and are
	// evaluated against `$request_uri` in the rendered nginx map -- no host
	// concatenation, so `^` keeps its natural "start of path" meaning.  Per-host
	// rules are split off into separate maps below; the host is selected by a
	// dispatcher map, never embedded in the path pattern.
	//
	// Preset opt-in: only IDs explicitly listed in EnabledPresets render.
	// Matches the "All OFF by default" docstring on BypassPathPresetGroups.
	//
	// Multi-site phase 2.2: BypassPathsConfig.Overrides[site].Append rows are
	// resolved via Resolve(site) and emitted as Site-scoped BypassPathRule
	// entries so splitBypassPathsForRender groups them into the per-host map.
	// Remove rows simply omit the path from the per-host map -- bypass is a
	// passthrough, so "host had it removed" naturally degrades to "no bypass"
	// (= no need for a separate disable map; the global rule for that path
	// has already been emitted under "" Site so the host inherits it unless
	// it explicitly opted out, and the Remove diff handling is per-host only
	// because BypassPath rules in the default global map are always desired
	// site-wide -- a future v0.3 may add per-host Remove of a global bypass
	// when an operator wants to gate /api/ on one site only).
	bp := []BypassPathRule{}
	bpSeen := map[string]bool{}
	enabledBPath := toSet(s.Nginx.BypassPaths.EnabledPresets)
	for _, g := range BypassPathPresetGroups {
		if !enabledBPath[g.ID] {
			continue
		}
		if VersionLess(seenVer, g.AddedIn) {
			continue
		}
		for _, r := range g.Rules {
			key := r.Site + "|" + r.Pattern
			if bpSeen[key] {
				continue
			}
			bpSeen[key] = true
			bp = append(bp, BypassPathRule{Pattern: r.Pattern, Site: r.Site})
		}
	}
	for _, e := range s.Nginx.BypassPaths.Paths {
		if e.Disabled {
			continue
		}
		p := trimSpaceAndQuotes(e.Path)
		if p == "" {
			continue
		}
		key := "|" + p
		if bpSeen[key] {
			continue
		}
		bpSeen[key] = true
		bp = append(bp, BypassPathRule{Pattern: p, Site: ""})
	}
	// Per-site Overrides walk: emit Append rows as Site-scoped BypassPathRule.
	// Removes are silently honored by not re-emitting the global row for that
	// site -- bypass paths are additive, so a per-host omission means "no
	// bypass for this host" which is the default state anyway (= the global
	// row still applies; per-host Remove of a global bypass is a v0.3 follow-
	// up that would mirror the protected-paths disable map).
	defaultBypassPathSet := bypassDefaultPathSet(s.Nginx.BypassPaths)
	for _, site := range gatherSites(s.Nginx.BypassPaths.Overrides) {
		resolved := s.Nginx.BypassPaths.Resolve(site)
		siteSeen := map[string]bool{}
		for _, e := range resolved.Paths {
			if e.Disabled {
				continue
			}
			p := trimSpaceAndQuotes(e.Path)
			if p == "" {
				continue
			}
			if defaultBypassPathSet[p] {
				continue // already covered by the global path map
			}
			if siteSeen[p] {
				continue
			}
			siteSeen[p] = true
			key := site + "|" + p
			if bpSeen[key] {
				continue
			}
			bpSeen[key] = true
			bp = append(bp, BypassPathRule{Pattern: p, Site: site})
		}
	}
	sort.Slice(bp, func(i, j int) bool {
		if bp[i].Site != bp[j].Site {
			return bp[i].Site < bp[j].Site
		}
		return bp[i].Pattern < bp[j].Pattern
	})
	d.BypassPaths = bp

	// Split into the render-friendly form used by http.conf.tmpl: a single
	// global map keyed on $request_uri + one path-only map per unique host
	// + a host dispatcher map.  Keeping the path patterns alone in each map
	// means `^/api/` is honored literally with no double-anchor wart.
	d.BypassPathsGlobal, d.BypassPathsPerHost = splitBypassPathsForRender(bp)

	// RateLimit zones: default goes first, followed by named zones in order.
	// If Default.Name is empty, fall back to "unmask_rate" (= matches
	// protect.inc and existing install examples).  RequestsPerMin/Burst
	// should be filled in by settings.defaults() to 100/50 when 0, but
	// we apply a safe fallback here too.
	//
	// TODO(multi-site phase 2.2 nginx wire): emit per-site limit_req_zone
	// blocks so each Host gets its own bucket sized by the resolved
	// RateLimit.Overrides[site].Default-zone knobs (rpm / burst / window).
	// Today this renders only the default-scope zone -- per-site rpm / burst
	// overrides are honoured today only via auth_request mode (= AuthCheck
	// calls RateLimitConfig.Resolve(site) before counting).  Wiring path:
	// walk gatherSites(s.RateLimit.Overrides), name the per-site zone
	// "<defaultName>_<sitehash>", and select via map $host $rate_limit_zone.
	// Key kind stays install-wide so the counter expression doesn't fork
	// per site.
	defaultName := strings.TrimSpace(s.RateLimit.Default.Name)
	if defaultName == "" {
		defaultName = "unmask_rate"
	}
	defaultRPM := s.RateLimit.Default.RequestsPerMin
	if defaultRPM <= 0 {
		defaultRPM = 100
	}
	defaultBurst := s.RateLimit.Default.Burst
	if defaultBurst <= 0 {
		defaultBurst = 50
	}
	d.RateZones = append(d.RateZones, RateZoneRender{
		Name:           defaultName,
		RequestsPerMin: defaultRPM,
		Burst:          defaultBurst,
	})
	d.DefaultRateZoneName = defaultName
	d.DefaultRateZoneBurst = defaultBurst
	switch s.RateLimit.ResolvedKey() {
	case settings.RateLimitKeyJA4:
		d.RateLimitKeyExpr = "$effective_ja4"
	case settings.RateLimitKeyIPAndJA4:
		d.RateLimitKeyExpr = "$binary_remote_addr$effective_ja4"
	default:
		d.RateLimitKeyExpr = "$binary_remote_addr"
	}
	zoneNamesSeen := map[string]bool{defaultName: true}
	for _, z := range s.RateLimit.Zones {
		name := strings.TrimSpace(z.Name)
		if name == "" || zoneNamesSeen[name] {
			continue
		}
		zoneNamesSeen[name] = true
		rpm := z.RequestsPerMin
		if rpm <= 0 {
			rpm = defaultRPM
		}
		burst := z.Burst
		if burst <= 0 {
			burst = defaultBurst
		}
		d.RateZones = append(d.RateZones, RateZoneRender{
			Name:           name,
			RequestsPerMin: rpm,
			Burst:          burst,
		})
	}

	// Geo (native mode): walk the mmdb once at render time to materialise a
	// `geo $binary_remote_addr $unmask_country { ... }` block listing only
	// the CIDRs of countries the operator has rules for.  The plugin can
	// then route on $unmask_country without needing libmaxminddb.
	// auth_request mode keeps doing live lookups via the admin /authcheck
	// handler so behavior matches across the two modes.
	d.GeoDefaultAction = s.Nginx.Geo.ResolvedDefaultAction()
	geoCountrySet := map[string]bool{}
	for _, r := range s.Nginx.Geo.Rules {
		if !r.Enabled {
			continue
		}
		cc := strings.ToUpper(strings.TrimSpace(r.Country))
		if cc == "" || geoCountrySet[cc] {
			continue
		}
		geoCountrySet[cc] = true
		action := strings.TrimSpace(r.Action)
		if action == "" {
			action = d.GeoDefaultAction
		}
		if !settings.IsValidGeoAction(action) {
			action = settings.GeoActionSkip
		}
		d.GeoRules = append(d.GeoRules, GeoRuleRender{Country: cc, Action: action})
	}
	sort.Slice(d.GeoRules, func(i, j int) bool { return d.GeoRules[i].Country < d.GeoRules[j].Country })
	if len(d.GeoRules) > 0 && strings.TrimSpace(s.IPGeo.MMDBPath) != "" {
		codes := make([]string, 0, len(d.GeoRules))
		for _, g := range d.GeoRules {
			codes = append(codes, g.Country)
		}
		if cidrs, err := ipgeo.GeoCIDRsForCountries(s.IPGeo.MMDBPath, codes); err == nil {
			d.GeoCIDRs = cidrs
		}
		// On error: silently leave GeoCIDRs empty.  The geo block then
		// degrades to default "" → action map default action.  Operators
		// see the WARN in `unmask-admin doctor` (= mmdb path check).
	}

	// SharedFeed: render the 3 maps only when subscribe is ON.
	// MapDir priority: SharedFeed.MapDir > Nginx.OutputDir > "/etc/unmask".
	if s.SharedFeed.SubscribeEnabled {
		d.SharedFeedSubscribe = true
		md := strings.TrimSpace(s.SharedFeed.MapDir)
		if md == "" {
			md = strings.TrimSpace(s.Nginx.OutputDir)
		}
		if md == "" {
			md = "/etc/unmask"
		}
		d.SharedFeedMapDir = md
	}

	return d, nil
}

func toSet(xs []string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// collectUpstreamPatternsByMode walks the upstream rescue groups and returns
// the patterns that should land in the white map and the black map
// respectively.  Mode is resolved per-category via classify.ResolveGroupMode.
// Patterns listed in disabledSet are skipped regardless of mode (= explicit
// per-pattern OFF wins over the group default).
func collectUpstreamPatternsByMode(overrides map[string]string, disabledSet map[string]bool) (white, black []string) {
	groups := classify.UpstreamRescueList()
	whiteSeen := map[string]bool{}
	blackSeen := map[string]bool{}
	for cat, entries := range groups {
		mode := classify.ResolveGroupMode(cat, overrides)
		switch mode {
		case classify.GroupModeWhite:
			for _, e := range entries {
				if e.Pattern == "" || disabledSet[e.Pattern] || whiteSeen[e.Pattern] {
					continue
				}
				whiteSeen[e.Pattern] = true
				white = append(white, e.Pattern)
			}
		case classify.GroupModeBlack:
			for _, e := range entries {
				if e.Pattern == "" || disabledSet[e.Pattern] || blackSeen[e.Pattern] {
					continue
				}
				blackSeen[e.Pattern] = true
				black = append(black, e.Pattern)
			}
		}
	}
	return white, black
}

func defStr(v, fallback string) string {
	if v == "" {
		return fallback
	}
	return v
}

func defaultAllow(xs []string) []string {
	if len(xs) == 0 {
		return []string{"127.0.0.1", "::1"}
	}
	return xs
}

// mergeBypassIPs: merge the official presets (= enabled) + user row-UI
// entries (= disabled[i]=false).  Order is preset -> user.  Deduplicated.
func mergeBypassIPs(s settings.Settings) []string {
	out := []string{}
	seen := map[string]bool{}
	for _, p := range FlattenBypassPresets(s.Nginx.BypassIPEnabledPresets) {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	for _, p := range sanitizeBypassIPs(s.Nginx.BypassIPs, s.Nginx.BypassIPsDisabled) {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// sanitizeBypassIPs: validate BypassIPs while skipping rows where
// Disabled[i]=true (= don't emit temporarily-OFF rows into rendered conf).
func sanitizeBypassIPs(ips []string, disabled []bool) []string {
	out := make([]string, 0, len(ips))
	seen := map[string]bool{}
	for i, x := range ips {
		x = strings.TrimSpace(x)
		if x == "" || seen[x] {
			continue
		}
		if i < len(disabled) && disabled[i] {
			continue
		}
		if _, _, err := net.ParseCIDR(x); err != nil {
			if ip := net.ParseIP(x); ip == nil {
				continue
			}
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

// sanitizeIPs: validate each bypass_ips element as IP or CIDR and keep
// it.  Invalid values are sunk into a black hole (= prevent nginx
// startup failure).  Input order is preserved (= the order the
// operator wrote them in yml = the order shown in the web textarea).
func sanitizeIPs(xs []string) []string {
	out := make([]string, 0, len(xs))
	seen := map[string]bool{}
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x == "" || seen[x] {
			continue
		}
		if _, _, err := net.ParseCIDR(x); err != nil {
			if ip := net.ParseIP(x); ip == nil {
				continue
			}
		}
		seen[x] = true
		out = append(out, x)
	}
	return out
}

// Reject values containing quoting / control characters.  Prevents
// putting newlines or `"` into config.yml from breaking an nginx
// directive.  Regex metacharacters (= including backslashes) are
// allowed so that legitimate regexes like /wp-login\.php /
// ^/admin\.php aren't rejected.
// resolveGlobalAction: same fallback ladder handlers.go uses when picking
// the chain for the "no-match" path: per-axis setting → DefaultAction →
// "pow_only" as the strict default.  Returned verbatim into http.inc so
// nginx can decide whether to challenge ($action != "pass") without
// duplicating the resolution table.
func resolveGlobalAction(axis, fallback string) string {
	if axis != "" {
		return axis
	}
	if fallback != "" {
		return fallback
	}
	return "pow_only"
}

// gatherSites returns the deterministic list of site keys to walk for a
// per-site Overrides map.  The default scope ("" / "default") is intentionally
// excluded -- the default is handled separately by the global path map.  The
// returned slice is sorted so render output stays byte-stable across runs;
// empty / whitespace-only keys are dropped (defensive against yaml typos).
//
// Multi-site phase 2.2 helper used by both bypass-paths and protected-paths
// per-site renderers.  Generic on the override value type so the same helper
// works for {Bypass,Protected}PathsOverride (and for future
// {Challenge,RateLimit,Honeypot}Override maps when phase 2.1 schema lands).
func gatherSites[V any](overrides map[string]V) []string {
	if len(overrides) == 0 {
		return nil
	}
	sites := make([]string, 0, len(overrides))
	for k := range overrides {
		k = strings.TrimSpace(k)
		if k == "" || k == "default" {
			continue
		}
		sites = append(sites, k)
	}
	sort.Strings(sites)
	return sites
}

// bypassDefaultPathSet: set of (trimmed, non-empty, non-disabled) Path strings
// in the default BypassPaths list.  Used by the per-site walk to dedupe
// Append rows against the default global map (= avoids emitting the same row
// once per site).
func bypassDefaultPathSet(c settings.BypassPathsConfig) map[string]bool {
	out := map[string]bool{}
	for _, e := range c.Paths {
		if e.Disabled {
			continue
		}
		p := trimSpaceAndQuotes(e.Path)
		if p == "" {
			continue
		}
		out[p] = true
	}
	return out
}

// protectedDefaultPathSet: same as bypassDefaultPathSet for ProtectedPaths.
func protectedDefaultPathSet(c settings.ProtectedPathsConfig) map[string]bool {
	out := map[string]bool{}
	for _, e := range c.Paths {
		if e.Disabled {
			continue
		}
		p := trimSpaceAndQuotes(e.Path)
		if p == "" {
			continue
		}
		out[p] = true
	}
	return out
}

var controlChars = regexp.MustCompile(`[\x00-\x1f"]`)

func trimSpaceAndQuotes(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	if controlChars.MatchString(s) {
		return ""
	}
	return s
}
