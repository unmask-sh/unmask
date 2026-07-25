// nginxconf.Render: generate nginx config snippets for native mode
// from settings.
//
// Output (= unified under <OutputDir>/.  Restructured on 2026-05-13):
//   - http.inc       http scope: JA4 maps + assorted decision maps + log_format + unmask upstream
//   - server.inc     server scope: access_log syslog + ban enforcement +
//     @unmask_rate_challenge + `location ^~ /unmask/` proxy
//     to admin.  Restricting which Host gets the admin UI is
//     done at the HTTP layer by settings.Nginx.AdminAllowedHosts.
//   - protect.inc    location/server scope: limit_req + final_challenge rewrite
//
// The forward-auth-mode static snippets (= /etc/unmask/forward-auth/{server,protect}.inc)
// are placed by the unmask-web-nginx package (= this code does not touch them).
//
// Callers:
//   - CLI: `unmask render-nginx [-config PATH] [-out-dir DIR]`
//   - web: will be called from the handler after settings are saved
//     (= no auto-reload, but render runs)
package nginxconf

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
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
// <outDir>/.
//   - <outDir>/http.inc      http scope: JA4 maps / log_format / rate-zone
//   - <outDir>/server.inc    server scope: access_log + ban + @unmask_rate_challenge + `location ^~ /unmask/`
//   - <outDir>/protect.inc   location/server scope: protection trigger
//     (= the unmask upstream block now lives at the tail of http.inc)
//
// If outDir is empty, settings.Nginx.OutputDir is used (= default /var/lib/unmask/nginx).
// version is for display (= written in the header of the generated file).
func Render(s settings.Settings, outDir, version string) error {
	if outDir == "" {
		outDir = s.Nginx.OutputDir
	}
	if outDir == "" {
		outDir = "/var/lib/unmask/nginx"
	}
	// outDir is already the nginx-specific dir (= /var/lib/unmask/nginx/);
	// the renderer writes directly into it, no sub-directory.  When apache
	// support lands it gets its own /var/lib/unmask/apache/ alongside.
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return fmt.Errorf("mkdir %s: %w", outDir, err)
	}

	data, err := buildRenderData(s, outDir, version)
	if err != nil {
		return err
	}
	// Surface a host map_hash mismatch (probed in buildRenderData) once per actual
	// render.  RenderSignature shares buildRenderData but must not log, so the
	// warning rides on the (unexported) renderData field and is emitted only here.
	if data.mapHashWarning != "" {
		log.Printf("unmask: WARNING: %s", data.mapHashWarning)
	}

	// http scope: JA4 maps / log_format / rate-zone.  The postinstall
	// drops a symlink to /etc/nginx/conf.d/00-unmask.conf to auto-load it.
	if err := renderToFile(outDir, "http.inc",
		"templates/http.conf.tmpl", data, 0o640); err != nil { // 0640: carries bv_secret
		return err
	}
	// upstream.conf was retired -- the `upstream unmask { ... }` block
	// now lives at the tail of http.inc so a single `include http.inc;`
	// covers it (= one fewer file + one fewer symlink in conf.d/).
	// server scope: access_log + ban enforcement + @unmask_rate_challenge +
	// `location ^~ /unmask/` proxy.  The user's vhost adds
	// `include /var/lib/unmask/nginx/server.inc;` on each vhost where the
	// challenge should fire OR the admin UI should be reachable.  Per-host
	// gating of /admin/* is done at the HTTP layer (= AdminAllowedHosts).
	if err := renderToFile(outDir, "server.inc",
		"templates/server.inc.tmpl", data, 0o644); err != nil {
		return err
	}
	// location/server scope: protection trigger (= rate-limit + final_challenge rewrite).
	if err := renderToFile(outDir, "protect.inc",
		"templates/protect.inc.tmpl", data, 0o644); err != nil {
		return err
	}
	// http scope (forward-auth): defines $unmask_fa_ja4 = the LB-forwarded client
	// JA4 gated on the source IP being a trusted LB, for forward-auth/server.inc.
	// Always emitted (a no-op `default ""` when no LB is configured) so the
	// variable resolves and `nginx -t` passes; the unmask-web-nginx postinstall
	// symlinks it into conf.d/.  Plugin-var-free, so it loads without the module.
	if err := renderToFile(outDir, "forward-auth-lbtrust.conf",
		"templates/forward-auth-lbtrust.conf.tmpl", data, 0o644); err != nil {
		return err
	}
	// The daemon upstream both deploy modes proxy to (`upstream
	// unmask_daemon`) -- the ONLY place it is defined (http.inc carries
	// none, so loading http.inc + upstream.conf together never duplicates
	// it).  The unmask-web-nginx postinstall symlinks it into conf.d/.
	// Rendered (not just postinstall-generated) so it tracks server.bind /
	// port on every save.
	if err := renderToFile(outDir, "upstream.conf",
		"templates/upstream.conf.tmpl", data, 0o644); err != nil {
		return err
	}
	// The http.inc just written `include`s the community-bans map files when
	// fetch_apply mode is active (= data.CommunityBansMapDir is then non-empty).
	// Those files are normally produced by the community-bans pull loop, which
	// only runs once the admin daemon is up -- so a fresh install's
	// `unmask render-nginx` (postinstall) would emit an http.inc that `nginx -t`
	// rejects with "open() .../community-bans-*.map failed" until the daemon's
	// first tick.  Lay down empty placeholders here, keyed on the same condition
	// and dir as the include, so the rendered config is always self-consistent.
	// Populated maps are never clobbered (O_EXCL).
	if data.CommunityBansMapDir != "" {
		ensureCommunityBanMapPlaceholders(data.CommunityBansMapDir)
	}
	return nil
}

// communityBanMapFiles are the 3 nginx map snippets http.inc `include`s in
// fetch_apply mode.  Kept in sync by hand with communitybans.WriteMapFiles: the
// import graph (communitybans -> nginxconf) forbids importing that writer here,
// so Render lays down its own empty placeholders.
var communityBanMapFiles = []string{
	"community-bans-ipja4.map",
	"community-bans-ja4.map",
	"community-bans-ip.map",
}

// ensureCommunityBanMapPlaceholders creates an empty community-bans map file in
// dir for each name that does not exist yet, so http.inc's `include` directives
// resolve before the community-bans pull loop's first write.  O_EXCL leaves an
// already-present file (placeholder or daemon-populated) untouched and refuses
// to follow a symlink.  Best-effort: a failure just defers to the daemon, so
// Render never errors on it.
func ensureCommunityBanMapPlaceholders(dir string) {
	const header = "# generated by unmask communitybans. DO NOT EDIT.\n"
	for _, name := range communityBanMapFiles {
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if err != nil {
			continue // already exists, or a write error we leave to the daemon
		}
		_, _ = f.WriteString(header)
		_ = f.Close()
	}
}

// buildUpstreamServer: look at settings.Server.Bind and return the
// value for the upstream block's `server XXX;`.
//   - TCP    : "host:port"  (= existing behavior)
//   - unix   : "unix:/path/to.sock"
//
// nginx.upstream_addr overrides the bind-derived form when set -- useful
// when nginx and admin live in different network namespaces (docker
// compose, k8s sidecar) and the upstream needs the service hostname
// instead of the loopback address admin binds to.  If bind has a "unix:"
// prefix, it's socket mode.
func buildUpstreamServer(s settings.Settings) string {
	if addr := strings.TrimSpace(s.Nginx.UpstreamAddr); addr != "" {
		return addr
	}
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

func renderToFile(outDir, outName, tmplPath string, data any, perm os.FileMode) error {
	body, err := fs.ReadFile(templatesFS, tmplPath)
	if err != nil {
		return fmt.Errorf("read template %s: %w", tmplPath, err)
	}
	t, err := template.New(outName).Parse(string(body))
	if err != nil {
		return fmt.Errorf("parse template %s: %w", tmplPath, err)
	}
	dst := filepath.Join(outDir, outName)
	// CreateTemp uses a random name + O_EXCL, so a pre-planted symlink at a
	// predictable "<dst>.tmp" path can't redirect this (possibly root-run) write
	// to an attacker-chosen target.
	f, err := os.CreateTemp(outDir, outName+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp in %s: %w", outDir, err)
	}
	tmp := f.Name()
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
	// CreateTemp makes the file 0600; set the intended perm before publishing.
	// http.inc carries bv_secret, so it must not be world-readable.
	if err := os.Chmod(tmp, perm); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("chmod: %w", err)
	}
	if err := os.Rename(tmp, dst); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// renderToString: same template execute as renderToFile, returns the output
// as a string instead of writing it.  Used by RenderSignature.
func renderToString(tmplPath string, data any) (string, error) {
	body, err := fs.ReadFile(templatesFS, tmplPath)
	if err != nil {
		return "", fmt.Errorf("read template %s: %w", tmplPath, err)
	}
	t, err := template.New(tmplPath).Parse(string(body))
	if err != nil {
		return "", fmt.Errorf("parse template %s: %w", tmplPath, err)
	}
	var b strings.Builder
	if err := t.Execute(&b, data); err != nil {
		return "", fmt.Errorf("exec template %s: %w", tmplPath, err)
	}
	return b.String(), nil
}

// RenderSignature: render all nginx fragments for the given settings and
// return their concatenation.  Two settings snapshots produce identical
// signatures iff the rendered nginx conf would be byte-identical -- so the
// settings-save handler can compare before/after and prompt for a reload
// ONLY when the conf actually changed.  No files are written.
//
// REQUIRES the render to be deterministic: every map iterated into the
// output must be sorted first (= see collectUpstreamPatternsByMode).  The
// volatile GeneratedAt timestamp is blanked here so identical settings match.
func RenderSignature(s settings.Settings, outDir, version string) (string, error) {
	if outDir == "" {
		outDir = s.Nginx.OutputDir
	}
	if outDir == "" {
		outDir = "/var/lib/unmask/nginx"
	}
	data, err := buildRenderData(s, outDir, version)
	if err != nil {
		return "", err
	}
	data.GeneratedAt = ""
	var sig strings.Builder
	for _, tmpl := range []string{
		"templates/http.conf.tmpl",
		"templates/server.inc.tmpl",
		"templates/protect.inc.tmpl",
		"templates/forward-auth-lbtrust.conf.tmpl",
		"templates/upstream.conf.tmpl",
	} {
		out, err := renderToString(tmpl, data)
		if err != nil {
			return "", err
		}
		sig.WriteString("\x00" + tmpl + "\x00")
		sig.WriteString(out)
	}
	return sig.String(), nil
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
	// Stale-browser tier (Global.StaleBrowserEnabled).  When off, none of
	// these are used and the template emits its original $final_challenge map
	// verbatim (zero rendered-config diff on upgrade).  When on:
	//   StaleBrowserPattern : an nginx regex matching a Chrome/<major>. token
	//                         whose major is >= StaleBrowserLag behind current
	//                         stable (built by staleBrowserPattern()).
	StaleBrowserEnabled bool
	StaleBrowserPattern string
	UpstreamAddr        string
	// UpstreamServer: value to write for `server XXX;` in upstream.conf.
	// Switches based on the bind format:
	//   TCP    : "127.0.0.1:9477"
	//   socket : "unix:/run/unmask/http.sock"
	// Determined by looking at server.bind in config.yml.
	UpstreamServer string

	SearchBotPatterns []string // flatten of enabled presets + extras
	// RangeVerifiedUACount: crawler UA patterns deliberately absent from
	// SearchBotPatterns because their vendor's IP-range presets carry the
	// rescue (see uarange.go).  Rendered as a conf comment so an operator
	// diffing the conf understands why a Googlebot line is missing.
	RangeVerifiedUACount int
	JA4Verdicts          []JA4VerdictRule
	HoneypotPatterns     []string // OR list of honeypot path patterns (= deprecated; kept while callers migrate)
	// HoneypotPatternsGlobal / HoneypotPatternsPerHost are the per-site
	// render split: one global path map + one map per unique Site + a host
	// dispatcher.  Same four-stage shape as Bypass paths.
	HoneypotPatternsGlobal  []string            // patterns from rules with Site == ""
	HoneypotPatternsPerHost []HoneypotHostMaps  // one entry per unique non-empty Site
	ProtectedPaths          []ProtectedPathRule // protected paths {Pattern, Mode, Site} (= source-of-truth list)
	// ProtectedPathsGlobal / ProtectedPathsPerHost are the rendered split:
	// global rules emit one path -> mode map; per-host rules emit one path
	// map per unique Site plus a host dispatcher (= same pattern as bypass).
	ProtectedPathsGlobal  []ProtectedPathRule     // rules with Site == ""
	ProtectedPathsPerHost []ProtectedPathHostMaps // one entry per unique non-empty Site
	BypassPaths           []BypassPathRule        // whitelist paths {Pattern, Site} (= source-of-truth list)
	// BypassPathsGlobal / BypassPathsPerHost are the rendered split:
	// global rules feed a `map $request_uri ...` block directly, while per-host
	// rules group by Site and are emitted as separate path-only maps + a host
	// dispatcher map.  Both keep the original Pattern (= `^/api/` form) intact;
	// no anchor stripping needed because no map ever concatenates host + uri.
	BypassPathsGlobal       []string               // patterns from rules with Site == ""
	BypassPathsPerHost      []BypassPathHostMaps   // one entry per unique non-empty Site
	ChallengeAll            bool                   // true -> $is_challenge_target = 1 (= UA-agnostic)
	ChallengeTargetPatterns []string               // OR list of UA patterns evaluated when false
	HTTPSRedirect           bool                   // true -> emit an HTTP->HTTPS 301 at the top of server.inc
	HTTPSRedirectExempt     []RedirectExemptClause // rewrite-phase `break`s emitted before the 301 (ACME path + LB-health UA presets + custom rules)

	BypassIPs []string // whitelist that lets challenge / rate_limit pass through (= IP or CIDR)
	// StatsExcludeIPs: IP/CIDR list dropped entirely from statistics (= own
	// monitoring tools etc.).  Rendered into the $is_bypass_ip geo (so they
	// skip the challenge) and into a dedicated $unmask_stats_excluded geo that
	// gates the unmask_minimal access_log via `if=`.
	StatsExcludeIPs []string
	BanFilePath     string // ban list file watched by the unmask module (= "" disables it)

	NginxLogEnabled bool
	NginxLogSocket  string

	// Admin / metrics IP allowlists are NOT rendered into nginx config: both
	// are enforced at the admin HTTP layer (AdminIPAllowMiddleware /
	// handlers.Metrics), which works identically across native and
	// forward-auth modes.  They used to be copied into this struct anyway,
	// which no template ever read — removed so the data flow matches reality.

	LBIPRanges []LBIPRange // per-vendor LB IP range presets (= expand as geo $unmask_lb_<id>)

	// RateZones: derived from settings.RateLimit.  Render limit_req_zone into http {}.
	// [0] is the default zone (= when there's no name, use "unmask_rate").
	RateZones []RateZoneRender
	// RatePathZones: path-pattern zones applied with a path-conditional key in
	// protect.inc (= no shadow location).  See RatePathZoneRender.
	RatePathZones []RatePathZoneRender
	// DefaultRateZone: name + burst used for limit_req zone= in protect.inc.tmpl.
	DefaultRateZoneName  string
	DefaultRateZoneBurst int
	// ComposeMode: true when the host nginx supports limit_req_dry_run (>= 1.17.6),
	// resolved by ComposeCapable (nginx.rate_compose_mode override + the startup
	// probe).  Switches protect.inc to the unified flow -- limit_req runs in
	// dry-run and the plugin's ACCESS-phase handler composes the rate + captcha
	// decision, so a deny zone can win over the protected captcha (which the
	// REWRITE-phase gate would otherwise pre-empt).  Off -> the classic
	// error_page-429 + rewrite flow (the only valid flow on nginx < 1.17.1, where
	// limit_req_dry_run would fail `nginx -t`).
	ComposeMode bool
	// RateLimitKeyExpr: nginx variable expression for the limit_req zone key.
	//   "ip"     -> "$unmask_client_net"
	//   "ja4"    -> "$effective_ja4"
	//   "ip+ja4" -> "$unmask_client_net$effective_ja4"
	// Empty Key falls back to "ip" (= the default).  $unmask_client_net is the
	// plugin-provided client IP folded to a network granularity (IPv4 = /32,
	// IPv6 = /64) so a v6 client can't multiply its budget by rotating privacy
	// addresses within its /64; native-only (the plugin sets it), which is the
	// only mode render.go emits -- forward-auth's static snippets keep
	// $binary_remote_addr.
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

	// AsnCIDRs / AsnRules / AsnDefaultAction: the by-network sibling of the
	// Geo* fields above.  Native mode gets a `geo $remote_addr $unmask_asn`
	// block (only the CIDRs of the operator's targeted ASNs, walked from the
	// ASN mmdb) + a `map $unmask_asn $unmask_asn_action` block.  Empty when no
	// ASN rules exist or the ASN mmdb is missing -- the axis then no-ops.
	AsnCIDRs         string
	AsnRules         []AsnRuleRender
	AsnDefaultAction string

	// CommunityBans: the unmask.sh community feed (= submit + pull from the
	// distribution-side install).  Include the 3 map snippets only when
	// CommunityBansSubscribe is true.  MapDir is the base directory of the
	// include (= communitybans.WriteMapFiles output destination).
	CommunityBansSubscribe bool
	CommunityBansMapDir    string
	// CommunityBansMapHashBucket/Max: emit map_hash_bucket_size / map_hash_max_size
	// at the top of http.inc.  The community-bans ipja4 key reaches ~76 chars with
	// an IPv6 address and overflows nginx's default map_hash_bucket_size (64), and a
	// large feed exceeds the default map_hash_max_size (2048).  Each is set only when
	// fetch_apply is active AND the host nginx.conf does not already declare that
	// directive (a duplicate is a fatal `nginx -t` error).  See buildRenderData.
	CommunityBansMapHashBucket bool
	CommunityBansMapHashMax    bool

	// EmitVariablesHash: emit variables_hash_max_size / _bucket_size at the top
	// of http.inc.  unmask's many maps (rate-limit / per-site / challenge axes)
	// push nginx's variables hash past its 1024 default, so nginx warns "could
	// not build optimal variables_hash" on every reload.  Unlike map_hash these
	// are not tied to a preceding map block, so it is emitted whenever the host
	// nginx.conf does not already declare one (a duplicate is a fatal error).
	EmitVariablesHash bool

	// WebBotAuthEnabled mirrors settings.Nginx.WebBotAuthActive() (= the advanced
	// master switch AND WebBotAuth.Enabled).  The signed-agent
	// branch in server.inc (= the RFC 9421 / Web Bot Auth detect + auth_request
	// + try_files machinery) is rendered ONLY when this is true.  With WBA
	// disabled (the default) the whole branch is omitted, so a request that
	// merely carries a Signature-Input header is never re-routed through the
	// signed-route: it stays on the normal native flow and a proxied path like
	// /rss/ is served by its own location instead of the signed-route's
	// try_files (which =404s a proxied URI that has no file on disk).
	WebBotAuthEnabled bool

	// PrivacyPassEnabled mirrors settings.Nginx.PrivacyPassActive() (= the
	// advanced master switch AND PrivacyPass.Enabled).  The PAT
	// detour/verify machinery in server.inc + the gate maps in http.inc are
	// rendered ONLY when this is true.  With it disabled the whole branch is
	// omitted, so a request carrying an "Authorization: PrivateToken" stays on
	// the normal native flow (the admin still emits the WWW-Authenticate
	// challenge from ServeChallenge, but no native pre-content verify happens).
	PrivacyPassEnabled bool

	// mapHashWarning: non-empty when the host nginx.conf already declares a
	// map_hash_bucket_size too small for the community-bans maps, or could not be
	// read to check.  Logged by Render only -- RenderSignature must stay
	// side-effect free.  Unexported so the template can't reference it.
	mapHashWarning string
}

// RateZoneRender: zone values used to generate the nginx config.  KeyVar is
// the limit_req_zone key variable: "$rate_limit_key" for install-wide zones,
// or a path-conditional "$rl_<zone>_key" for zones restricted to PathPatterns.
type RateZoneRender struct {
	Name           string
	RequestsPerMin int
	Burst          int
	KeyVar         string
}

// RatePathZoneRender: a rate-limit zone restricted to specific path patterns.
// Instead of a dedicated nginx location (which, being more specific, would
// shadow the operator's protect.inc and silently disable the challenge /
// honeypot / ban / geo protections for that path), the zone is applied with a
// path-conditional key: $rl_<zone>_key resolves to the normal IP key when the
// request URI matches one of Patterns, else "" (= nginx skips limiting).  The
// limit_req sits in protect.inc next to the default zone, so a rate-limited
// path keeps every other protection -- the two features compose in one
// location.  MatchVar / KeyVar name the two maps emitted in http.inc.
type RatePathZoneRender struct {
	ZoneName string
	Burst    int
	MatchVar string // $rl_<zone>_match  (= "1" when $request_uri matches)
	KeyVar   string // $rl_<zone>_key    (= IP key when matched, else "")
	BaseKey  string // smart key fed in on match: $rate_limit_key, or
	// $rate_limit_key_deny for a "deny" zone (counts _bv holders)
	Patterns []string // path patterns (anchored as ~*^<pattern> in the map)
}

// GeoRuleRender: one entry of the $unmask_geo_action map.
type GeoRuleRender struct {
	Country string // ISO 3166-1 alpha-2 uppercase
	Action  string // resolved action (= rule.Action || geo.DefaultAction)
}

// AsnRuleRender: one entry of the $unmask_asn_action map.  Key is the token
// the geo block writes for a matching CIDR ("AS<n>" or "org:<pattern>").
type AsnRuleRender struct {
	Key    string // map key ("AS16509" / "org:microsoft")
	Action string // resolved action (= rule.Action || asn.DefaultAction)
}

// sanitizeConfPath strips characters that could break out of an nginx
// `include <path>;` directive -- newline (a new directive), NUL, quotes, the
// statement terminator, and braces.  These dir paths come from operator yaml, so
// this is belt-and-suspenders against a malformed value reaching the rendered
// config (L-2).  A legitimate filesystem path never contains them.
func sanitizeConfPath(p string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case '\n', '\r', 0, '"', '\'', ';', '{', '}':
			return -1
		}
		return r
	}, p)
}

func buildRenderData(s settings.Settings, outDir, version string) (renderData, error) {
	d := renderData{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Version:     version,
		OutputDir:   sanitizeConfPath(outDir),
		BVSecret:    s.Secret.BVSecret,
		// _bv HMAC validation runs in nginx with one shared secret + cookie
		// window; per-site challenge fields (PowDifficulty, theme, branding
		// etc.) are resolved in admin's serve handler via Challenge.Resolve(site)
		// instead, so the nginx side only needs the defaults here.
		BVPowValidSeconds:     s.Challenge.Default.PowCookieValidSecondsResolved(),
		BVCaptchaValidSeconds: s.Challenge.Default.CaptchaCookieValidSecondsResolved(),
		PowDifficulty:         s.Challenge.Default.ResolvedPowDifficulty(),
		KnownBrowserAction:    resolveGlobalAction(s.Global.KnownBrowserAction),
		UnknownUAAction:       resolveGlobalAction(s.Global.UnknownUAAction),
		UpstreamAddr:          defStr(s.Nginx.UpstreamAddr, "127.0.0.1:9477"),
		UpstreamServer:        buildUpstreamServer(s),
		BypassIPs:             mergeBypassIPs(s),
		StatsExcludeIPs:       sanitizeIPs(statsExcludeList(s.Nginx)),
		BanFilePath:           trimSpaceAndQuotes(s.Nginx.Honeypot.BanFilePath),
		NginxLogSocket:        s.NginxLog.SocketPath,
		NginxLogEnabled:       s.NginxLog.Enabled && s.NginxLog.SocketPath != "",
		LBIPRanges:            effectiveLBs(s.Nginx.TrustedLBPresets, s.Nginx.TrustedLBExtra),
		WebBotAuthEnabled:     s.Nginx.WebBotAuthActive(),
		PrivacyPassEnabled:    s.Nginx.PrivacyPassActive(),
	}

	// search bots: operator-added extras + the upstream auto-rescue below.
	// The old hand-maintained whitelist presets (Googlebot / Bingbot / ... )
	// were removed: every operator they covered is already rescued via the
	// crawler-user-agents.json upstream path (see classify), and keeping a
	// second, UI-hidden source meant turning a category off in the UI did not
	// actually stop the rescue.  seenVer is still used by the challenge-target
	// / JA4 NEW-badge gating below.
	seenVer := s.Nginx.SeenVersion
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
	//
	// Range-backed patterns whose UA-string rescue is effectively off are
	// dropped from the UA whitelist here: the rescue rides geo $is_bypass_ip
	// instead, so a spoofed UA from outside the published ranges gets the
	// normal challenge flow.  See uarange.go for the per-pattern resolution
	// (explicit lists first, then the preset-driven auto default).
	upstreamDisabled := toSet(s.Nginx.SearchBots.UpstreamDisabled)
	rangeVerified := EffectiveUpstreamUAOff(s.Nginx)
	upstreamGroupWhitePatterns, upstreamGroupBlackPatterns := collectUpstreamPatternsByMode(
		s.Nginx.SearchBots.UpstreamGroupMode, upstreamDisabled, rangeVerified)
	d.SearchBotPatterns = append(d.SearchBotPatterns, upstreamGroupWhitePatterns...)
	d.RangeVerifiedUACount = len(rangeVerified)

	// Stale-browser tier: only wire it when enabled AND the generated pattern
	// is non-empty (a lag so large that no positive major qualifies yields no
	// pattern -> leave the tier off rather than emit a map that matches
	// nothing).
	if s.Global.StaleBrowserEnabled() {
		if pat := staleBrowserPattern(s.Global.CurrentChromeMajorResolved(), s.Global.CurrentFirefoxMajorResolved(),
			s.Global.FirefoxESRMajors(), s.Global.StaleBrowserLagN()); pat != "" {
			d.StaleBrowserEnabled = true
			d.StaleBrowserPattern = pat
		}
	}

	d.HTTPSRedirect = s.Nginx.HTTPSRedirect
	if d.HTTPSRedirect {
		ex := s.Nginx.HTTPSRedirectExempt
		custom := make([]CustomExemptRule, 0, len(ex.Rules))
		for _, r := range ex.Rules {
			custom = append(custom, CustomExemptRule{Type: r.Type, Pattern: r.Pattern, Disabled: r.Disabled})
		}
		d.HTTPSRedirectExempt = ResolveRedirectExemptClauses(ex.EnabledPresets, ex.DisabledPresets, custom)
	}

	// challenge target UA: all=true is UA-agnostic.  Otherwise enabled presets + extras.
	d.ChallengeAll = s.Nginx.ChallengeTargets.All
	if !d.ChallengeAll {
		disabledTgt := toSet(s.Nginx.ChallengeTargets.DisabledPresets)
		seen := map[string]bool{}
		for _, g := range ChallengeTargetGroups {
			if disabledTgt[g.ID] {
				continue
			}
			if PresetIsNew(seenVer, g.AddedIn) {
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
		if PresetIsNew(seenVer, g.AddedIn) {
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
		// Reject rows whose Pattern/Verdict could break out of the quoted map
		// value and inject an nginx directive into the ROOT-loaded config.  The
		// settings-tab form validates this, but the hunt "ja4_bot" path appends
		// without it -- so re-validate at the render layer (the single
		// chokepoint that also covers a config.yml hand-edit).
		if strings.ContainsAny(r.Pattern, "\"\\\x00\r\n") || strings.ContainsAny(r.Verdict, "\"\\\x00\r\n") {
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

	// honeypot: enabled preset groups + custom URLs (= skip Disabled rows).
	// Custom URLs carry a per-row Site (= empty = global, non-empty = only
	// fires when $host matches).  Preset rules are always global.
	hpRules := []HoneypotPathRule{}
	hpSeen := map[string]bool{} // dedup key = "site|pattern"
	disabledHP := toSet(s.Nginx.Honeypot.DisabledPresets)
	enabledHP := toSet(s.Nginx.Honeypot.EnabledPresets)
	for _, g := range HoneypotPresetGroups {
		// OptIn presets stay inactive unless the operator names them in
		// EnabledPresets; the historical on-by-default groups (OptIn=false)
		// keep using DisabledPresets for opt-out.
		if g.OptIn {
			if !enabledHP[g.ID] {
				continue
			}
		} else if disabledHP[g.ID] {
			continue
		}
		if PresetIsNew(seenVer, g.AddedIn) {
			continue
		}
		for _, p := range g.Patterns {
			key := "|" + p
			if hpSeen[key] {
				continue
			}
			hpSeen[key] = true
			hpRules = append(hpRules, HoneypotPathRule{Pattern: p})
		}
	}
	for _, u := range s.Nginx.Honeypot.URLs {
		if u.Disabled {
			continue
		}
		p := trimSpaceAndQuotes(u.Path)
		if p == "" {
			continue
		}
		site := trimSpaceAndQuotes(u.Site)
		key := site + "|" + p
		if hpSeen[key] {
			continue
		}
		hpSeen[key] = true
		hpRules = append(hpRules, HoneypotPathRule{Pattern: p, Site: site})
	}
	sort.Slice(hpRules, func(i, j int) bool {
		if hpRules[i].Site != hpRules[j].Site {
			return hpRules[i].Site < hpRules[j].Site
		}
		return hpRules[i].Pattern < hpRules[j].Pattern
	})
	// Flat list kept for callers that haven't moved over to the per-site split.
	hp := make([]string, 0, len(hpRules))
	for _, r := range hpRules {
		hp = append(hp, r.Pattern)
	}
	d.HoneypotPatterns = hp
	d.HoneypotPatternsGlobal, d.HoneypotPatternsPerHost = splitHoneypotPathsForRender(hpRules)

	// Protected paths: presets (= enabled / preset carries {Pattern, Mode}) +
	// extras (= skip ExtraDisabled[i]=true).
	// DisabledPresets == nil means an existing yml where the protected
	// tab was never saved.  In that case every preset is OFF
	// (= compat-first: don't silently start protecting new paths in
	// existing deploys).
	pp := []ProtectedPathRule{}
	// Dedup key is (site, pattern) so a path can carry different modes per
	// host without one row silently shadowing the other.
	ppSeen := map[string]bool{}
	enabledPP := toSet(s.Nginx.ProtectedPaths.EnabledPresets)
	for _, g := range ProtectedPathPresetGroups {
		if !enabledPP[g.ID] {
			continue
		}
		for _, r := range g.Rules {
			pat := trimSpaceAndQuotes(r.Pattern)
			if pat == "" {
				continue
			}
			key := "|" + pat // preset rules are always global (Site="")
			if ppSeen[key] {
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
	// Custom rows carry a per-row Site (= empty = global, non-empty = only
	// for that $host).  The render side splits them below into a global map
	// + per-host maps so a $host-specific rule fires only on that vhost.
	for _, r := range s.Nginx.ProtectedPaths.Paths {
		if r.Disabled {
			continue
		}
		p := trimSpaceAndQuotes(r.Path)
		site := trimSpaceAndQuotes(r.Site)
		// Per-pattern dedup is keyed on (site, pattern) so the same path
		// can carry different modes on different hosts without one row
		// shadowing the other.
		key := site + "|" + p
		if p == "" || ppSeen[key] {
			continue
		}
		ppSeen[key] = true
		mode := ProtectedModeCaptcha
		if IsValidProtectedMode(r.Mode) {
			mode = r.Mode
		}
		pp = append(pp, ProtectedPathRule{Pattern: p, Mode: mode, Site: site})
	}
	sort.Slice(pp, func(i, j int) bool {
		if pp[i].Site != pp[j].Site {
			return pp[i].Site < pp[j].Site
		}
		return pp[i].Pattern < pp[j].Pattern
	})
	d.ProtectedPaths = pp
	d.ProtectedPathsGlobal, d.ProtectedPathsPerHost = splitProtectedPathsForRender(pp)

	// Whitelist paths: enabled presets + extras (= skip ExtraDisabled[i]=true).
	//
	// Patterns are stored as path-anchored PCRE (e.g., `^/api/`) and are
	// evaluated against `$request_uri` in the rendered nginx map -- no host
	// concatenation, so `^` keeps its natural "start of path" meaning.  Per-host
	// rules are split off into separate maps below; the host is selected by a
	// dispatcher map, never embedded in the path pattern.
	//
	// Preset resolution: each preset's DefaultOn + the operator's recorded
	// deviations (enabled_presets / disabled_presets), via the shared
	// EffectiveBypassPathPresets so this render agrees with the forward-auth
	// matcher and the settings UI.  The SeenVersion NEW gate below still
	// excludes presets the operator hasn't reviewed yet.
	bp := []BypassPathRule{}
	bpSeen := map[string]bool{}
	enabledBPath := EffectiveBypassPathPresets(s.Nginx.BypassPaths.EnabledPresets, s.Nginx.BypassPaths.DisabledPresets)
	for _, g := range BypassPathPresetGroups {
		if !enabledBPath[g.ID] {
			continue
		}
		if PresetIsNew(seenVer, g.AddedIn) {
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
	// Custom rows: per-row Site filter is already part of BypassPath, so
	// splitBypassPathsForRender keeps emitting per-host maps for non-empty
	// sites.  TODO(phase 3): unify with the per-site protected/honeypot
	// map wire so all three lists share a single $host dispatcher.
	for _, r := range s.Nginx.BypassPaths.Paths {
		if r.Disabled {
			continue
		}
		p := trimSpaceAndQuotes(r.Path)
		if p == "" {
			continue
		}
		site := trimSpaceAndQuotes(r.Site)
		key := site + "|" + p
		if bpSeen[key] {
			continue
		}
		bpSeen[key] = true
		bp = append(bp, BypassPathRule{Pattern: p, Site: site})
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
		KeyVar:         "$rate_limit_key",
	})
	d.DefaultRateZoneName = defaultName
	d.DefaultRateZoneBurst = defaultBurst
	// Compose vs classic is decided by the host nginx's limit_req_dry_run support
	// (>= 1.17.6), NOT by whether a deny zone exists.  Compose is the unified flow
	// (the plugin's ACCESS handler composes rate + challenge, so a deny zone wins
	// over a protected-path challenge that the classic REWRITE-phase gate would
	// pre-empt), but its `limit_req_dry_run` fails `nginx -t` on older nginx --
	// so older nginx always renders classic.  A deny zone on classic still
	// hard-blocks un-challenged traffic; it just can't preempt a challenge (that
	// gap is surfaced as a startup / doctor warning, HasDenyRateZone && !capable).
	d.ComposeMode = ComposeCapable(s)
	switch s.RateLimit.ResolvedKey() {
	case settings.RateLimitKeyJA4:
		d.RateLimitKeyExpr = "$effective_ja4"
	case settings.RateLimitKeyIPAndJA4:
		d.RateLimitKeyExpr = "$unmask_client_net$effective_ja4"
	default:
		d.RateLimitKeyExpr = "$unmask_client_net"
	}
	// Zone naming: per-site zones get a "<site-fragment>__" prefix on the
	// rendered nginx zone name so an identical "shop_api" zone configured for
	// two different vhosts emits as two distinct limit_req_zone declarations
	// (= nginx requires globally unique zone names).  Operators reference the
	// rendered name in their vhost server block; the global default zone
	// keeps its plain name so the canonical protect.inc snippet stays valid
	// without any vhost-side override.
	zoneNamesSeen := map[string]bool{defaultName: true}
	for _, z := range s.RateLimit.Zones {
		name := strings.TrimSpace(z.Name)
		if name == "" {
			continue
		}
		site := strings.TrimSpace(z.Site)
		rendered := name
		if site != "" {
			rendered = hostToNginxVarSegment(site) + "__" + name
		}
		if zoneNamesSeen[rendered] {
			continue
		}
		zoneNamesSeen[rendered] = true
		rpm := z.RequestsPerMin
		if rpm <= 0 {
			rpm = defaultRPM
		}
		burst := z.Burst
		if burst <= 0 {
			burst = defaultBurst
		}
		// PathPatterns wiring: instead of a dedicated nginx location (which
		// would shadow protect.inc and strip the challenge / honeypot / ban /
		// geo protections for that path), the zone is applied with a
		// path-conditional key.  The key var is "" for non-matching URIs so
		// nginx skips the limit there, and the limit_req lives in protect.inc
		// next to the default zone -- so rate-limit and protection compose in
		// the same location.  Site-scoped zones match on URI only (nginx has
		// no Host in a map key here); Host isolation is via AdminAllowedHosts.
		patterns := make([]string, 0, len(z.PathPatterns))
		for _, p := range z.PathPatterns {
			if p = strings.TrimSpace(p); p != "" {
				patterns = append(patterns, p)
			}
		}
		keyVar := "$rate_limit_key"
		if len(patterns) > 0 {
			keyVar = "$rl_" + rendered + "_key"
			// A "deny" zone is a hard cap: on a URI match it feeds in
			// $rate_limit_key_deny (counts _bv holders) rather than
			// $rate_limit_key (which exempts them).  Trusted sources (search
			// bot / bypass IP / bypass path) stay exempt in either map.
			baseKey := "$rate_limit_key"
			if z.ResolvedChallengeMode() == settings.RateChallengeDeny {
				// Deny zones count _bv holders too (a hard cap ignores the pass
				// cookie).  ComposeMode itself is decided once above by nginx
				// capability, not per-zone.
				baseKey = "$rate_limit_key_deny"
			}
			d.RatePathZones = append(d.RatePathZones, RatePathZoneRender{
				ZoneName: rendered,
				Burst:    burst,
				MatchVar: "$rl_" + rendered + "_match",
				KeyVar:   keyVar,
				BaseKey:  baseKey,
				Patterns: patterns,
			})
		}
		d.RateZones = append(d.RateZones, RateZoneRender{
			Name:           rendered,
			RequestsPerMin: rpm,
			Burst:          burst,
			KeyVar:         keyVar,
		})
	}

	// Geo (native mode): walk the mmdb once at render time to materialise a
	// `geo $binary_remote_addr $unmask_country { ... }` block listing only
	// the CIDRs of countries the operator has rules for.  The plugin can
	// then route on $unmask_country without needing libmaxminddb.
	// forward-auth mode keeps doing live lookups via the admin /authcheck
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
		// see the WARN in `unmask doctor` (= mmdb path check).
	}

	// ASN (native mode): the by-network sibling of the geo block above.  Walk
	// the ASN mmdb once, materialising a `geo $remote_addr $unmask_asn { ... }`
	// block listing only the CIDRs the operator's rules/providers target, plus
	// a $unmask_asn -> $unmask_asn_action map.  Each target's map key is a
	// stable token: "AS<n>" for exact rules, "org:<pattern>" for org / provider
	// matches.  Requires the ASN mmdb (MMDBASNPath); inert without it.
	d.AsnDefaultAction = s.Nginx.Asn.ResolvedDefaultAction()
	if s.Nginx.Asn.HasEnabled() {
		var targets []ipgeo.ASNTarget
		seenKey := map[string]bool{}
		addRule := func(key, action string, t ipgeo.ASNTarget) {
			if seenKey[key] {
				return
			}
			seenKey[key] = true
			act := strings.TrimSpace(action)
			if act == "" {
				act = d.AsnDefaultAction
			}
			if !settings.IsValidGeoAction(act) {
				act = settings.GeoActionSkip
			}
			t.Value = key
			targets = append(targets, t)
			d.AsnRules = append(d.AsnRules, AsnRuleRender{Key: key, Action: act})
		}
		// Exact-ASN rules first (more specific), then org rules, then providers.
		for _, r := range s.Nginx.Asn.EnabledASNRules() {
			key := "AS" + strconv.FormatUint(uint64(r.ASN), 10)
			addRule(key, r.Action, ipgeo.ASNTarget{ASN: r.ASN})
		}
		for _, o := range s.Nginx.Asn.EnabledOrgPatterns() {
			key := "org:" + strings.ToLower(o.Pattern)
			addRule(key, o.Action, ipgeo.ASNTarget{OrgPattern: o.Pattern})
		}
		if len(targets) > 0 && strings.TrimSpace(s.IPGeo.MMDBASNPath) != "" {
			if cidrs, err := ipgeo.CIDRsForASNTargets(s.IPGeo.MMDBASNPath, targets); err == nil {
				d.AsnCIDRs = cidrs
			}
			// On error: leave AsnCIDRs empty; the block degrades to the default
			// action.  doctor's mmdb path check surfaces a missing/broken db.
		}
	}

	// CommunityBans: render the 3 map includes only in fetch_apply mode.
	// "fetch" pulls for the browse list but never enforces, so it gets no
	// nginx include; "off" likewise.  MapDir priority:
	// CommunityBans.MapDir > Nginx.OutputDir > "/var/lib/unmask/nginx".
	// OutputDir is already the nginx-specific dir, so the maps land right
	// next to http.inc / banned.txt -- no extra sub-directory.
	if s.CommunityBans.ApplyActive() {
		d.CommunityBansSubscribe = true
		md := strings.TrimSpace(s.CommunityBans.MapDir)
		if md == "" {
			md = strings.TrimSpace(s.Nginx.OutputDir)
		}
		if md == "" {
			md = "/var/lib/unmask/nginx"
		}
		d.CommunityBansMapDir = sanitizeConfPath(md)

		// Size the map hash for the community-bans maps -- emit only the directives
		// the host nginx.conf lacks (a duplicate map_hash_* is a fatal nginx -t
		// error); warn when a host value is present but too small.
		d.CommunityBansMapHashBucket, d.CommunityBansMapHashMax, d.mapHashWarning = resolveMapHash(s)
	}

	// Size the variables hash: unmask's maps push the variable count past
	// nginx's 1024 default, so it warns "could not build optimal variables_hash"
	// on every reload.  Emit ours unless the host nginx.conf already declares
	// one (a duplicate is fatal); an unreadable conf falls through to emitting
	// and letting any duplicate surface as a clear nginx -t error.
	d.EmitVariablesHash = !hostHasVariablesHash(s)

	return d, nil
}

// hostHasVariablesHash reports whether the host nginx config already declares a
// variables_hash_max_size / variables_hash_bucket_size at top level, so unmask
// does not emit a duplicate (a fatal nginx -t error that the plugin fail-safe
// then reacts to by stripping ALL unmask wiring -- silent unprotect).  Unlike
// map_hash these are not constrained to precede a map block, so the scan only
// checks for the directive's presence.  Scans nginx.conf AND its `include`d
// files (one level) so a host directive in the ubiquitous conf.d/*.conf is seen
// -- a literal nginx.conf-only scan missed it.  Unmask's own rendered files are
// excluded (see hostConfContents) so it never self-detects + under-emits.
func hostHasVariablesHash(s settings.Settings) bool {
	for _, content := range hostConfContents(s) {
		for _, line := range strings.Split(content, "\n") {
			f := strings.Fields(line)
			if len(f) < 2 || strings.HasPrefix(f[0], "#") {
				continue
			}
			if f[0] == "variables_hash_max_size" || f[0] == "variables_hash_bucket_size" {
				return true
			}
		}
	}
	return false
}

// hostConfContents returns the content of the host nginx.conf plus the files it
// pulls in via top-level `include <glob>;` (one level, globs resolved relative to
// the conf's dir), EXCLUDING unmask's own rendered output (files that resolve
// under Nginx.OutputDir -- e.g. http.inc reached via the conf.d/00-unmask.conf
// symlink).  The exclusion matters: without it the probe would see unmask's OWN
// emitted variables_hash and conclude "the host already has it", skip emitting,
// and under-emit on every re-render.  Best-effort: unreadable files are skipped;
// one level deep covers the conf.d/*.conf case without shelling out to nginx -T.
func hostConfContents(s settings.Settings) []string {
	confPath := strings.TrimSpace(s.Nginx.ConfPath)
	if confPath == "" {
		confPath = "/etc/nginx/nginx.conf"
	}
	b, err := os.ReadFile(confPath)
	if err != nil {
		return nil
	}
	out := []string{string(b)}

	var realOut string
	if outDir := strings.TrimSpace(s.Nginx.OutputDir); outDir != "" {
		realOut, _ = filepath.EvalSymlinks(outDir) // resolved so symlinked includes match
	}
	base := filepath.Dir(confPath)
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if !strings.HasPrefix(t, "include ") {
			continue
		}
		arg := strings.Trim(strings.TrimSuffix(strings.TrimSpace(strings.TrimPrefix(t, "include")), ";"), "\"'")
		if arg == "" {
			continue
		}
		if !filepath.IsAbs(arg) {
			arg = filepath.Join(base, arg)
		}
		matches, _ := filepath.Glob(arg)
		for _, m := range matches {
			if realOut != "" {
				if rm, e := filepath.EvalSymlinks(m); e == nil && strings.HasPrefix(rm, realOut) {
					continue // unmask's own rendered file -- do not self-detect
				}
			}
			if mb, e := os.ReadFile(m); e == nil {
				out = append(out, string(mb))
			}
		}
	}
	return out
}

// resolveMapHash probes the host nginx.conf (Nginx.ConfPath, default
// /etc/nginx/nginx.conf) and decides which map_hash_* directives http.inc must
// emit for the community-bans maps: only those the host has not already declared,
// because map_hash_bucket_size / map_hash_max_size are single-occurrence http{}
// directives and a duplicate is a fatal `nginx -t` error.  warning is non-empty
// when a host value is present but smaller than the community-bans keys need
// (~76 chars / 256), or the conf could not be read.  Callers gate on
// community-bans enforcement being active.
func resolveMapHash(s settings.Settings) (emitBucket, emitMax bool, warning string) {
	confPath := strings.TrimSpace(s.Nginx.ConfPath)
	if confPath == "" {
		confPath = "/etc/nginx/nginx.conf"
	}
	const wantBucket = 256
	hb, hmax, hasMapBlock, readable := readHostMapHash(confPath)
	if !readable {
		// Missing or unreadable (e.g. 0600-hardened) host config: emit ours and
		// note it -- any duplicate surfaces as a clear `nginx -t` error.
		return true, true, fmt.Sprintf("could not read %s to check for an existing map_hash_bucket_size; "+
			"emitting map_hash_bucket_size %d + map_hash_max_size 4096 in http.inc. If you set them in nginx.conf "+
			"yourself, ensure map_hash_bucket_size >= %d and remove the duplicate.", confPath, wantBucket, wantBucket)
	}
	if hasMapBlock && hb == 0 {
		// The host nginx.conf opens a map / geo / split_clients block (e.g.
		// Alpine 3.23's stock `map $http_upgrade $connection_upgrade {}` for
		// websocket proxying) BEFORE unmask's http.inc include, which lands late
		// in http{} via http.d/conf.d.  nginx requires map_hash_bucket_size to
		// precede EVERY map block, so emitting ours from http.inc -- after the
		// host's block -- is a fatal "directive is duplicate" `nginx -t` error
		// (the placer's fail-safe then strips the whole module).  Skip emission:
		// the community-bans maps fall back to nginx's default bucket (64), which
		// is fine for an empty feed or IPv4 ip:ja4 keys (~55 chars), and warn so
		// the operator can size it themselves for a large IPv6 feed.
		return false, false, fmt.Sprintf("%s opens a map/geo/split_clients block before unmask's http.inc include; "+
			"nginx forbids map_hash_bucket_size after a map block, so unmask cannot size the community-bans maps from "+
			"http.inc (they use nginx's default bucket, 64).  If the community-bans feed carries long IPv6 ip:ja4 keys "+
			"(~76 chars), add `map_hash_bucket_size %d;` + `map_hash_max_size 4096;` to the TOP of your nginx.conf "+
			"http{} block (before the first map).", confPath, wantBucket)
	}
	if hb > 0 && hb < wantBucket {
		warning = fmt.Sprintf("%s sets map_hash_bucket_size %d, but unmask community-bans map keys reach ~76 chars "+
			"(IPv6) and need >= %d. Raise it to %d (or remove it so unmask manages it), or `nginx -t` will fail once "+
			"the community-bans feed populates.", confPath, hb, wantBucket, wantBucket)
	}
	return hb == 0, hmax == 0, warning
}

// MapHashAdvice returns a non-empty operator warning when community-bans
// enforcement is active and the host nginx.conf's map_hash sizing is inadequate
// (present but too small, or unreadable so unmask can't verify it).  Empty
// otherwise.  `unmask doctor` surfaces this; Render logs the same string.
func MapHashAdvice(s settings.Settings) string {
	if !s.CommunityBans.ApplyActive() {
		return ""
	}
	_, _, w := resolveMapHash(s)
	return w
}

// readHostMapHash scans an nginx config file for top-level map_hash_bucket_size
// / map_hash_max_size declarations (returning their values, 0 when absent) and
// whether the file opens any map / geo / split_clients block (hasMapBlock) --
// these finalize the map-hash params, so a later map_hash_bucket_size is a fatal
// duplicate.  readable is false when the file can't be read (missing / permission
// denied), letting the caller fall back to emitting its own.  Best-effort line
// scan: it does not follow include directives, matching the postinstall's old grep.
func readHostMapHash(path string) (bucket, maxsz int, hasMapBlock, readable bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, false, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || strings.HasPrefix(f[0], "#") {
			continue
		}
		// map / geo / split_clients are always block directives in nginx; their
		// opener line (e.g. `map $http_upgrade $connection_upgrade {`) marks the
		// point after which map_hash_bucket_size can no longer be set.
		switch f[0] {
		case "map", "geo", "split_clients":
			hasMapBlock = true
		}
		val := strings.TrimRight(f[1], ";")
		switch f[0] {
		case "map_hash_bucket_size":
			if n, err := strconv.Atoi(val); err == nil {
				bucket = n
			}
		case "map_hash_max_size":
			if n, err := strconv.Atoi(val); err == nil {
				maxsz = n
			}
		}
	}
	return bucket, maxsz, hasMapBlock, true
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
// per-pattern OFF wins over the group default).  Patterns in rangeVerified
// are skipped on the white side only: their rescue is carried by the
// vendor's IP-range presets (geo $is_bypass_ip), not by the UA string.
func collectUpstreamPatternsByMode(overrides map[string]string, disabledSet, rangeVerified map[string]bool) (white, black []string) {
	groups := classify.UpstreamRescueList()
	// Iterate categories in sorted order: groups is a map, and Go map
	// iteration is randomized, so ranging it directly makes the rendered
	// pattern list non-deterministic (= the same settings produce different
	// conf bytes each render).  Sorting the keys makes render deterministic,
	// which the settings-save conf-diff relies on.
	cats := make([]string, 0, len(groups))
	for cat := range groups {
		cats = append(cats, cat)
	}
	sort.Strings(cats)
	whiteSeen := map[string]bool{}
	blackSeen := map[string]bool{}
	for _, cat := range cats {
		entries := groups[cat]
		mode := classify.ResolveGroupMode(cat, overrides)
		switch mode {
		case classify.GroupModeWhite:
			for _, e := range entries {
				if e.Pattern == "" || disabledSet[e.Pattern] || whiteSeen[e.Pattern] {
					continue
				}
				if rangeVerified[e.Pattern] {
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
// statsExcludeList returns the operator's StatsExcludeIPs plus the private-
// network CIDRs when the preset is on (appended, not stored — the config keeps
// only the toggle + the custom list).
func statsExcludeList(n settings.Nginx) []string {
	if !n.StatsExcludePrivateNetworks {
		return n.StatsExcludeIPs
	}
	return append(append([]string{}, n.StatsExcludeIPs...), PrivateNetworkCIDRs...)
}

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
// resolveGlobalAction: per-axis setting → "pow_only" strict default.
// Returned verbatim into http.inc so nginx can decide whether to challenge
// ($action != "pass") without duplicating the resolution table.
func resolveGlobalAction(axis string) string {
	if axis != "" {
		return axis
	}
	return "pow_only"
}

// staleBrowserPattern builds the nginx regex the $unmask_stale_browser map
// tests $http_user_agent against.  A UA is stale when its Chromium-family or
// Firefox major is at least lag behind that family's current stable, i.e.
// major <= current-lag.  The pattern matches a `Chrome/<major>.` /
// `Firefox/<major>.` token for every stale major (skipping the exempt
// Firefox ESR major), so it mirrors classify.IsStaleBrowser exactly (the
// daemon side) while running as a pure nginx map (the native gate needs no
// plugin call).  Safari carries neither token and is out of scope by design
// (see classify.IsStaleBrowser).
//
// An explicit alternation (not a hand-rolled numeric-range regex) is used on
// purpose: it is obviously correct, unit-tested against the same threshold the
// daemon uses, and compiled once by nginx.  The trailing `\.` anchors the
// major so Chrome/50. never matches the "5" alternative and Chrome/1400. never
// matches "140".  Returns "" when no positive major qualifies in either
// family, signalling the caller to leave the tier off.
func staleBrowserPattern(curChrome, curFirefox int, ffESRExempt []int, lag int) string {
	var fams []string
	if alt := staleMajorAlternation(curChrome-lag, nil); alt != "" {
		fams = append(fams, "Chrome/(?:"+alt+")")
	}
	if alt := staleMajorAlternation(curFirefox-lag, ffESRExempt); alt != "" {
		fams = append(fams, "Firefox/(?:"+alt+")")
	}
	if len(fams) == 0 {
		return ""
	}
	return `(?:` + strings.Join(fams, "|") + `)\.`
}

// staleMajorAlternation lists every major from threshold down to 1 as a regex
// alternation, skipping the exempt majors; "" when threshold < 1.
func staleMajorAlternation(threshold int, exempt []int) string {
	if threshold < 1 {
		return ""
	}
	skip := map[int]bool{}
	for _, e := range exempt {
		skip[e] = true
	}
	majors := make([]string, 0, threshold)
	for m := threshold; m >= 1; m-- {
		if skip[m] {
			continue
		}
		majors = append(majors, strconv.Itoa(m))
	}
	return strings.Join(majors, "|")
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
