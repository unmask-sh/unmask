// Bypass paths (= per-path total opt-out from all unmask checks).
//
// Scope: matched requests are excluded from JA4 verdict / honeypot /
// protected paths / rate limit, every check.  Useful for "let static / api
// paths pass through on an unmask-protected site."
//
// Per-site restriction: each rule has a site column.  Empty = all sites.
// Non-empty = only hits when $host equals that value.
//
// Render layout (= http.conf.tmpl): patterns are evaluated against
// `$request_uri` directly, never a `$host:$request_uri` concatenation, so a
// natural `^/api/` regex keeps its "start of path" meaning.  Per-site rules
// are emitted as one extra path-only map per unique host plus a host
// dispatcher map that selects the right per-host result.
package nginxconf

import (
	"sort"
	"strings"
)

// BypassPathGroup: a group of bypass-path presets.  Same shape as the search-bots preset.
type BypassPathGroup struct {
	ID      string
	Label   string
	Rules   []BypassPathRule // {Pattern, Site}
	AddedIn string
	// DefaultOn: the preset's factory state when the operator has recorded no
	// choice for it (= its ID is in neither EnabledPresets nor DisabledPresets).
	// ON is reserved for presets where staying OFF silently breaks machine
	// access (ACME renewal, robots.txt / SEO, health checks, browser metadata);
	// anything that could plausibly be a protection target (API paths) stays
	// OFF.  Every future preset declares its own default here — the config only
	// stores deviations, so a new preset's default reaches existing installs
	// too.
	DefaultOn bool
}

// BypassPathRule: a single entry.  Empty Site = all sites.
//
// Pattern convention: a **path-anchored** PCRE regex evaluated against
// `$request_uri` (= just the path, NOT host:request_uri).  Operators write
// `^/api/` as they would for any path-matching regex; both the in-memory
// matcher in auth_check.go and the nginx render in http.conf.tmpl feed the
// pattern into a `map $request_uri ...` directive (= per-site rules go
// through a host dispatcher map; pattern itself never carries host info).
//
// Empty Site selects the rule for the global path map; non-empty Site
// routes the rule into the per-host map for that exact host string.
type BypassPathRule struct {
	Pattern string // path-anchored PCRE (e.g., "^/api/", "/static/", "/foo$")
	Site    string // empty = global (= every host); else exact host match
}

// BypassPathPresetGroups: presets for typical bypass paths.  Each group
// declares its own factory default via DefaultOn (see the field docs);
// EffectiveBypassPathPresets resolves the operator's recorded deviations
// against those defaults.
var BypassPathPresetGroups = []BypassPathGroup{
	{
		ID:        "static-assets",
		DefaultOn: true, // robots.txt / sitemap.xml behind a challenge = SEO incident
		Label:     "Static assets (= /static/ /assets/ /favicon.ico /robots.txt /sitemap.xml /ads.txt etc.)",
		Rules: []BypassPathRule{
			{Pattern: `^/static/`},
			{Pattern: `^/assets/`},
			{Pattern: `^/favicon\.ico$`},
			{Pattern: `^/robots\.txt$`},
			{Pattern: `^/sitemap\.xml$`},
			// IAB ads ecosystem (= ad crawlers always fetch these).
			{Pattern: `^/ads\.txt$`},
			{Pattern: `^/app-ads\.txt$`},
			// Site / author metadata (= curious crawlers + browser extensions).
			{Pattern: `^/humans\.txt$`},
		},
	},
	{
		ID:        "well-known",
		DefaultOn: true, // a challenged ACME HTTP-01 = failed cert renewal, noticed on expiry day
		Label:     "/.well-known/ (= ACME / OIDC discovery / security.txt etc.)",
		Rules: []BypassPathRule{
			{Pattern: `^/\.well-known/`},
		},
	},
	{
		ID:        "browser-metadata",
		DefaultOn: true, // browsers fetch these cookie-less without user action; a challenge page breaks them silently
		Label:     "Browser metadata (= manifest / browserconfig / apple-touch-icon / service worker -- browsers fetch these without user action)",
		Rules: []BypassPathRule{
			// PWA manifests (= both naming conventions).
			{Pattern: `^/manifest\.json$`},
			{Pattern: `^/manifest\.webmanifest$`},
			// Microsoft IE / Edge tile config.
			{Pattern: `^/browserconfig\.xml$`},
			// iOS / iPadOS home-screen icons (= every size variant Safari probes).
			{Pattern: `^/apple-touch-icon(?:-\d+x\d+)?(?:-precomposed)?\.png$`},
			// Service workers -- /service-worker.js is the de-facto name,
			// /sw.js is the popular short alias.  Disable this preset and
			// add the path manually under bypass_paths.paths if your app
			// happens to occupy /sw.js for a different purpose.
			{Pattern: `^/service-worker\.js$`},
			{Pattern: `^/sw\.js$`},
		},
		AddedIn: "v0.1.0",
	},
	{
		ID:        "health",
		DefaultOn: true, // a challenged health check = LB marks the node unhealthy
		Label:     "Health checks (= /healthz / /readyz / /api/health)",
		Rules: []BypassPathRule{
			{Pattern: `^/healthz$`},
			{Pattern: `^/readyz$`},
			{Pattern: `^/api/health$`},
			{Pattern: `^/ping$`},
		},
	},
	{
		// DefaultOn stays false: APIs are a typical scraping target — silently
		// opening ^/api/ would un-protect the very thing many installs guard.
		ID:    "api-paths",
		Label: "API paths (= /api/ /v1/ /v2/ /graphql / etc. — assumes non-browser clients)",
		Rules: []BypassPathRule{
			{Pattern: `^/api/`},
			{Pattern: `^/v1/`},
			{Pattern: `^/v2/`},
			{Pattern: `^/graphql$`},
			{Pattern: `^/rpc/`},
		},
	},
}

// EffectiveBypassPathPresets resolves which preset groups are active from the
// operator's recorded deviations.  A group is active when the operator
// explicitly enabled it (enabled list), or it is DefaultOn and not explicitly
// disabled (disabled list).  IDs unknown to the current build are ignored on
// both lists (they may belong to a newer / older version's presets).
//
// This is the single resolution point shared by the nginx renderer, the
// forward-auth in-memory matcher, and the settings UI — the three must agree
// on what "enabled" means or the admin would lie about the conf it rendered.
//
// A preset is active from the release that ships it: there is no version gate
// here or in the callers (render / forward-auth match / settings UI), so a
// preset added by an upgrade takes effect at its DefaultOn immediately.
func EffectiveBypassPathPresets(enabled, disabled []string) map[string]bool {
	on := map[string]bool{}
	en := map[string]bool{}
	dis := map[string]bool{}
	for _, id := range enabled {
		en[strings.TrimSpace(id)] = true
	}
	for _, id := range disabled {
		dis[strings.TrimSpace(id)] = true
	}
	for _, g := range BypassPathPresetGroups {
		on[g.ID] = en[g.ID] || (g.DefaultOn && !dis[g.ID])
	}
	return on
}

// BypassPathHostMaps describes the per-host bypass-path map that the
// http.conf.tmpl renders for a single host with non-empty Site rules.
// Patterns are the original path-anchored PCRE (= no anchor stripping).
// VarName is a sanitized identifier safe to embed in nginx variable names
// (= the rendered map sets `$<VarName>` from `$request_uri`).
type BypassPathHostMaps struct {
	Host     string   // exact host string (= goes into the dispatcher map key)
	VarName  string   // nginx-variable-safe identifier derived from Host
	Patterns []string // path-anchored regex list, evaluated against $request_uri
}

// splitBypassPathsForRender separates merged rules into:
//   - globals: patterns for rules with Site == "" (= apply to every host)
//   - perHost: one BypassPathHostMaps per unique non-empty Site
//
// Deterministic ordering: globals follow the input slice order (callers sort
// upstream); perHost groups are sorted by Host so the rendered map text is
// stable across runs.
func splitBypassPathsForRender(rules []BypassPathRule) (globals []string, perHost []BypassPathHostMaps) {
	byHost := map[string][]string{}
	hostOrder := []string{}
	for _, r := range rules {
		if r.Site == "" {
			globals = append(globals, r.Pattern)
			continue
		}
		if _, seen := byHost[r.Site]; !seen {
			hostOrder = append(hostOrder, r.Site)
		}
		byHost[r.Site] = append(byHost[r.Site], r.Pattern)
	}
	sort.Strings(hostOrder)
	for _, host := range hostOrder {
		perHost = append(perHost, BypassPathHostMaps{
			Host:     host,
			VarName:  hostToNginxVarSegment(host),
			Patterns: byHost[host],
		})
	}
	return
}

// hostToNginxVarSegment converts a hostname into a fragment safe for use
// inside an nginx variable name.  nginx accepts `[A-Za-z0-9_]` for variable
// names, so dots and hyphens are replaced with `_` (= "shop.example" ->
// "shop_example", "blog-edge.example" -> "blog_edge_example").  Mixed-case
// is preserved because nginx variables are case-sensitive.  Empty input
// maps to "default" so the rendered identifier is always non-empty.
// SiteVarNameClash reports two distinct hosts that would render to the same
// nginx variable segment (hostToNginxVarSegment folds '.', '-' and ':' into
// '_', so "a-b.example" and "a.b.example" collide).  Two such sites produce
// two `map` blocks defining one variable, and nginx refuses the whole config
// -- so the settings form refuses the second site instead.
func SiteVarNameClash(hosts []string) (a, b, segment string, clash bool) {
	seen := map[string]string{}
	for _, h := range hosts {
		seg := hostToNginxVarSegment(h)
		if prev, ok := seen[seg]; ok && prev != h {
			return prev, h, seg, true
		}
		seen[seg] = h
	}
	return "", "", "", false
}

func hostToNginxVarSegment(host string) string {
	if host == "" {
		return "default"
	}
	var b strings.Builder
	b.Grow(len(host))
	for _, r := range host {
		switch {
		case r >= 'a' && r <= 'z',
			r >= 'A' && r <= 'Z',
			r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			// Covers '.', '-', ':' (= IPv6 brackets get sanitized too).
			b.WriteByte('_')
		}
	}
	return b.String()
}
