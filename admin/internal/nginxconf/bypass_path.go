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

// BypassPathPresetGroups: presets for typical bypass paths.  All OFF by default
// (= path layouts vary per site; avoid mistaken opt-outs).
var BypassPathPresetGroups = []BypassPathGroup{
	{
		ID:    "static-assets",
		Label: "Static assets (= /static/ /assets/ /favicon.ico /robots.txt)",
		Rules: []BypassPathRule{
			{Pattern: `^/static/`},
			{Pattern: `^/assets/`},
			{Pattern: `^/favicon\.ico$`},
			{Pattern: `^/robots\.txt$`},
			{Pattern: `^/sitemap\.xml$`},
		},
	},
	{
		ID:    "well-known",
		Label: "/.well-known/ (= ACME / OIDC discovery etc.)",
		Rules: []BypassPathRule{
			{Pattern: `^/\.well-known/`},
		},
	},
	{
		ID:    "health",
		Label: "Health checks (= /healthz / /readyz / /api/health)",
		Rules: []BypassPathRule{
			{Pattern: `^/healthz$`},
			{Pattern: `^/readyz$`},
			{Pattern: `^/api/health$`},
			{Pattern: `^/ping$`},
		},
	},
	{
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
// names, so dots and hyphens are replaced with `_` (= "uic.jp" -> "uic_jp",
// "tool-jp.example" -> "tool_jp_example").  Mixed-case is preserved because
// nginx variables are case-sensitive.  Empty input maps to "default" so the
// rendered identifier is always non-empty.
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
