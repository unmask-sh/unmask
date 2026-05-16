// Bypass paths (= per-path total opt-out from all unmask checks).
//
// Scope: matched requests are excluded from JA4 verdict / honeypot /
// protected paths / rate limit, every check.  Useful for "let static / api
// paths pass through on an unmask-protected site."
//
// Per-site restriction: each rule has a site column.  Empty = all sites.
// Non-empty = only hits when $unmask_site equals that value.
package nginxconf

// BypassPathGroup: a group of bypass-path presets.  Same shape as the search-bots preset.
type BypassPathGroup struct {
	ID      string
	Label   string
	Rules   []BypassPathRule // {Pattern, Site}
	AddedIn string
}

// BypassPathRule: a single entry.  Empty Site = all sites.
type BypassPathRule struct {
	Pattern string // nginx regex (= no ~^ prefix)
	Site    string // empty = all sites
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
