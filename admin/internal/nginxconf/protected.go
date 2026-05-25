// Protected paths feature (= transparent CAPTCHA / PoW / strict gate).
//
// Difference from honeypot:
//   - honeypot: "step on the trap → persistent BAN on that IP → affects all subsequent paths"
//   - protected paths: "a visitor reaching here is human-verified.  affects only that path"
//
// Meaning of each mode:
//   - "captcha" : skip PoW → straight to CAPTCHA → issue _bv.  standard.  medium UX cost
//   - "pow"     : PoW only → issue _bv.  lightweight protection that only charges CPU cost
//   - "strict"  : PoW → CAPTCHA chain → _bv.  In v0.1 behaves like captcha
//     (= the chain JS state machine ships in v0.2).  The yml schema carries all 3 from the start.
package nginxconf

import "sort"

const (
	ProtectedModeCaptcha = "captcha"
	ProtectedModePoW     = "pow"
	ProtectedModeStrict  = "strict"
)

// IsValidProtectedMode: validate a value coming from form / yml.
func IsValidProtectedMode(m string) bool {
	return m == ProtectedModeCaptcha || m == ProtectedModePoW || m == ProtectedModeStrict
}

// ProtectedPathRule: render-time struct that maps to one row in the UI.
// Site != "" scopes the rule to that exact host (= per-site overrides come in
// via ProtectedPathsConfig.Overrides[site].Append / Remove).
type ProtectedPathRule struct {
	Pattern string // nginx regex (= without ~^)
	Mode    string // "captcha" | "pow" | "strict"
	Site    string // empty = global (= every host); else exact host match
}

// ProtectedPathHostMaps describes the per-host protected-path map that the
// http.conf.tmpl renders for one host with non-empty Site rules.  Same shape
// as BypassPathHostMaps but with per-rule Mode preserved so the rendered
// `map $request_uri ...` block can set $protected_mode_host_<varname> to the
// mode string (= "captcha" / "pow" / "strict") rather than a binary 1/0.
type ProtectedPathHostMaps struct {
	Host    string              // exact host string (= dispatcher map key)
	VarName string              // nginx-variable-safe identifier derived from Host
	Rules   []ProtectedPathRule // path + mode list, evaluated against $request_uri
}

// ProtectedPathDisableHostMaps describes the per-host "Remove" set: paths
// the site opts out of the default global protected-path list.  Renders into
// a `map $request_uri $protected_mode_disable_host_<varname> { ... "1"; }`
// block; the dispatcher OR's the per-host disable signal and the global
// $protected_mode is suppressed when the matched host's disable=1.
type ProtectedPathDisableHostMaps struct {
	Host     string   // exact host string
	VarName  string   // nginx-variable-safe identifier
	Patterns []string // path-anchored regex list (= paths to suppress)
}

// splitProtectedPathsForRender separates merged rules into:
//   - globals: rules with Site == "" (= apply to every host)
//   - perHost: one ProtectedPathHostMaps per unique non-empty Site
//
// Same deterministic ordering as splitBypassPathsForRender (= globals follow
// input order, perHost groups are sorted by Host so the rendered text is
// stable across runs).
func splitProtectedPathsForRender(rules []ProtectedPathRule) (globals []ProtectedPathRule, perHost []ProtectedPathHostMaps) {
	byHost := map[string][]ProtectedPathRule{}
	hostOrder := []string{}
	for _, r := range rules {
		if r.Site == "" {
			globals = append(globals, r)
			continue
		}
		if _, seen := byHost[r.Site]; !seen {
			hostOrder = append(hostOrder, r.Site)
		}
		byHost[r.Site] = append(byHost[r.Site], r)
	}
	sort.Strings(hostOrder)
	for _, host := range hostOrder {
		perHost = append(perHost, ProtectedPathHostMaps{
			Host:    host,
			VarName: hostToNginxVarSegment(host),
			Rules:   byHost[host],
		})
	}
	return
}

// ProtectedPathPresetGroup: a preset group of protected paths.  Rules inside
// the group hold {Pattern, Mode} per entry (= captcha for login pages, pow
// for APIs, etc.).
type ProtectedPathPresetGroup struct {
	ID      string
	Label   string
	Rules   []ProtectedPathRule
	AddedIn string
}

// ProtectedPathPresetGroups: typical "you probably want to protect this" path sets.
//
// Default ON / OFF is set in settings.defaults(): "unmask" ships ON because
// it covers unmask's own admin login at the fixed `/unmask/admin/` path --
// no site-layout dependency, and the brand cost of an admin brute-force on
// an anti-bot product is too large to leave to opt-in.  "common-admin" stays
// OFF because it assumes `/wp-admin/` etc. exist on the protected site;
// enabling it without checking the layout would silently CAPTCHA legitimate
// users.
//
// Mode is fixed by the preset.  Admin login forms expect a human, so
// "captcha" is appropriate (= blocks bots, while a real operator gets through
// after a single CAPTCHA).
var ProtectedPathPresetGroups = []ProtectedPathPresetGroup{
	{
		ID:    "unmask",
		Label: "unmask itself (= cover the /unmask/admin/ login page with CAPTCHA)",
		Rules: []ProtectedPathRule{
			{Pattern: `^/unmask/admin/`, Mode: ProtectedModeCaptcha},
		},
	},
	{
		ID:    "common-admin",
		Label: "Common admin / CMS paths (= /wp-admin/ /wp-login.php /phpmyadmin/ /admin/ /administrator/ /manager/html)",
		Rules: []ProtectedPathRule{
			{Pattern: `^/wp-admin/`, Mode: ProtectedModeCaptcha},
			{Pattern: `^/wp-login\.php`, Mode: ProtectedModeCaptcha},
			{Pattern: `^/phpmyadmin/`, Mode: ProtectedModeCaptcha},
			{Pattern: `^/admin/`, Mode: ProtectedModeCaptcha},
			{Pattern: `^/administrator/`, Mode: ProtectedModeCaptcha},
			{Pattern: `^/manager/html`, Mode: ProtectedModeCaptcha},
		},
	},
}
