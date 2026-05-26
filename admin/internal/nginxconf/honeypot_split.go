// Honeypot path render-time splitter.  Mirrors bypass_path.go: one global
// path map (= rule.Site == "") + one map per unique non-empty Site, with a
// host dispatcher that picks the per-host result.  Result is boolean
// ("0" / "1"), so the final OR-combine is a straight concatenation check
// instead of the value-pass-through used by protected paths.
package nginxconf

import "sort"

// HoneypotPathRule: render-time row carrying a path pattern + an optional
// per-host scope.  Distinct from settings.HoneypotURL (= the yml type) so
// the render layer can keep its source-of-truth shape free of yml tags.
type HoneypotPathRule struct {
	Pattern string // path-anchored regex, evaluated against $request_uri
	Site    string // empty = global; non-empty = exact $host match
}

// HoneypotHostMaps describes the per-host honeypot map that the
// http.conf.tmpl renders for a single host with non-empty Site rules.
type HoneypotHostMaps struct {
	Host     string   // exact host string (= goes into the dispatcher map key)
	VarName  string   // nginx-variable-safe identifier derived from Host
	Patterns []string // path-anchored regex list, evaluated against $request_uri
}

// splitHoneypotPathsForRender separates merged rules into:
//   - globals: patterns for rules with Site == "" (= apply to every host)
//   - perHost: one HoneypotHostMaps per unique non-empty Site
//
// Deterministic ordering matches the bypass-path splitter: globals follow
// the caller's slice order, perHost groups are sorted by Host.
func splitHoneypotPathsForRender(rules []HoneypotPathRule) (globals []string, perHost []HoneypotHostMaps) {
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
		perHost = append(perHost, HoneypotHostMaps{
			Host:     host,
			VarName:  hostToNginxVarSegment(host),
			Patterns: byHost[host],
		})
	}
	return
}
