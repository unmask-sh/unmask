// Protected-paths render-time splitter.  Mirrors bypass_path.go's
// splitBypassPathsForRender: one global path map + one map per unique
// non-empty Site, plus a host dispatcher that selects per-host result.
//
// The per-host map yields a *mode string* ("captcha" / "pow" / "strict") or
// "" (= no match).  A final OR-merge picks per-host first (= the more
// specific override) and falls back to global.  Both layers use
// `map $request_uri ...` so a path-anchored regex like `^/admin/` keeps its
// natural meaning -- no host concatenation in the pattern.
package nginxconf

import "sort"

// ProtectedPathHostMaps describes the per-host protected-path map that
// http.conf.tmpl renders for a single host with non-empty Site rules.
// Rules retain their mode strings; the renderer emits one map entry per
// rule that returns the mode literal.
type ProtectedPathHostMaps struct {
	Host    string              // exact host string (= goes into the dispatcher map key)
	VarName string              // nginx-variable-safe identifier derived from Host
	Rules   []ProtectedPathRule // pattern + mode pairs evaluated against $request_uri
}

// splitProtectedPathsForRender splits merged rules into:
//   - globals: rules with Site == "" (= apply to every host)
//   - perHost: one ProtectedPathHostMaps per unique non-empty Site
//
// Deterministic ordering: globals follow the input slice order (the caller
// sorts upstream); perHost groups are sorted by Host so the rendered map
// text is stable across runs.
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
