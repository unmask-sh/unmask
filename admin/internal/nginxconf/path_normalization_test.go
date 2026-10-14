package nginxconf

import (
	"strings"
	"testing"
)

// TestPathPolicyMapsKeyedOnNormalizedURI guards the fix for the path
// decision / routing mismatch: the path-policy maps are decided on $uri (the
// normalized, decoded path nginx actually routes and serves), not on the raw
// $request_uri.
//
// With the raw $request_uri, a request like `/static/%2e%2e/admin` matched the
// default `^/static/` bypass (raw prefix) yet was routed and served as
// `/admin` (normalized) -- so an encoded traversal bought a bypass that turned
// off the challenge, rate limit, protected-path and honeypot axes, and the
// same mismatch let `/static/../secret` dodge a `^/secret` protected rule.
// Keying these maps on $uri removes the mismatch: the decision sees the same
// path that gets served.
//
// Honeypot and custom-rule path maps intentionally stay on $request_uri: they
// match the raw, undecoded form and the query string (see honeypot_sqli_test
// and custom_rules_render_test), so they must NOT be switched here.
func TestPathPolicyMapsKeyedOnNormalizedURI(t *testing.T) {
	inc := renderHTTPInc(t, nil)

	for _, want := range []string{
		"map $uri $unmask_bp_global {", // bypass paths
		"map $uri $unmask_pp_global {", // protected paths
		"map $uri $unmask_gx_global {", // geo-exempt paths
		"map $uri $unmask_ax_global {", // asn-exempt paths
	} {
		if !strings.Contains(inc, want) {
			t.Errorf("path-policy map not keyed on $uri: expected %q in http.inc", want)
		}
	}

	// The vulnerable raw-$request_uri keying must be gone for these axes.
	for _, bad := range []string{
		"map $request_uri $unmask_bp_global {",
		"map $request_uri $unmask_pp_global {",
		"map $request_uri $unmask_gx_global {",
		"map $request_uri $unmask_ax_global {",
	} {
		if strings.Contains(inc, bad) {
			t.Errorf("path-policy map still keyed on raw $request_uri: %q", bad)
		}
	}

	// Honeypot stays on the raw request URI (query string + undecoded probes).
	if !strings.Contains(inc, "map $request_uri $unmask_hp_global {") {
		t.Error("honeypot map must stay keyed on $request_uri (raw form + query)")
	}
}
