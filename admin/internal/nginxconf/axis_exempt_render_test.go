package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestAxisExemptPathRender pins the native per-axis exemption: both signals
// ($is_geo_exempt_path / $is_asn_exempt_path) are always defined (empty global
// maps when unused), each axis's effective verdict folds in ONLY its own
// signal, $is_net_challenge combines the two effective verdicts, and the
// composite $final_challenge key is unchanged (still routes on
// $is_net_challenge) so ja4 / honeypot / protected / UA are untouched.
func TestAxisExemptPathRender(t *testing.T) {
	off := renderHTTPInc(t, nil)
	for _, want := range []string{
		"map $request_uri $unmask_gx_global",
		"map $request_uri $unmask_ax_global",
		"$is_geo_exempt_path {",
		"$is_asn_exempt_path {",
		`map "$is_geo_challenge:$is_geo_exempt_path" $geo_challenge_eff`,
		`map "$is_asn_challenge:$is_asn_exempt_path" $asn_challenge_eff`,
		`map "$geo_challenge_eff:$asn_challenge_eff" $is_net_challenge`,
	} {
		if !strings.Contains(off, want) {
			t.Errorf("no rules: expected %q in http.inc", want)
		}
	}

	on := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.Geo.ExemptPaths = []settings.BypassPath{
			{Path: "^/feed"}, // global, geo only
			{Path: "^/atom", Site: "shop.example.com"}, // per-site
		}
		s.Nginx.Asn.ExemptPaths = []settings.BypassPath{
			{Path: "^/rss"},                 // global, asn only
			{Path: "^/off", Disabled: true}, // disabled -> omitted
		}
	})
	for _, want := range []string{
		`"~^/feed" "1";`,                      // geo global pattern
		`map $host $unmask_gx_per_host`,       // geo per-host dispatcher
		`"shop.example.com" $unmask_gx_host_`, // shop dispatch
		`"~^/atom" "1";`,                      // per-host pattern
		`"~^/rss" "1";`,                       // asn global pattern
	} {
		if !strings.Contains(on, want) {
			t.Errorf("expected %q in http.inc", want)
		}
	}
	if strings.Contains(on, `"~^/off"`) {
		t.Error("disabled asn-exempt row must not render")
	}
	// The geo-only /feed pattern must not leak into the asn map ($unmask_ax_*).
	axStart := strings.Index(on, "map $request_uri $unmask_ax_global")
	if axStart < 0 {
		t.Fatal("asn exempt global map missing")
	}
	axEnd := strings.Index(on[axStart:], "}")
	if axBlock := on[axStart : axStart+axEnd]; strings.Contains(axBlock, "/feed") {
		t.Error("geo-only pattern leaked into the asn exempt map")
	}
}
