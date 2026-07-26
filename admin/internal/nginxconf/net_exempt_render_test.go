package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestNetExemptPathRender pins the native geo/asn-only exemption: the
// $is_net_exempt_path signal is always defined (empty global map when unused),
// $is_net_challenge folds it in so a matched feed drops only the geo/asn axis,
// and configured rows render as $request_uri-keyed patterns (global + per-host)
// exactly like bypass paths.  The composite $final_challenge key is unchanged
// (still routes on $is_net_challenge), so ja4 / honeypot / protected / UA are
// untouched.
func TestNetExemptPathRender(t *testing.T) {
	off := renderHTTPInc(t, nil)
	if !strings.Contains(off, "map $request_uri $unmask_ne_global") {
		t.Error("no rules: $unmask_ne_global map must still be defined")
	}
	if !strings.Contains(off, "$is_net_exempt_path {") {
		t.Error("no rules: $is_net_exempt_path signal must be defined")
	}
	if !strings.Contains(off, `map "$is_geo_challenge:$is_asn_challenge:$is_net_exempt_path" $is_net_challenge`) {
		t.Error("$is_net_challenge must fold in $is_net_exempt_path")
	}
	// The net-exempt veto forces net-challenge to 0; the other final-challenge
	// fields (ja4/honeypot/protected/ua) stay in the composite key untouched.
	if !strings.Contains(off, `"~:1$"  0;`) {
		t.Error("net-exempt path must force $is_net_challenge to 0 regardless of geo/asn")
	}

	on := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.NetExemptPaths = settings.NetExemptPathsConfig{
			Paths: []settings.BypassPath{
				{Path: "^/feed"}, // global
				{Path: "^/atom", Site: "shop.example.com"}, // per-site
				{Path: "^/off", Disabled: true},            // disabled -> omitted
			},
		}
	})
	for _, want := range []string{
		`"~^/feed" "1";`,                      // global net-exempt pattern
		`map $host $unmask_ne_per_host`,       // per-host dispatcher present
		`"shop.example.com" $unmask_ne_host_`, // shop dispatch
		`"~^/atom" "1";`,                      // per-host pattern
	} {
		if !strings.Contains(on, want) {
			t.Errorf("expected %q in http.inc", want)
		}
	}
	if strings.Contains(on, `"~^/off"`) {
		t.Error("disabled net-exempt row must not render")
	}
}
