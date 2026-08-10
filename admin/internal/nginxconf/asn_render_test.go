package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestAsnRenderBlocks pins the native ASN wiring: the action map + the
// is_net_challenge combining map are always defined, the final-challenge
// composite key routes on is_net_challenge, and enabled rules/providers emit
// their keyed action-map entries (exact "AS<n>" and org "org:<pattern>").
func TestAsnRenderBlocks(t *testing.T) {
	off := renderHTTPInc(t, nil)
	if !strings.Contains(off, "map $unmask_asn $unmask_asn_action") {
		t.Error("no rules: $unmask_asn_action map must still be defined")
	}
	if !strings.Contains(off, "map \"$geo_challenge_eff:$asn_challenge_eff\" $is_net_challenge") {
		t.Error("no rules: is_net_challenge combining map missing (must combine the per-axis effective verdicts)")
	}
	if !strings.Contains(off, "$is_net_challenge:$protected_mode") {
		t.Error("composite final-challenge key must route on is_net_challenge")
	}

	on := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.Asn = settings.AsnConfig{
			DefaultAction: settings.GeoActionSkip,
			Providers: []settings.AsnProviderSel{
				{ID: "microsoft", Action: settings.GeoActionDeny, Enabled: true},
				{ID: "google", Action: settings.GeoActionPoWOnly, Enabled: false}, // disabled -> omitted
			},
			Rules: []settings.AsnRule{
				{ASN: 16509, Action: settings.GeoActionCaptchaOnly, Enabled: true}, // exact
				{Org: "Hetzner", Action: settings.GeoActionDeny, Enabled: true},    // org
				{ASN: 99999, Action: settings.GeoActionDeny, Enabled: false},       // disabled
			},
		}
	})
	for _, want := range []string{
		`geo $remote_addr $unmask_asn {`,
		`"AS16509" "captcha_only";`, // exact custom rule
		`"org:hetzner" "deny";`,     // org custom rule (lower-cased key)
		`"org:microsoft" "deny";`,   // enabled provider (org pattern)
	} {
		if !strings.Contains(on, want) {
			t.Errorf("expected %q in http.inc", want)
		}
	}
	if strings.Contains(on, `"AS99999"`) {
		t.Error("disabled custom rule must not render")
	}
	if strings.Contains(on, `"org:google"`) {
		t.Error("disabled provider must not render")
	}
}
