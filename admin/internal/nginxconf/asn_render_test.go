package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestAsnRenderBlocks pins the native ASN wiring: with rules present the
// action map + is_asn_challenge + the combined is_net_challenge are emitted,
// the final-challenge composite key routes on is_net_challenge (not the bare
// is_geo_challenge), and with no rules the axis degrades to the skip default.
func TestAsnRenderBlocks(t *testing.T) {
	// No ASN rules: action map defaults to skip, no CIDRs, but the maps still
	// exist (so $unmask_asn_action / $is_asn_challenge are always defined).
	off := renderHTTPInc(t, nil)
	if !strings.Contains(off, "map $unmask_asn $unmask_asn_action") {
		t.Error("no rules: $unmask_asn_action map must still be defined")
	}
	if !strings.Contains(off, "map \"$is_geo_challenge:$is_asn_challenge\" $is_net_challenge") {
		t.Error("no rules: is_net_challenge combining map missing")
	}
	if !strings.Contains(off, "$is_net_challenge:$protected_mode_eff") {
		t.Error("composite final-challenge key must route on is_net_challenge")
	}

	// Rules present: the per-ASN action map lists them, and the geo block
	// header is emitted (CIDRs stay empty without an ASN mmdb, which is fine —
	// the axis then no-ops until a db is configured).
	on := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.Asn = settings.AsnConfig{
			DefaultAction: settings.GeoActionSkip,
			Rules: []settings.AsnRule{
				{ASN: 16509, Action: settings.GeoActionDeny, Enabled: true},
				{ASN: 14061, Action: settings.GeoActionCaptchaOnly, Enabled: true},
				{ASN: 99999, Action: settings.GeoActionPoWOnly, Enabled: false}, // disabled -> omitted
			},
		}
	})
	for _, want := range []string{
		`geo $remote_addr $unmask_asn {`,
		`"14061" "captcha_only";`,
		`"16509" "deny";`,
	} {
		if !strings.Contains(on, want) {
			t.Errorf("rules on: expected %q in http.inc", want)
		}
	}
	if strings.Contains(on, `"99999"`) {
		t.Error("disabled ASN rule must not be rendered")
	}
	// ASN action map entries are sorted by number (deterministic output).
	if i, j := strings.Index(on, `"14061"`), strings.Index(on, `"16509"`); i < 0 || j < 0 || i > j {
		t.Error("ASN action map must be sorted ascending by AS number")
	}
}
