package nginxconf

import (
	"os"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A network rule that says CAPTCHA must not be satisfied by a proof-of-work
// cookie.  The veto consults $unmask_needs_captcha_grade, so a captcha-ending
// geo/ASN rule has to (a) arm the grade block at all and (b) appear in its
// key.  Before this wiring, an ASN captcha_only rule stopped only addresses
// arriving bare: every pow-cookie holder passed for the cookie's remaining
// lifetime -- measured live as 1,096 content pages in two hours through a rule
// that said captcha_only.
func TestAxisCaptchaRulesArmTheGradeGate(t *testing.T) {
	render := func(s settings.Settings) string {
		dir := t.TempDir()
		s.Nginx.OutputDir = dir
		if err := Render(s, dir, "test"); err != nil {
			t.Fatalf("render: %v", err)
		}
		b, err := os.ReadFile(dir + "/http.inc")
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	// Silence the shipped challenge-target presets so the only grade source
	// under test is the network rule itself.
	noPresets := func(s *settings.Settings) {
		for _, g := range ChallengeTargetGroups {
			s.Nginx.ChallengeTargets.DisabledPresets = append(s.Nginx.ChallengeTargets.DisabledPresets, g.ID)
		}
	}

	t.Run("an ASN captcha_only rule arms the gate", func(t *testing.T) {
		var s settings.Settings
		noPresets(&s)
		s.Nginx.Asn.Rules = []settings.AsnRule{{ASN: 132203, Action: settings.GeoActionCaptchaOnly, Enabled: true}}
		out := render(s)
		if !strings.Contains(out, "$unmask_asn_captcha") {
			t.Fatal("the ASN grade signal was not emitted")
		}
		if !strings.Contains(out, ":$unmask_geo_captcha$unmask_asn_captcha\" $unmask_needs_captcha_grade") {
			t.Fatal("the grade requirement key does not consult the network axes")
		}
		// Exempt-awareness: the signal keys on the axis's own exempt-path map.
		if !strings.Contains(out, `"$is_asn_exempt_path:$unmask_asn_action" $unmask_asn_captcha`) {
			t.Error("the ASN grade signal ignores asn-exempt paths")
		}
	})

	t.Run("a provider with no action inherits a captcha-ending chain and arms it", func(t *testing.T) {
		var s settings.Settings
		noPresets(&s)
		// Blank action inherits DefaultRuleAction = pow_then_captcha, which
		// ends in a CAPTCHA -- the live-incident shape (a ticked provider with
		// nothing else filled in).
		s.Nginx.Asn.Providers = []settings.AsnProviderSel{{ID: "tencent", Enabled: true}}
		out := render(s)
		if !strings.Contains(out, "$unmask_asn_captcha") {
			t.Fatal("an enabled provider on the inherited chain leaves the gate unarmed")
		}
	})

	t.Run("a geo captcha rule arms it too", func(t *testing.T) {
		var s settings.Settings
		noPresets(&s)
		s.Nginx.Geo.Rules = []settings.GeoRule{{Country: "CN", Action: settings.GeoActionCaptchaOnly, Enabled: true}}
		out := render(s)
		if !strings.Contains(out, `"$is_geo_exempt_path:$unmask_geo_action" $unmask_geo_captcha`) {
			t.Fatal("the geo grade signal was not emitted")
		}
	})

	t.Run("pow-only network rules impose no grade requirement", func(t *testing.T) {
		var s settings.Settings
		noPresets(&s)
		s.Nginx.Asn.Rules = []settings.AsnRule{{ASN: 4837, Action: settings.GeoActionPoWOnly, Enabled: true}}
		out := render(s)
		// The grade block itself is armed regardless on a default install (the
		// shipped protected-path presets end in a CAPTCHA), so the assertion
		// is on the signal map: pow_only must map to nothing -- a pow cookie
		// is exactly what that rule's chain mints.
		if strings.Contains(out, `"0:pow_only"`) {
			t.Error("a pow_only network rule marks the captcha-grade signal")
		}
	})
}
