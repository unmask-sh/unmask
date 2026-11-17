package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestThrottledRowsMapToSkip: a country or network rule set to a rate acts on
// the overage only, through its rate zone, and lets the requests under its
// cap through.  In the action maps it had no entry, so its country or network
// took the map's default -- the action for the ones no rule names, here a
// CAPTCHA -- on every request under the cap, where the daemon and the rule
// itself let them through.  It maps to skip now.
func TestThrottledRowsMapToSkip(t *testing.T) {
	rate := 60
	httpInc := renderHTTPInc(t, func(s *settings.Settings) {
		s.Nginx.Geo = settings.GeoConfig{
			DefaultAction: settings.RateChallengeCaptchaOnly,
			Rules: []settings.GeoRule{
				{Country: "JP", Action: settings.RateChallengeCaptchaOnly, RatePerMin: &rate, Enabled: true},
				{Country: "CN", Action: settings.GeoActionDeny, Enabled: true},
			},
		}
		s.Nginx.Asn = settings.AsnConfig{
			DefaultAction: settings.RateChallengeCaptchaOnly,
			Rules: []settings.AsnRule{
				{ASN: 64501, Action: settings.RateChallengeCaptchaOnly, RatePerMin: &rate, Enabled: true},
				{ASN: 64500, Action: settings.GeoActionDeny, Enabled: true},
			},
		}
	})
	block := func(head string) string {
		i := strings.Index(httpInc, head)
		if i < 0 {
			t.Fatalf("http.inc has no %q", head)
		}
		j := strings.Index(httpInc[i:], "\n}")
		return httpInc[i : i+j]
	}
	geo := block("map $unmask_country $unmask_geo_action {")
	for _, want := range []string{`default "captcha_only";`, `"JP" "skip";`, `"CN" "deny";`} {
		if !strings.Contains(geo, want) {
			t.Errorf("the country action map lacks %q:\n%s", want, geo)
		}
	}
	asn := block("map $unmask_asn $unmask_asn_action {")
	for _, want := range []string{`default "captcha_only";`, `"AS64501" "skip";`, `"AS64500" "deny";`} {
		if !strings.Contains(asn, want) {
			t.Errorf("the network action map lacks %q:\n%s", want, asn)
		}
	}
}
