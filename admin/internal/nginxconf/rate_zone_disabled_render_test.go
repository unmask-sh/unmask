package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Native mode must not emit a switched-off zone at all: leaving the
// limit_req_zone in the rendered config would keep enforcing on that wire what
// the UI shows as off (and what forward-auth already stopped enforcing).
func TestDisabledZoneIsNotRendered(t *testing.T) {
	conf := renderHTTPInc(t, func(s *settings.Settings) {
		s.RateLimit.Zones = []settings.RateZone{
			{Name: "off_zone", PathPatterns: []string{"/api/"}, RequestsPerMin: 5, Disabled: true},
			{Name: "on_zone", PathPatterns: []string{"/admin/"}, RequestsPerMin: 7},
		}
	})
	if strings.Contains(conf, "off_zone") {
		t.Error("a disabled zone was rendered into the nginx config; native mode would still enforce it")
	}
	if !strings.Contains(conf, "on_zone") {
		t.Error("the enabled zone is missing from the render")
	}
}

// The deny/protected-paths compose warning is about what actually runs, so a
// disabled deny zone must not raise it -- otherwise an operator switches the
// zone off and the warning stays, describing a constraint that no longer holds.
func TestDisabledDenyZoneDoesNotTriggerComposeWarning(t *testing.T) {
	var s settings.Settings
	s.RateLimit.Default.ChallengeMode = settings.RateChallengePoWOnly
	s.RateLimit.Zones = []settings.RateZone{
		{Name: "deny_zone", PathPatterns: []string{"/api/"}, RequestsPerMin: 5,
			ChallengeMode: settings.RateChallengeDeny, Disabled: true},
	}
	if HasDenyRateZone(s) {
		t.Error("a disabled deny zone still reports as a deny zone")
	}
	s.RateLimit.Zones[0].Disabled = false
	if !HasDenyRateZone(s) {
		t.Error("an enabled deny zone should report as one")
	}
}
