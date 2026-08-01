package settings

import "testing"

// A switched-off zone keeps its row but stops being enforced.  The flag has to
// hold on EVERY evaluation path -- the resolver the forward-auth daemon calls,
// and the zone list the native render walks -- or a row the UI shows as off
// keeps firing on one of the two wires.
func TestDisabledZoneIsNotResolved(t *testing.T) {
	c := RateLimitConfig{
		Default: RateLimitValues{RequestsPerMin: 100, Burst: 50, ChallengeMode: RateChallengePoWOnly},
		Zones: []RateZone{
			{Name: "off_zone", PathPatterns: []string{"/api/"}, RequestsPerMin: 5, ChallengeMode: RateChallengeDeny, Disabled: true},
			{Name: "on_zone", PathPatterns: []string{"/admin/"}, RequestsPerMin: 7, ChallengeMode: RateChallengeCaptchaOnly},
		},
	}

	// A path that only the disabled zone matches falls through to the default.
	got := c.ResolveZone("/api/x", "")
	if got.Name == "off_zone" {
		t.Error("a disabled zone still matched; the row is shown as off but is being enforced")
	}
	if got.RequestsPerMin != 100 {
		t.Errorf("expected the default zone's threshold after the disabled row was skipped, got %d", got.RequestsPerMin)
	}
	// The enabled row is untouched.
	if got := c.ResolveZone("/admin/y", ""); got.Name != "on_zone" {
		t.Errorf("the enabled zone stopped matching, got %q", got.Name)
	}
	// ResolveZones (the per-site listing) hides it too.
	for _, z := range c.ResolveZones("") {
		if z.Name == "off_zone" {
			t.Error("a disabled zone is still listed for the site")
		}
	}
}

// Re-enabling must restore the row exactly: switching off is not a destructive
// edit, which is the whole reason for having the toggle instead of delete.
func TestDisabledZoneKeepsItsSettings(t *testing.T) {
	z := RateZone{Name: "z", PathPatterns: []string{"/api/"}, RequestsPerMin: 5, Burst: 3, ChallengeMode: RateChallengeDeny, Disabled: true}
	c := RateLimitConfig{Zones: []RateZone{z}}
	c.Zones[0].Disabled = false
	got := c.ResolveZone("/api/x", "")
	if got.Name != "z" || got.RequestsPerMin != 5 || got.Burst != 3 || got.ChallengeMode != RateChallengeDeny {
		t.Errorf("re-enabling did not restore the row verbatim: %+v", got)
	}
}
