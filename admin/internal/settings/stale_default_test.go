package settings

import "testing"

// TestStaleBrowserDefaults pins the two decisions that keep this tier from
// costing more than it catches.
//
// Off by default: over a production day, visitors it escalated abandoned at
// many times the baseline rate, and a large share of those who stayed solved
// the CAPTCHA -- they were people.  It is a deliberate opt-in, not a posture
// the product takes on someone's behalf.
//
// And when it IS on, the threshold has to clear the genuine long tail.  At
// Chromium's ~4-week cadence 10 majors is about ten months, which a corporate
// or auto-update-disabled browser reaches routinely; 15 keeps the tier above
// that while still catching the 2026-07-15 scraper, which sat 11 behind.
func TestStaleBrowserDefaults(t *testing.T) {
	s, _ := Load("/nonexistent/unmask-test.yml")
	if s.Global.StaleBrowserEnabled() {
		t.Error("the stale-browser tier must stay opt-in: it demonstrably challenges real visitors")
	}
	if DefaultStaleBrowserLag < 12 {
		t.Errorf("DefaultStaleBrowserLag = %d: too close to the genuine old-browser tail (~10 majors ≈ 10 months)", DefaultStaleBrowserLag)
	}
	// It must still catch the incident that motivated the tier (11 majors behind).
	if DefaultStaleBrowserLag > 20 {
		t.Errorf("DefaultStaleBrowserLag = %d: so lax the tier stops catching what it exists for", DefaultStaleBrowserLag)
	}
	// Firefox is judged separately but must not end up stricter by accident.
	if DefaultStaleBrowserLagFirefox < DefaultStaleBrowserLag {
		t.Errorf("Firefox lag %d is stricter than Chromium's %d — if that is intended it needs its own reason",
			DefaultStaleBrowserLagFirefox, DefaultStaleBrowserLag)
	}
}
