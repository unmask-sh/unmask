package nginxlog

import "testing"

// A request passing on a re-bound cookie has to reach the per-address reuse
// ranking, the same as the solves it used to be labelled with.
//
// Those requests arrived as kind "captcha" until the plugin learned to name
// the re-bind, and were ranked with everything else.  The allowlist here was
// written against the two names that existed then, so making the
// classification more honest would have quietly dropped a re-binding client
// out of the one view that shows its per-address volume -- acquiring a blind
// spot as a side effect of removing one.
func TestCookieIPKindsCoversEveryPass(t *testing.T) {
	for kind, want := range map[string]bool{
		"captcha": true,
		"pow":     true,
		"rebind":  true,
		// Not a presented cookie: nothing to rank an address by.
		"challenge_served": false,
		"crawler_pass":     false,
		"bypass_pass":      false,
		"total":            false,
		"":                 false,
		// A kind this build has not learned yet stays out rather than being
		// counted as something it is not -- the ranking splits by how the
		// cookie was earned, and an unknown answer is not one of them.
		"passkey": false,
	} {
		if got := cookieIPKinds(kind); got != want {
			t.Errorf("cookieIPKinds(%q) = %v, want %v", kind, got, want)
		}
	}
}
