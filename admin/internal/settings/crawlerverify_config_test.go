package settings

import "testing"

// TestResolvedForgedAction pins the safe default: an unset, "skip", or invalid
// forged-action resolves to a challenge (pow_then_captcha), never a silent
// hard-block, while an explicit valid action is honoured.
func TestResolvedForgedAction(t *testing.T) {
	cases := map[string]string{
		"":                   GeoActionPoWThenCaptcha, // unset -> safe challenge
		"skip":               GeoActionPoWThenCaptcha, // skip is meaningless for a forgery
		"bogus":              GeoActionPoWThenCaptcha, // invalid -> safe challenge
		GeoActionDeny:        GeoActionDeny,
		GeoActionCaptchaOnly: GeoActionCaptchaOnly,
		GeoActionPoWOnly:     GeoActionPoWOnly,
	}
	for in, want := range cases {
		if got := (CrawlerVerifyConfig{ForgedAction: in}).ResolvedForgedAction(); got != want {
			t.Errorf("ResolvedForgedAction(%q) = %q, want %q", in, got, want)
		}
	}
}
