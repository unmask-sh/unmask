package settings

import "testing"

// The challenge knobs live under `challenge.default.*` (multi-site v2).  The
// config-init + docker generators used to emit them flat under `challenge:`,
// which the loader silently drops -- so every operator edit to provider /
// cookie windows / pow_difficulty was a no-op.  Lock the contract: nested
// values take effect, flat values are ignored.
func TestChallengeKnobs_NestedDefaultLoadsFlatIgnored(t *testing.T) {
	nested, err := LoadFromYAML("challenge:\n  default:\n    pow_cookie_valid_seconds: 12345\n    captcha:\n      provider: hcaptcha\n")
	if err != nil {
		t.Fatal(err)
	}
	v := nested.Challenge.Resolve("")
	if v.PowCookieValidSeconds != 12345 {
		t.Errorf("nested pow_cookie_valid_seconds = %d, want 12345", v.PowCookieValidSeconds)
	}
	if v.CaptchaProvider.Provider != "hcaptcha" {
		t.Errorf("nested captcha.provider = %q, want hcaptcha", v.CaptchaProvider.Provider)
	}

	flat, err := LoadFromYAML("challenge:\n  pow_cookie_valid_seconds: 12345\n")
	if err != nil {
		t.Fatal(err)
	}
	if flat.Challenge.Resolve("").PowCookieValidSeconds == 12345 {
		t.Error("flat challenge.pow_cookie_valid_seconds must be ignored (this was the bug), but it loaded")
	}
}
