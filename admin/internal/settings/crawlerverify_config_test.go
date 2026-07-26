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

// TestCrawlerActive: an empty disabled-list means every crawler is active; a
// listed name (case-insensitive) is off.
func TestCrawlerActive(t *testing.T) {
	if !(CrawlerVerifyConfig{}).CrawlerActive("Googlebot") {
		t.Error("empty disabled-list: all crawlers should be active")
	}
	cv := CrawlerVerifyConfig{DisabledCrawlers: []string{"Googlebot", "baiduspider"}}
	if cv.CrawlerActive("Googlebot") {
		t.Error("Googlebot should be inactive")
	}
	if !cv.CrawlerActive("YandexBot") {
		t.Error("YandexBot should stay active")
	}
	if cv.CrawlerActive("Baiduspider") { // case-insensitive
		t.Error("Baiduspider should be inactive (case-insensitive match)")
	}
}
