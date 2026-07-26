package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestHeaderDecide pins the header-integrity axis (v0.2 #2): it fires ONLY when
// a Chromium UA over https/h2h3 carries no Sec-CH-UA, is silent on every
// precondition failure (the FP fence), and is clamped to a challenge severity
// -- never deny.
func TestHeaderDecide(t *testing.T) {
	const chrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
	const firefox = "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0"

	on := settings.GlobalConfig{HeaderIntegrity: true}
	off := settings.GlobalConfig{HeaderIntegrity: false}

	cases := []struct {
		name       string
		ua         string
		secChUA    string
		scheme     string
		modern     bool
		g          settings.GlobalConfig
		wantOK     bool
		wantSev    axisSeverity
		wantReason string
	}{
		{"chromium https h2 no CH -> fire captcha", chrome, "", "https", true, on, true, sevCaptchaOnly, "header:no_sch_ua"},
		{"axis off -> silent", chrome, "", "https", true, off, false, sevPass, ""},
		{"CH present -> silent", chrome, `"Chromium";v="120"`, "https", true, on, false, sevPass, ""},
		{"http (not https) -> silent", chrome, "", "http", true, on, false, sevPass, ""},
		{"h1 (not modern) -> silent", chrome, "", "https", false, on, false, sevPass, ""},
		{"firefox -> silent (not chromium)", firefox, "", "https", true, on, false, sevPass, ""},
		{"empty ua -> silent", "", "", "https", true, on, false, sevPass, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			d, ok := headerDecide(c.ua, c.secChUA, c.scheme, c.modern, c.g)
			if ok != c.wantOK {
				t.Fatalf("ok=%v, want %v (d=%+v)", ok, c.wantOK, d)
			}
			if !ok {
				return
			}
			if d.sev != c.wantSev || d.reason != c.wantReason {
				t.Errorf("d=(sev=%d reason=%q), want (sev=%d reason=%q)", d.sev, d.reason, c.wantSev, c.wantReason)
			}
		})
	}

	// The operator's action tunes the severity, but deny can never be reached:
	// HeaderIntegrityResolvedAction clamps a stored "deny" to captcha_only.
	denyish := settings.GlobalConfig{HeaderIntegrity: true, HeaderIntegrityAction: settings.RateChallengeDeny}
	if d, ok := headerDecide(chrome, "", "https", true, denyish); !ok || d.sev == sevDeny {
		t.Errorf("a stored deny action must clamp to a challenge, got sev=%d ok=%v", d.sev, ok)
	}
	powish := settings.GlobalConfig{HeaderIntegrity: true, HeaderIntegrityAction: settings.RateChallengePoWOnly}
	if d, _ := headerDecide(chrome, "", "https", true, powish); d.sev != sevPoWOnly {
		t.Errorf("pow_only action -> sevPoWOnly, got %d", d.sev)
	}
}
