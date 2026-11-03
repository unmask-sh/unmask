package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// On the forward-auth wire a stale browser holding a proof-of-work cookie
// does not pass a stale tier whose screen is the CAPTCHA: the tier runs
// after the cookie veto, so the cookie used to carry it past the screen.  A
// CAPTCHA-grade cookie passes, and a tier set to pow_only takes the
// proof-of-work cookie as before.
func TestAuthCheck_StaleTierDemandsItsGrade(t *testing.T) {
	const ip = "203.0.113.70"
	const host = "shop.example.com"
	const stale = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.0.0 Safari/537.36"
	cfg := func(action string) settings.Settings {
		s := settings.Settings{Secret: settings.Secret{BVSecret: "test-secret"}}
		s.Global.KnownBrowserAction = "pass"
		s.Global.StaleBrowserChallenge = true
		s.Global.CurrentChromeMajor = 150
		s.Global.StaleBrowserLag = 35
		s.Global.StaleBrowserAction = action
		return s
	}
	drive := func(h *Handler, kind string) string {
		r := httptest.NewRequest(http.MethodGet, "/unmask/api/check", nil)
		r.Header.Set("X-Original-URI", "/article/1")
		r.Header.Set("X-Original-IP", ip)
		r.Header.Set("X-Original-Host", host)
		r.Header.Set("User-Agent", stale)
		r.AddCookie(&http.Cookie{Name: "_bv", Value: cookies.IssueValue("test-secret", ip, host, kind)})
		w := httptest.NewRecorder()
		h.AuthCheck(w, r)
		return w.Result().Header.Get("X-Unmask-Action")
	}
	h := &Handler{}
	h.SetSettings(cfg(settings.RateChallengeCaptchaOnly))
	if got := drive(h, "pow"); got != "challenge" {
		t.Errorf("stale browser with a proof-of-work cookie on a CAPTCHA tier: got %q, want challenge", got)
	}
	if got := drive(h, "captcha"); got != "pass" {
		t.Errorf("stale browser with a CAPTCHA cookie: got %q, want pass", got)
	}
	h.SetSettings(cfg(settings.RateChallengePoWOnly))
	if got := drive(h, "pow"); got != "pass" {
		t.Errorf("stale browser with a proof-of-work cookie on a pow_only tier: got %q, want pass", got)
	}
}
