package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/ratelimit"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A "deny" rate-limit zone is a HARD CAP.  A valid _bv (the visitor already
// passed a challenge) exempts the client from CHALLENGE-mode zones -- there is
// no point re-challenging a proven human -- but it must NOT buy a pass past a
// deny zone: a human who passed CAPTCHA can still flood.  This pins both halves
// (regression for the "_bv holder floods the admin cap" bypass).
func TestAuthCheck_DenyZoneDoesNotExemptBV(t *testing.T) {
	const ip = "203.0.113.50" // TEST-NET-3, not loopback / bypass
	const host = "shop.example.com"
	const ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

	cfg := func(mode string) settings.Settings {
		return settings.Settings{
			Secret: settings.Secret{BVSecret: "test-secret"},
			RateLimit: settings.RateLimitConfig{
				Zones: []settings.RateZone{{
					Name:           "admin",
					PathPatterns:   []string{"/admin/"},
					ChallengeMode:  mode,
					RequestsPerMin: 2,
				}},
			},
		}
	}
	bv := cookies.IssueValue("test-secret", ip, host, "captcha")
	drive := func(h *Handler) *http.Response {
		r := httptest.NewRequest(http.MethodGet, "/unmask/api/check", nil)
		r.Header.Set("X-Original-URI", "/admin/dashboard")
		r.Header.Set("X-Original-IP", ip)
		r.Header.Set("X-Original-Host", host)
		r.Header.Set("User-Agent", ua)
		r.AddCookie(&http.Cookie{Name: "_bv", Value: bv})
		w := httptest.NewRecorder()
		h.AuthCheck(w, r)
		return w.Result()
	}

	t.Run("deny zone blocks a _bv holder once over the cap", func(t *testing.T) {
		h := &Handler{RateLimiter: ratelimit.New()}
		h.SetSettings(cfg(settings.RateChallengeDeny))
		if got := drive(h).Header.Get("X-Unmask-Action"); got != "pass" {
			t.Fatalf("first request: a valid _bv under the cap must pass, got %q "+
				"(check IssueValue kind / trust)", got)
		}
		blocked := false
		for i := 0; i < 12 && !blocked; i++ {
			res := drive(h)
			blocked = res.StatusCode == http.StatusForbidden &&
				res.Header.Get("X-Unmask-Action") == "block"
		}
		if !blocked {
			t.Error("a _bv holder flooding a deny zone was never blocked -> the hard cap is bypassable")
		}
	})

	t.Run("captcha zone keeps the _bv exemption (never re-challenged)", func(t *testing.T) {
		h := &Handler{RateLimiter: ratelimit.New()}
		h.SetSettings(cfg(settings.RateChallengeCaptchaOnly))
		for i := 0; i < 12; i++ {
			if got := drive(h).Header.Get("X-Unmask-Action"); got != "pass" {
				t.Fatalf("request %d: a _bv holder on a captcha zone must stay passed "+
					"(no re-challenge), got %q", i, got)
			}
		}
	})
}
