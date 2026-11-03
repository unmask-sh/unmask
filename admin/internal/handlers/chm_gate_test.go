package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The chain-mode hint in the query (?chm=) used to be honoured on a direct
// hit of the public challenge route, so a visitor could pick the chain they
// were served -- never below what the gate requires, but lighter than the
// posture -- and the chain the serve recorded with it.  It is taken only from
// a request nginx routed here from another URI.
func TestChmHintOnlyFromAnInternalRoute(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	cur.Global.KnownBrowserAction = settings.RateChallengePoWOnly
	h.SetSettings(cur)
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
	serve := func(orig string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/?chm=captcha_only", nil)
		req.Header.Set("User-Agent", ua)
		if orig != "" {
			req.Header.Set("X-Original-URI", orig)
		}
		rr := httptest.NewRecorder()
		h.ServeChallenge(rr, req)
		return chModeFromChallengeHTML(rr.Body.String())
	}
	if got := serve(""); got != settings.RateChallengePoWOnly {
		t.Errorf("a direct hit with ?chm=captcha_only was served %q, want the posture's pow_only", got)
	}
	if got := serve("/unmask/challenge/?chm=captcha_only"); got != settings.RateChallengePoWOnly {
		t.Errorf("a direct hit through the proxy was served %q, want the posture's pow_only", got)
	}
	if got := serve("/account/settings"); got != settings.RateChallengeCaptchaOnly {
		t.Errorf("a request routed from a page was served %q, want the hint's captcha_only", got)
	}
}
