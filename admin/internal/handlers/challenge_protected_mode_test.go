package handlers

import (
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The per-path protected mode must drive the served challenge screen on both
// axes.  Mode == action: pow -> pow_only, captcha -> captcha_only,
// pow_then_captcha -> the chain.  No default-action / rate-limit-linkage layer
// on top (removed in the redesign), so the mode the operator picked is exactly
// what gets served.
func servedChModeReq(t *testing.T, h *Handler, target string, hdr map[string]string) string {
	t.Helper()
	req := httptest.NewRequest("GET", target, nil)
	req.Header.Set("User-Agent", uaCurrentChrome)
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeChallenge(w, req)
	m := chModeMarkerRE.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("__CHMODE__ marker not found in challenge body (status=%d)", w.Code)
	}
	return m[1]
}

func TestServeChallengeProtectedPathMode(t *testing.T) {
	h := newTestHandler(t)
	s := *h.cfg()
	s.Global.KnownBrowserAction = "pass"
	s.Nginx.ChallengeTargets.DefaultAction = settings.RateChallengePoWOnly // must NOT leak in
	s.Nginx.ProtectedPaths.Paths = []settings.ProtectedPath{
		{Path: "^/pow-gate/", Mode: "pow"},
		{Path: "^/members/", Mode: "captcha"},
		{Path: "^/vault/", Mode: "pow_then_captcha"},
	}
	h.SetSettings(s)

	// Native axis: the rendered $protected_mode map arrives as a header.
	if got := servedChModeReq(t, h, "/unmask/challenge/", map[string]string{"X-Protected-Mode": "pow"}); got != settings.RateChallengePoWOnly {
		t.Errorf("header pow: want pow_only, got %s", got)
	}
	if got := servedChModeReq(t, h, "/unmask/challenge/", map[string]string{"X-Protected-Mode": "captcha"}); got != settings.RateChallengeCaptchaOnly {
		t.Errorf("header captcha: want captcha_only, got %s", got)
	}
	if got := servedChModeReq(t, h, "/unmask/challenge/", map[string]string{"X-Protected-Mode": "pow_then_captcha"}); got != settings.RateChallengePoWThenCaptcha {
		t.Errorf("header pow_then_captcha: want pow_then_captcha, got %s", got)
	}

	// Forward-auth axis: no header; the _orig query resolves the rule + mode.
	if got := servedChModeReq(t, h, "/unmask/challenge/?_orig=%2Fpow-gate%2Fdeep%3Fq%3D1", nil); got != settings.RateChallengePoWOnly {
		t.Errorf("_orig pow-gate: want pow_only, got %s", got)
	}
	if got := servedChModeReq(t, h, "/unmask/challenge/?_orig=%2Fmembers%2F", nil); got != settings.RateChallengeCaptchaOnly {
		t.Errorf("_orig members: want captcha_only, got %s", got)
	}
	if got := servedChModeReq(t, h, "/unmask/challenge/?_orig=%2Fvault%2Fkeys", nil); got != settings.RateChallengePoWThenCaptcha {
		t.Errorf("_orig vault: want pow_then_captcha, got %s", got)
	}

	// An _orig outside every protected rule stays on the Operating-mode path
	// (known browser + pass -> the base rate-limit default), not "protected".
	base := s.RateLimit.Default.ResolvedChallengeMode()
	if got := servedChModeReq(t, h, "/unmask/challenge/?_orig=%2Fplain%2F", nil); got != base {
		t.Errorf("_orig plain: want base %s, got %s", base, got)
	}
}
