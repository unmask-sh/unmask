package handlers

import (
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// ChallengeTargets.DefaultAction is the black-list chain (ua-filter tab:
// "chain used when a black-list UA match triggers a challenge").  These tests
// pin its scope: it fires only when the UA actually matches a challenge
// target (extra / preset), and a plain no-match challenge keeps the
// Operating-mode pick.  Regression: ServeChallenge applied it to every
// forceReason="none" challenge, so with default_action=pow_then_captcha a
// current-stable Chrome that failed the transparent PoW was walked into the
// CAPTCHA leg meant for black-listed UAs only.

var chModeMarkerRE = regexp.MustCompile(`/\*__CHMODE__\*/"([a-z_]+)"`)

func servedChMode(t *testing.T, h *Handler, ua string) string {
	t.Helper()
	req := httptest.NewRequest("GET", "/unmask/challenge/", nil)
	req.Header.Set("User-Agent", ua)
	w := httptest.NewRecorder()
	h.ServeChallenge(w, req)
	m := chModeMarkerRE.FindStringSubmatch(w.Body.String())
	if m == nil {
		t.Fatalf("__CHMODE__ marker not found in challenge body (status=%d)", w.Code)
	}
	return m[1]
}

const uaCurrentChrome = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"

func TestServeChallengeBlacklistDefaultActionScope(t *testing.T) {
	h := newTestHandler(t)
	s := *h.cfg()
	s.Global.KnownBrowserAction = settings.RateChallengePoWOnly
	s.Nginx.ChallengeTargets.Extra = []string{"BadBot"}
	s.Nginx.ChallengeTargets.DefaultAction = settings.RateChallengePoWThenCaptcha
	h.SetSettings(s)

	// A plain known browser keeps the Operating-mode pick; the black-list
	// chain must not leak onto it.
	if got := servedChMode(t, h, uaCurrentChrome); got != settings.RateChallengePoWOnly {
		t.Errorf("plain known browser: chmode=%q, want pow_only (Operating-mode pick)", got)
	}
	// A black-list extra hit takes DefaultAction.
	if got := servedChMode(t, h, "BadBot/1.0 (+https://example.com/bot)"); got != settings.RateChallengePoWThenCaptcha {
		t.Errorf("black-list extra hit: chmode=%q, want pow_then_captcha (DefaultAction)", got)
	}

	// Challenge-everything is the Operating-mode buckets' job, and stays under
	// their chain: hardening the posture there must not hand plain browsers to
	// the black-list chain.
	s.Global.KnownBrowserAction = settings.RateChallengeCaptchaOnly
	h.SetSettings(s)
	if got := servedChMode(t, h, uaCurrentChrome); got != settings.RateChallengeCaptchaOnly {
		t.Errorf("bucket action: chmode=%q, want captcha_only (Operating-mode pick, not DefaultAction)", got)
	}
}

// TestUaDecideBlacklistDefaultAction: the forward-auth UA axis honours the
// same DefaultAction for a black-list hit (parity with native ServeChallenge);
// unset keeps the historical fixed captcha_only.
func TestUaDecideBlacklistDefaultAction(t *testing.T) {
	bot := "BadBot/1.0 (+https://example.com/bot)"

	var cfg settings.Settings
	cfg.Global.KnownBrowserAction = "pass"
	cfg.Nginx.ChallengeTargets.Extra = []string{"BadBot"}

	// Unset: historical captcha_only.
	d, ok := uaDecide(bot, "", cfg, nil)
	if !ok || d.sev != sevCaptchaOnly || d.chMode != settings.RateChallengeCaptchaOnly {
		t.Fatalf("unset DefaultAction: sev=%v chMode=%q ok=%v, want captcha_only", d.sev, d.chMode, ok)
	}

	// Operator picked a chain: honour it.
	cfg.Nginx.ChallengeTargets.DefaultAction = settings.RateChallengePoWThenCaptcha
	d, ok = uaDecide(bot, "", cfg, nil)
	if !ok || d.sev != sevPoWThenCaptcha || d.chMode != settings.RateChallengePoWThenCaptcha {
		t.Fatalf("pow_then_captcha DefaultAction: sev=%v chMode=%q ok=%v, want pow_then_captcha", d.sev, d.chMode, ok)
	}

	// Deny is a hard block (chMode empty by the chModeFromSeverity contract).
	cfg.Nginx.ChallengeTargets.DefaultAction = settings.RateChallengeDeny
	d, ok = uaDecide(bot, "", cfg, nil)
	if !ok || d.sev != sevDeny || d.chMode != "" {
		t.Fatalf("deny DefaultAction: sev=%v chMode=%q ok=%v, want deny with empty chMode", d.sev, d.chMode, ok)
	}

	// A UA that matches nothing never takes the black-list chain.
	cfg.Nginx.ChallengeTargets.DefaultAction = settings.RateChallengePoWThenCaptcha
	if d, _ := uaDecide(uaCurrentChrome, "", cfg, nil); d.sev != sevPass {
		t.Errorf("plain known browser: sev=%v want pass (KnownBrowserAction, not the black-list chain)", d.sev)
	}
}
