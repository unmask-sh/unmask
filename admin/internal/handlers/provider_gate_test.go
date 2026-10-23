package handlers

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/captcha"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// With a 3rd-party CAPTCHA configured, /verify used to run the external
// check only when a provider_token was PRESENT: a client that left it out fell
// through to the builtin behavioral and math paths, the ones the operator had
// picked a provider to replace.  Now a configured provider is the only way in.
func TestVerifyJSONRequiresTheConfiguredProvider(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Challenge.Default.CaptchaProvider = settings.Captcha{
			Provider:           "turnstile",
			TurnstileSiteKey:   "0xSITE",
			TurnstileSecretKey: "0xSECRET",
		}
	})
	ct := captcha.IssueToken(h.cfg().Secret.CaptchaSecretBase)
	sig := map[string]any{"keys": 1, "clickAt": 1500, "windowSize": []int{1280, 720}, "screenSize": []int{1920, 1080}}
	res, out := postMath(t, h, "198.51.100.21", map[string]any{"token": "x", "ct": ct, "sig": sig})
	if res.StatusCode != http.StatusForbidden || fmt.Sprint(out["error"]) != "provider_required" {
		t.Fatalf("behavioral payload without provider_token: status=%d out=%v", res.StatusCode, out)
	}
	if bv := bvKindFrom(t, res); bv != "" {
		t.Fatalf("a _bv was issued on the refused path: %q", bv)
	}
	answer, tok, ct2 := mathAnswerFor(t, h, "198.51.100.22")
	res, out = postMath(t, h, "198.51.100.22", map[string]any{"answer": answer, "token": tok, "ct": ct2, "iv": 3, "dt": 2000})
	if res.StatusCode != http.StatusForbidden || fmt.Sprint(out["error"]) != "provider_required" {
		t.Fatalf("math answer without provider_token: status=%d out=%v", res.StatusCode, out)
	}
}

// A provider whose site key is unset never reaches the page (captchaInjectJSON
// hands the page "null" and it runs the builtin check), so the server falls
// back to builtin for the same configuration rather than locking everyone out.
func TestVerifyJSONProviderWithoutSiteKeyIsBuiltin(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Challenge.Default.CaptchaProvider = settings.Captcha{Provider: "hcaptcha", HCaptchaSecretKey: "0xSECRET"}
	})
	answer, tok, ct := mathAnswerFor(t, h, "198.51.100.23")
	res, out := postMath(t, h, "198.51.100.23", map[string]any{"answer": answer, "token": tok, "ct": ct, "iv": 3, "dt": 2000})
	if res.StatusCode != http.StatusOK || fmt.Sprint(out["ok"]) != "1" {
		t.Fatalf("builtin fallback refused: status=%d out=%v", res.StatusCode, out)
	}
}
