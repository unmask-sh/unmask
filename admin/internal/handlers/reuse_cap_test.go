package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/cookies"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A request nginx sent down the rate route (/_rl/...) while it carries a valid
// pass is the reuse cap's: it gets the cap's action and is recorded as
// reuse_limit.  Without a pass, or with the cap off, it stays a plain
// rate-limit hit.
func TestReuseCapOnTheRateRoute(t *testing.T) {
	const host = "example.test"
	const ip = "203.0.113.7"
	newH := func(t *testing.T, enabled bool, action string) (*Handler, string) {
		h := newTestHandler(t)
		cfg := *h.cfg()
		cfg.Secret.BVSecret = "test-secret-for-the-reuse-cap"
		cfg.RateLimit.Reuse = settings.ReuseLimitConfig{Disabled: !enabled, Action: action}
		h.SetSettings(cfg)
		return h, cookies.IssueValue(cfg.Secret.BVSecret, ip, host, "pow")
	}
	serve := func(h *Handler, bv string, page bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "https://"+host+"/unmask/_rl/zipcode/code/1000001/", nil)
		r.Host = host
		r.Header.Set("X-Real-IP", ip)
		if page {
			r.Header.Set("Sec-Fetch-Dest", "document")
		} else {
			r.Header.Set("Sec-Fetch-Dest", "empty")
			r.Header.Set("Sec-Fetch-Mode", "cors")
		}
		if bv != "" {
			r.AddCookie(&http.Cookie{Name: "_bv", Value: bv})
		}
		rr := httptest.NewRecorder()
		h.ServeChallengeOrJSON(rr, r)
		return rr
	}
	jsonBody := func(t *testing.T, rr *httptest.ResponseRecorder) map[string]any {
		t.Helper()
		if rr.Code != http.StatusForbidden {
			t.Fatalf("status %d, want 403", rr.Code)
		}
		var b map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil {
			t.Fatalf("not JSON: %v\n%s", err, rr.Body.String())
		}
		return b
	}

	t.Run("captcha_only", func(t *testing.T) {
		h, bv := newH(t, true, "")
		if b := jsonBody(t, serve(h, bv, false)); b["reason"] != "reuse_limit" || b["error"] != "challenge_required" {
			t.Errorf("API client over the cap: %v, want challenge_required / reuse_limit", b)
		}
		page := serve(h, bv, true).Body.String()
		if !strings.Contains(page, `"reuse_limit"`) || !strings.Contains(page, `"captcha_only"`) {
			t.Error("a page over the cap must get a CAPTCHA-only challenge recorded as reuse_limit")
		}
		// No pass: the plain rate limit, as before the cap.
		if b := jsonBody(t, serve(h, "", false)); b["reason"] != "rate_limit" {
			t.Errorf("no pass: reason %v, want rate_limit", b["reason"])
		}
		// A pass for another address is no pass here.
		other := cookies.IssueValue(h.cfg().Secret.BVSecret, "198.51.100.9", host, "pow")
		if b := jsonBody(t, serve(h, other, false)); b["reason"] != "rate_limit" {
			t.Errorf("foreign pass: reason %v, want rate_limit", b["reason"])
		}
	})
	t.Run("deny", func(t *testing.T) {
		h, bv := newH(t, true, "deny")
		if b := jsonBody(t, serve(h, bv, false)); b["error"] != "rate_limited" || b["reason"] != "reuse_limit" {
			t.Errorf("deny over the cap: %v, want rate_limited / reuse_limit", b)
		}
		if page := serve(h, bv, true); page.Code != http.StatusForbidden || strings.Contains(page.Body.String(), "captcha_only") {
			t.Errorf("deny over the cap must serve the deny page, not a challenge (status %d)", page.Code)
		}
	})
	t.Run("off", func(t *testing.T) {
		h, bv := newH(t, false, "deny")
		if b := jsonBody(t, serve(h, bv, false)); b["reason"] != "rate_limit" || b["error"] != "challenge_required" {
			t.Errorf("cap off: %v, want the plain rate-limit challenge", b)
		}
	})
}

// The settings form: the card ships on, blank numbers keep the seeds and
// captcha_only is the default -- so an untouched card stores nothing; a
// switched-off cap keeps its tuning, out-of-range values are refused, and a
// form from before the cap leaves it alone.
func TestApplyReuseForm(t *testing.T) {
	form := func(vals url.Values) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=rate_limit", strings.NewReader(vals.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = r.ParseForm()
		return r
	}
	var ru settings.ReuseLimitConfig
	if err := applyReuseForm(&ru, form(url.Values{"reuse_enabled": {"1"}, "reuse_action": {"captcha_only"}})); err != nil || !ru.IsZero() {
		t.Fatalf("untouched card: %+v, %v -- want the zero value", ru, err)
	}
	if err := applyReuseForm(&ru, form(url.Values{
		"reuse_enabled": {"1"}, "reuse_per_day": {"20000"}, "reuse_burst": {"3000"}, "reuse_action": {"deny"},
	})); err != nil {
		t.Fatal(err)
	}
	if ru != (settings.ReuseLimitConfig{PerDay: 20000, Burst: 3000, Action: "deny"}) {
		t.Errorf("stored %+v", ru)
	}
	if err := applyReuseForm(&ru, form(url.Values{
		"reuse_per_day": {"20000"}, "reuse_burst": {"3000"}, "reuse_action": {"deny"},
	})); err != nil || !ru.Disabled || ru.PerDay != 20000 {
		t.Errorf("switched off: %+v, %v -- want the tuning kept", ru, err)
	}
	for _, bad := range []url.Values{
		{"reuse_per_day": {"1000"}, "reuse_action": {"captcha_only"}}, // below nginx's 1 a minute
		{"reuse_burst": {"0"}, "reuse_action": {"captcha_only"}},
		{"reuse_action": {"pow_only"}},
	} {
		before := ru
		if err := applyReuseForm(&ru, form(bad)); err == nil {
			t.Errorf("%v: want an error", bad)
		}
		if ru != before {
			t.Errorf("%v: a refused save changed the cap", bad)
		}
	}
	kept := ru
	if err := applyReuseForm(&ru, form(url.Values{"axis_ip_on": {"1"}})); err != nil || ru != kept {
		t.Errorf("a form without the card: %+v, %v -- want it left as stored", ru, err)
	}
}
