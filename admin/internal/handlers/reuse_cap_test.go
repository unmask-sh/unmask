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
		if rr.Code != http.StatusTooManyRequests {
			t.Fatalf("status %d, want 429 (every answer here comes off the rate path)", rr.Code)
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
	// With the per-pass tier in force a solved CAPTCHA is a pass like any:
	// its holder on the rate route is over a budget of the cap's (the pass's
	// own, or the address's five-fold one) and gets the cap's answer -- a
	// CAPTCHA again, whose solve is a new pass with a budget of its own, or
	// here the deny page.  A pass that lists the solve first and an older PoW
	// entry after it (what the CAPTCHA issuer leaves in the browser) reads as
	// the solve.
	t.Run("a solved CAPTCHA", func(t *testing.T) {
		h, powBV := newH(t, true, "deny")
		secret := h.cfg().Secret.BVSecret
		solved := cookies.IssueValue(secret, ip, host, "captcha")
		for name, bv := range map[string]string{
			"the solve alone":         solved,
			"the solve over the pass": cookies.AppendEntry(powBV, solved, 16),
		} {
			if b := jsonBody(t, serve(h, bv, false)); b["reason"] != "reuse_limit" || b["error"] != "rate_limited" {
				t.Errorf("%s: %v, want the cap's answer (rate_limited / reuse_limit)", name, b)
			}
		}
		if b := jsonBody(t, serve(h, powBV, false)); b["reason"] != "reuse_limit" {
			t.Errorf("the PoW pass: reason %v, want reuse_limit", b["reason"])
		}
	})
	// While the upgrade review holds the per-pass tier (the cap acknowledged,
	// the release that added the tier not), the address zone is the only one
	// counting, and the CAPTCHA it serves is the way out for a person behind
	// a busy address: the pass it gives is not the cap's to count, so a
	// request that reaches the rate route carrying one is a plain rate-limit
	// hit, as before the tier.
	t.Run("a solved CAPTCHA while the per-pass tier is held", func(t *testing.T) {
		h, powBV := newH(t, true, "deny")
		cfg := *h.cfg()
		cfg.Nginx.UpgradeReviewPolicy = settings.UpgradeReviewReview
		cfg.Nginx.EnforcementReviewedVersion = settings.ReuseAddedIn
		h.SetSettings(cfg)
		secret := cfg.Secret.BVSecret
		solved := cookies.IssueValue(secret, ip, host, "captcha")
		for name, bv := range map[string]string{
			"the solve alone":         solved,
			"the solve over the pass": cookies.AppendEntry(powBV, solved, 16),
		} {
			if b := jsonBody(t, serve(h, bv, false)); b["reason"] != "rate_limit" || b["error"] != "challenge_required" {
				t.Errorf("%s: %v, want the plain rate-limit challenge, not the cap", name, b)
			}
		}
		// The PoW pass on its own is still the cap's.
		if b := jsonBody(t, serve(h, powBV, false)); b["reason"] != "reuse_limit" {
			t.Errorf("the PoW pass: reason %v, want reuse_limit", b["reason"])
		}
	})
	// A custom rule with a rate limit of its own counts everyone it matches,
	// pass holders included, and the conf names the matched rule on the rate
	// route.  Under such a rule a pass holder over "some zone" cannot be told
	// from one over the rule's, so the rule's own answer is served, as under
	// an ASN / country rate rule; a rule without a rate limit has no zone,
	// and the hit is the cap's.
	t.Run("a throttled custom rule", func(t *testing.T) {
		h, bv := newH(t, true, "deny")
		cfg := *h.cfg()
		cfg.Nginx.CustomRules = []settings.CustomRule{
			{ID: "crthrottle", RatePerMin: 10},
			{ID: "crplain"},
		}
		h.SetSettings(cfg)
		ruled := func(id string) *httptest.ResponseRecorder {
			r := httptest.NewRequest(http.MethodGet, "https://"+host+"/unmask/_rl/api/items", nil)
			r.Host = host
			r.Header.Set("X-Real-IP", ip)
			r.Header.Set("Sec-Fetch-Dest", "empty")
			r.Header.Set("Sec-Fetch-Mode", "cors")
			r.Header.Set("X-Unmask-Rule", id)
			r.AddCookie(&http.Cookie{Name: "_bv", Value: bv})
			rr := httptest.NewRecorder()
			h.ServeChallengeOrJSON(rr, r)
			return rr
		}
		if b := jsonBody(t, ruled("crthrottle")); b["reason"] != "rate_limit" || b["error"] != "challenge_required" {
			t.Errorf("under a throttled rule: %v, want the rule's plain rate-limit answer", b)
		}
		for _, id := range []string{"crplain", "crunknown", ""} {
			if b := jsonBody(t, ruled(id)); b["reason"] != "reuse_limit" {
				t.Errorf("rule %q (no rate limit of its own): reason %v, want reuse_limit", id, b["reason"])
			}
		}
	})
	t.Run("deny", func(t *testing.T) {
		h, bv := newH(t, true, "deny")
		if b := jsonBody(t, serve(h, bv, false)); b["error"] != "rate_limited" || b["reason"] != "reuse_limit" {
			t.Errorf("deny over the cap: %v, want rate_limited / reuse_limit", b)
		}
		if page := serve(h, bv, true); page.Code != http.StatusTooManyRequests || strings.Contains(page.Body.String(), "captcha_only") {
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
		"reuse_enabled": {"1"}, "reuse_pass_per_hour": {"600"}, "reuse_per_day": {"20000"}, "reuse_burst": {"3000"}, "reuse_action": {"deny"},
	})); err != nil {
		t.Fatal(err)
	}
	if ru != (settings.ReuseLimitConfig{PerDay: 20000, Burst: 3000, PassPerHour: 600, Action: "deny"}) {
		t.Errorf("stored %+v", ru)
	}
	if err := applyReuseForm(&ru, form(url.Values{
		"reuse_per_day": {"20000"}, "reuse_burst": {"3000"}, "reuse_action": {"deny"},
	})); err != nil || !ru.Disabled || ru.PerDay != 20000 {
		t.Errorf("switched off: %+v, %v -- want the tuning kept", ru, err)
	}
	for _, bad := range []url.Values{
		{"reuse_per_day": {"1000"}, "reuse_action": {"captcha_only"}},     // below nginx's 1 a minute
		{"reuse_pass_per_hour": {"59"}, "reuse_action": {"captcha_only"}}, // the same floor for one pass
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
