package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A request nginx sent down the rate route (/_rl/...) because a custom
// rule's rate limit tripped carries the rule's over-limit answer on
// X-Unmask-Rule-Rate-Action: deny is the rate deny, a chain is served in
// place of the rule's on-match action, and without one the rate limit's
// own mode applies -- the on-match action (X-Unmask-Rule-Action) never
// decides the rate path.
func TestCustomRuleRateActionOnTheRateRoute(t *testing.T) {
	const host = "example.test"
	h := newTestHandler(t)
	serve := func(onMatch, over string, page bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, "https://"+host+"/unmask/_rl/search?q=1", nil)
		r.Host = host
		r.Header.Set("X-Real-IP", "203.0.113.7")
		r.Header.Set("X-Unmask-Rule", "cr1")
		r.Header.Set("X-Unmask-Rule-Action", onMatch)
		r.Header.Set("X-Unmask-Rule-Rate-Action", over)
		if page {
			r.Header.Set("Sec-Fetch-Dest", "document")
		} else {
			r.Header.Set("Sec-Fetch-Dest", "empty")
			r.Header.Set("Sec-Fetch-Mode", "cors")
		}
		rr := httptest.NewRecorder()
		h.ServeChallengeOrJSON(rr, r)
		return rr
	}
	// deny over the limit: the rate deny, for a page and for an API client.
	if rr := serve("captcha_only", "deny", false); rr.Code != http.StatusTooManyRequests {
		t.Errorf("deny over the limit (API): status %d, want 429", rr.Code)
	} else {
		var b map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &b); err != nil || b["error"] != "rate_limited" {
			t.Errorf("deny over the limit (API): %s", rr.Body.String())
		}
	}
	// The page names its chain as challenge_mode: /*__CHMODE__*/"<chain>".
	mode := func(body string) string {
		const mark = `/*__CHMODE__*/"`
		i := strings.Index(body, mark)
		if i < 0 {
			return ""
		}
		rest := body[i+len(mark):]
		return rest[:strings.Index(rest, `"`)]
	}
	if rr := serve("captcha_only", "deny", true); rr.Code != http.StatusTooManyRequests || mode(rr.Body.String()) != "" {
		t.Errorf("deny over the limit (page): status %d, challenge chain %q (want the deny page)", rr.Code, mode(rr.Body.String()))
	}
	// A chain over the limit is served, not the on-match action.
	if body := serve("deny", "pow_only", true).Body.String(); mode(body) != "pow_only" || !strings.Contains(body, `"rate_limit"`) {
		t.Errorf("a chain over the limit: chain %q, want pow_only on the rate-limit challenge", mode(body))
	}
	// No answer of its own: the rate limit's own mode -- what a rate-limit
	// hit with no rule at all gets -- and the on-match action does not leak
	// in, neither deny nor its chain.
	base := mode(serve("", "", true).Body.String())
	if base == "" || base == "pow_only" {
		t.Fatalf("the rate limit's own chain reads as %q; the test needs a challenge chain other than pow_only", base)
	}
	rr := serve("deny", "", true)
	if rr.Code != http.StatusTooManyRequests || mode(rr.Body.String()) != base {
		t.Errorf("no over-limit answer with deny on a match: status %d, chain %q, want the rate limit's %q", rr.Code, mode(rr.Body.String()), base)
	}
	if m := mode(serve("pow_only", "", true).Body.String()); m != base {
		t.Errorf("no over-limit answer with pow_only on a match: chain %q, want the rate limit's %q", m, base)
	}
}
