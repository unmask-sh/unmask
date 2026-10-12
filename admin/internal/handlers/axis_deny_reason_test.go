package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The deny page is dispatched by nginx, which does not carry the reason with
// it, so the daemon re-derives which axis said no.  "some rule denied you" is
// not an answer on a page whose job is telling the operator which rule.
func TestAxisDenyNamesTheAxisThatFired(t *testing.T) {
	h := newTestHandler(t)

	req := func(ua string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/unmask/_deny/articles/", nil)
		r.Header.Set("User-Agent", ua)
		r.Header.Set("Sec-Fetch-Dest", "empty") // non-navigation: the reason lands in the JSON body
		r.RemoteAddr = "203.0.113.5:5000"
		return r
	}
	reasonOf := func(r *http.Request) string {
		w := httptest.NewRecorder()
		h.ServeAxisDeny(w, r)
		var out map[string]any
		_ = json.NewDecoder(w.Result().Body).Decode(&out)
		if v, ok := out["reason"].(string); ok {
			return v
		}
		return ""
	}

	// With no axis able to claim it (no geo/ASN database in a bare test
	// handler, no matching UA rule), the label stays generic rather than
	// guessing.
	if got := reasonOf(req("Mozilla/5.0")); got != "axis_deny" {
		t.Errorf("underivable deny should stay generic, got %q", got)
	}

	// A UA the operator put on the deny list names that axis.
	cur := *h.cfg()
	cur.Nginx.ChallengeTargets.Extra = []string{`BadScraper`}
	cur.Nginx.ChallengeTargets.ExtraAction = []string{settings.RateChallengeDeny}
	cur.Nginx.ChallengeTargets.ExtraDisabled = []bool{false}
	h.SetSettings(cur)
	if got := reasonOf(req("BadScraper/1.0")); got != "ua_deny" {
		t.Errorf("a UA deny row must be labelled ua_deny, got %q", got)
	}
	// And a visitor that rule does not match is not mislabelled as one.
	if got := reasonOf(req("Mozilla/5.0 (innocent)")); got == "ua_deny" {
		t.Error("a non-matching UA must not be labelled ua_deny")
	}

	// A custom rule set to deny: nginx names the rule on the rewrite, and the
	// record says custom_rule -- as a rule's challenge does -- not the generic
	// axis_deny.  A named axis that also denies keeps the label.
	rule := req("Mozilla/5.0 (innocent)")
	rule.Header.Set("X-Unmask-Rule", "cr1a2b")
	rule.Header.Set("X-Unmask-Rule-Action", settings.RateChallengeDeny)
	if got := reasonOf(rule); got != "custom_rule" {
		t.Errorf("a custom rule's deny must be labelled custom_rule, got %q", got)
	}
	both := req("BadScraper/1.0")
	both.Header.Set("X-Unmask-Rule", "cr1a2b")
	both.Header.Set("X-Unmask-Rule-Action", settings.RateChallengeDeny)
	if got := reasonOf(both); got != "ua_deny" {
		t.Errorf("the UA deny row comes first in the conf's composite, got %q", got)
	}
	// A rule whose action is a challenge does not reach the deny page; if a
	// header said so anyway, it is no deny reason.
	chal := req("Mozilla/5.0 (innocent)")
	chal.Header.Set("X-Unmask-Rule-Action", "captcha_only")
	if got := reasonOf(chal); got != "axis_deny" {
		t.Errorf("a challenge action is no deny reason, got %q", got)
	}
}
