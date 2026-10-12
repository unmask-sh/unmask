package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"
)

// A challenge one of the operator's custom rules raised has to say so.  The
// conf decides the request by the rule and names its chain on the rewrite
// (X-Unmask-Rule-Action) but forwards no axis, so the serve recorded
// force_reason=none and the dashboard's detections-by-reason card filed the
// rule's work under the site's default posture.  Only the record changes: the
// chain is still the rule's, and a reason an axis gave keeps winning.
func TestCustomRuleChallengeNamesTheRule(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	h.SetSettings(cur)

	const plainUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
	serve := func(hdr map[string]string) (reason, chain string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/?u=%2F", nil)
		req.Header.Set("User-Agent", plainUA)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		h.ServeChallenge(rr, req)
		body := rr.Body.String()
		m := regexp.MustCompile(`/\*__CAPTCHA_FORCE__\*/"([a-z_]*)"`).FindStringSubmatch(body)
		c := regexp.MustCompile(`/\*__CHMODE__\*/"([a-z_]*)"`).FindStringSubmatch(body)
		p := regexp.MustCompile(`<!--probe=ON force_reason=([a-z_]*)-->`).FindStringSubmatch(body)
		if m == nil || c == nil || p == nil {
			t.Fatalf("no force reason / chain / probe in the served page (status %d)", rr.Code)
		}
		if m[1] != p[1] {
			t.Errorf("the page beacons %q but the probe says %q", m[1], p[1])
		}
		return m[1], c[1]
	}

	reason, chain := serve(map[string]string{"X-Unmask-Rule": "cr1a2b", "X-Unmask-Rule-Action": "captcha_only"})
	if reason != "custom_rule" {
		t.Errorf("a custom rule's challenge recorded force_reason=%q, want custom_rule", reason)
	}
	if chain != "captcha_only" {
		t.Errorf("chain = %q, want the rule's captcha_only", chain)
	}

	// No rule: the default posture, as before.
	if reason, chain := serve(nil); reason != "none" || chain != "pow_only" {
		t.Errorf("no rule: reason=%q chain=%q, want none / pow_only", reason, chain)
	}
	// A rule that only watches (or a deny, which never reaches the challenge)
	// decided nothing here.
	for _, a := range []string{"monitor", "deny", "bogus"} {
		if reason, _ := serve(map[string]string{"X-Unmask-Rule-Action": a}); reason != "none" {
			t.Errorf("rule action %q: reason=%q, want none", a, reason)
		}
	}
	// A stronger reason keeps its attribution.
	if reason, _ := serve(map[string]string{"X-Banned": "1", "X-Unmask-Rule-Action": "captcha_only"}); reason != "banned" {
		t.Errorf("a banned client on a rule reported %q, want banned", reason)
	}
}
