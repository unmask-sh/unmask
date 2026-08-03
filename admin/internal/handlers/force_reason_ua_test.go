package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
)

// A challenge raised by the operator's own UA rule has to say so.  Native
// nginx fires it off $is_challenge_target and forwards no header, so the serve
// event recorded force_reason=none -- the hunt log showed the rule working and
// could not say that a rule was involved, let alone which axis.  The admin
// already resolves the match (it picks the chain from it), so the reason is
// there to be recorded.
func TestBlackListChallengeNamesItsAxis(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	cur.Nginx.ChallengeTargets.Extra = []string{"X11; Linux x86_64"}
	cur.Nginx.ChallengeTargets.ExtraAction = []string{"captcha_only"}
	h.SetSettings(cur)

	const farmUA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
	const plainUA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"

	serve := func(ua string, hdr map[string]string) string {
		req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/?u=%2F", nil)
		req.Header.Set("User-Agent", ua)
		for k, v := range hdr {
			req.Header.Set(k, v)
		}
		rr := httptest.NewRecorder()
		h.ServeChallenge(rr, req)
		m := regexp.MustCompile(`/\*__CAPTCHA_FORCE__\*/"([a-z_]*)"`).FindStringSubmatch(rr.Body.String())
		if m == nil {
			t.Fatalf("no force reason in the served page (status %d)", rr.Code)
		}
		return m[1]
	}

	if got := serve(farmUA, nil); got != "ua_target" {
		t.Errorf("a black-listed UA served force_reason=%q, want ua_target", got)
	}
	if got := serve(plainUA, nil); got == "ua_target" {
		t.Error("a UA that matches nothing was attributed to the black list")
	}
	// A more specific axis keeps its own reason: the black list is the
	// fallback attribution, not an override.
	if got := serve(farmUA, map[string]string{"X-Banned": "1"}); got != "banned" {
		t.Errorf("a banned client on a black-listed UA reported %q, want banned", got)
	}
	if got := serve(farmUA, map[string]string{"X-Honeypot-Hit": "1"}); got != "honeypot" {
		t.Errorf("a honeypot trip on a black-listed UA reported %q, want honeypot", got)
	}
}

// The reason is only useful if it can be filtered for.
func TestHuntOffersTheUATargetReason(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/hunt.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `<option value="ua_target"`) {
		t.Error("the hunt force-reason filter has no ua_target option, so the rows cannot be found")
	}
}
