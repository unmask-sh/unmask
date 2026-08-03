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

// Naming the axis must not decide whether the roaming rebind runs.  The rebind
// gate reads "no forced reason", so filling force_reason in before it turned a
// silent re-bind for a visitor who had merely changed IP into a fresh
// challenge -- e2e 21 and 42 caught it as expected=200 actual=403.
func TestUATargetAttributionRunsAfterTheRebindGate(t *testing.T) {
	b, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	gate := strings.Index(src, "// Silent roaming rebind")
	attrib := strings.Index(src, `forceReason = "ua_target"`)
	if gate < 0 || attrib < 0 {
		t.Fatal("cannot locate the rebind gate or the ua_target attribution")
	}
	if attrib < gate {
		t.Error("ua_target is attributed before the rebind gate, so a roamed visitor is re-challenged instead of re-bound")
	}
	// And it stays the lowest-priority page-side axis.
	for _, higher := range []string{`forceReason = "header"`, `forceReason = "stale"`} {
		if i := strings.Index(src, higher); i > attrib {
			t.Errorf("%s is attributed after ua_target, so the more specific axis loses", higher)
		}
	}
}
