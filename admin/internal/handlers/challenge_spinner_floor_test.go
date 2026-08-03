package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// The spinner floor exists so an operator inspecting the challenge visuals can
// see the spinner instead of having it flash past.  It is a /unmask/test/ knob:
// production shows the real solve time, which on modern hardware is 30-100ms.
//
// It shipped the other way round.  The HTML carried 1500 while the handler
// searched for 0, so the substitution never fired: every visitor was held for
// an extra 1.5 seconds, and the test page could not slow the spinner down at
// all.  Fleet median load-to-pass was 1,508ms against a 1,500ms floor, with
// 55% of the visitors who gave up leaving inside that window.
func TestSpinnerFloorIsATestKnobNotAProductionDelay(t *testing.T) {
	// Point the packaged-asset lookup at nothing so the test reads the embedded
	// page, not whatever this machine happens to have installed.
	orig := challengeHTMLPackagePath
	challengeHTMLPackagePath = t.TempDir() + "/absent.html"
	t.Cleanup(func() { challengeHTMLPackagePath = orig })

	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	get := func(q string) int {
		rr := httptest.NewRecorder()
		h.ForcePoW(rr, httptest.NewRequest(http.MethodGet, "/unmask/test/force-pow"+q, nil))
		m := regexp.MustCompile(`pow_min_display_ms: /\*__POW_MIN_DISPLAY_MS__\*/(\d+)`).FindStringSubmatch(rr.Body.String())
		if m == nil {
			t.Fatalf("%s: no pow_min_display_ms in the page (%d)", q, rr.Code)
		}
		n, _ := strconv.Atoi(m[1])
		return n
	}
	if n := get(""); n != 0 {
		t.Errorf("production page holds the spinner for %dms; it should show the real solve time", n)
	}
	if n := get("?_pow_display=1500"); n != 1500 {
		t.Errorf("the test override produced %dms, want 1500 -- the placeholder no longer matches", n)
	}
}

// The pass path adds no artificial wait either.  A floor of 800ms used to pad
// a fast solve out before the redirect; the beat it was protecting does not
// need it, because location.replace keeps the verified state painted until the
// destination renders.  Nothing else depended on it: the beacon goes out via
// sendBeacon and the /bvj request sets keepalive so that the redirect winning
// the race is the expected case, not a loss.
func TestPassRedirectHasNoPaddedWait(t *testing.T) {
	b, err := os.ReadFile("../../assets/static/challenge.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	if regexp.MustCompile(`Math\.max\(\s*\d{3,}\s*-\s*elapsed`).MatchString(js) {
		t.Error("the redirect is padded out to a minimum again; a fast solve should redirect at once")
	}
	if !strings.Contains(js, "setTimeout(function(){passAndRedirect();},0)") {
		t.Error("the pass path no longer redirects on the next tick")
	}
}
