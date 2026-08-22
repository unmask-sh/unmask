package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The display floor began as a /unmask/test/ inspection knob, shipped inverted
// (the HTML carried 1500 while the handler searched for 0, holding every
// visitor 1.5s), was removed outright -- and the removal exposed the opposite
// failure: a modern device solves in ~150ms, and the page became a flash the
// visitor notices but cannot read.  It is a product setting now
// (ChallengeValues.MinDisplayMS, default 800): the page holds long enough to
// parse, the residual shows the verified state, and an operator who wants the
// raw redirect sets 0.  These tests pin the substitution chain for the whole
// display-style family.
func TestChallengeDisplaySubstitutions(t *testing.T) {
	// Point the packaged-asset lookup at nothing so the test reads the embedded
	// page, not whatever this machine happens to have installed.
	orig := challengeHTMLPackagePath
	challengeHTMLPackagePath = t.TempDir() + "/absent.html"
	t.Cleanup(func() { challengeHTMLPackagePath = orig })

	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	get := func(q string) (page string) {
		rr := httptest.NewRecorder()
		h.ForcePoW(rr, httptest.NewRequest(http.MethodGet, "/unmask/test/force-pow"+q, nil))
		return rr.Body.String()
	}
	minDisp := func(page string) int {
		m := regexp.MustCompile(`pow_min_display_ms: /\*__POW_MIN_DISPLAY_MS__\*/(\d+)`).FindStringSubmatch(page)
		if m == nil {
			t.Fatal("no pow_min_display_ms in the page")
		}
		n, _ := strconv.Atoi(m[1])
		return n
	}
	style := func(page string) string {
		m := regexp.MustCompile(`data-unmask-style', /\*__CHALLENGE_STYLE__\*/"(\w+)"`).FindStringSubmatch(page)
		if m == nil {
			t.Fatal("no pre-paint style stamp in the page")
		}
		return m[1]
	}

	// Out of the box: visible, held to the 800ms default.
	page := get("")
	if n := minDisp(page); n != 800 {
		t.Errorf("default min display = %dms, want 800", n)
	}
	if st := style(page); st != "visible" {
		t.Errorf("default style = %q, want visible", st)
	}

	// The /unmask/test/ inspection knob still overrides the floor.
	if n := minDisp(get("?_pow_display=1500")); n != 1500 {
		t.Errorf("the test override produced %dms, want 1500 -- the placeholder no longer matches", n)
	}

	// An explicit 0 is "no floor", not "follow the default": the two states
	// must survive the pointer round-trip.
	zero := 0
	s = h.snapshotSettings()
	s.Challenge.Default.MinDisplayMS = &zero
	h.SetSettings(s)
	if n := minDisp(get("")); n != 0 {
		t.Errorf("explicit min_display_ms=0 produced %dms, want 0", n)
	}

	// Invisible style: the pre-paint stamp flips and the timing knobs ride
	// along; a preview keeps rendering visible -- the operator opened the page
	// to look at it.
	s = h.snapshotSettings()
	s.Challenge.Default.DisplayStyle = settings.ChallengeDisplayInvisible
	h.SetSettings(s)
	page = get("")
	if st := style(page); st != "invisible" {
		t.Errorf("style = %q, want invisible", st)
	}
	if !strings.Contains(page, `invisible_reveal_ms: /*__INVISIBLE_REVEAL_MS__*/1200`) {
		t.Error("the reveal delay was not substituted (default 1200 expected)")
	}
	if !strings.Contains(page, `reveal_fade_ms: /*__REVEAL_FADE_MS__*/200`) {
		t.Error("the fade duration was not substituted (default 200 expected)")
	}
	if st := style(get("?_preview=1")); st != "visible" {
		t.Errorf("preview style = %q, want visible (the operator is inspecting the page)", st)
	}
}

// The pass path's hold is bounded and honest: the CAPTCHA leg branches before
// it (a screen that needs hands is never delayed), and the beacon reports the
// solve time captured BEFORE the hold -- the original 1.5s floor re-measured
// after its own sleep, so every solve read as a plausible 1.5s and the floor
// hid itself in the metrics for weeks.
func TestPassRedirectHoldIsHonest(t *testing.T) {
	b, err := os.ReadFile("../../assets/static/challenge.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)
	if !strings.Contains(js, "setTimeout(function(){passAndRedirect();},0)") {
		t.Error("the pass path no longer redirects on the next tick")
	}
	// The WAIT must run after the pass cookie is written, never before.  It
	// used to sit at the solve, ahead of the cookie and the beacon, so a
	// visitor who closed the tab during a hold WE imposed lost the solve they
	// had already paid for: no _bv, no bv_pow_only, an abandon beacon instead.
	// Split at the hour it shipped, one production node's abandonment fell well
	// below its own baseline without the hold and rose several times above it
	// with the hold -- big enough to hide a real improvement underneath it.
	paint := strings.Index(js, "var holdUntil")
	cookie := strings.Index(js, "document.cookie='_bv='")
	wait := strings.Index(js, "holdUntil - Date.now()")
	beacon := strings.Index(js, "_bcDebug('bv_pow_only'")
	for name, i := range map[string]int{"holdUntil": paint, "cookie write": cookie, "wait": wait, "beacon": beacon} {
		if i < 0 {
			t.Fatalf("cannot locate %s", name)
		}
	}
	if wait < cookie || wait < beacon {
		t.Error("the display hold waits before the pass cookie / beacon; a visitor who leaves during it loses a solve they already made")
	}
	if paint > cookie {
		t.Error("the completed-state paint runs after the cookie write; it belongs at the moment the solve lands")
	}
	// The hold must not re-measure elapsed after its sleep.
	holdEnd := strings.Index(js[paint:], "document.cookie='_bv='")
	seg := js[paint : paint+holdEnd]
	if strings.Contains(seg, "elapsed = Date.now()") {
		t.Error("the hold re-measures elapsed after sleeping, so the floor leaks into pow_elapsed_ms again")
	}
	// The paint must not stop the spinner, and must not swap the wording.
	if strings.Contains(seg, `getElementById('spinner')`) {
		t.Error("the hold touches the spinner; it must keep turning through the hold and the navigation that follows")
	}
	for _, w := range []string{"t.verified", "t.connecting"} {
		if strings.Contains(seg, w) {
			t.Errorf("the hold swaps the message to %s; the line should stay as it is", w)
		}
	}
	// The bar finishes rather than dissolving from wherever it reached.
	if !strings.Contains(seg, "style.width='100%'") {
		t.Error("the hold does not fill the progress bar; a fast solve leaves it nearly empty, which reads as a reset")
	}
	if strings.Contains(seg, "style.opacity='0'") {
		t.Error("the hold fades the progress bar out; a full bar should stay until the page navigates away")
	}
	// The message box keeps its first-rendered height so nothing reflows.
	if !strings.Contains(js, "style.minHeight") {
		t.Error("the message box height is not pinned, so a shorter line reflows the page under the visitor")
	}
	if pin := strings.Index(js, "style.minHeight"); pin < 0 || pin > strings.Index(js, "textContent=t.verify")+400 {
		if init := strings.Index(js, "textContent=t.verify"); init < 0 || pin < init {
			t.Error("the height floor is not taken from the first rendered line")
		}
	}
	// And the CAPTCHA chain branches before the hold runs.
	chain := strings.Index(js, "if (chainPoWThenCaptcha)")
	if chain < 0 {
		t.Fatal("cannot locate the chain branch")
	}
	if chain > paint {
		t.Error("the display floor runs before the CAPTCHA branch, so the operator's floor delays a screen that needs interaction")
	}
}
