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
	// The hold must not re-measure elapsed after its sleep.
	hold := strings.Index(js, "var shownFor")
	if hold < 0 {
		t.Fatal("cannot locate the display-floor hold")
	}
	// The hold block runs from its `shownFor` measurement to the sleep that
	// ends it.  Bounded by the code, not by a character count -- a fixed window
	// silently stopped covering the block as comments were added to it.
	holdEnd := strings.Index(js[hold:], "await new Promise")
	if holdEnd < 0 {
		t.Fatal("cannot find the end of the display-floor hold")
	}
	seg := js[hold : hold+holdEnd]
	if strings.Contains(seg, "elapsed = Date.now()") {
		t.Error("the hold re-measures elapsed after sleeping, so the floor leaks into pow_elapsed_ms again")
	}
	// The hold must not stop the spinner.  A PoW-only pass never shows the
	// CAPTCHA card, so the spinner passAndRedirect starts is invisible on that
	// path -- hiding this one left the visitor on a still frame from the solve
	// until the destination painted, which is the span a page transition most
	// needs to look busy.
	if strings.Contains(seg, `getElementById('spinner')`) {
		t.Error("the display hold touches the spinner; it must keep turning through the hold and the navigation that follows")
	}
	// The hold changes no words.  This screen never tells a visitor a check is
	// running, so announcing a verified result reads backwards; and advancing
	// to "connecting" was a change without a difference (near synonyms in
	// Japanese) that cost a real reflow.  The spinner carries the liveness.
	for _, s := range []string{"t.verified", "t.connecting"} {
		if strings.Contains(seg, s) {
			t.Errorf("the hold swaps the message to %s; the line should stay as it is and let the spinner carry the motion", s)
		}
	}

	// The progress bar finishes before it leaves.  powProgress() clamps the fill
	// at 95% while solving (so a long solve never sits at a frozen 100%), and
	// nothing wrote the final 100% -- the bar just faded from wherever it had
	// reached.  A 200ms solve barely moves it, so holding the page for 800ms
	// showed a nearly-empty bar dissolving, which reads as the progress
	// resetting rather than completing.
	if !strings.Contains(seg, "style.width='100%'") {
		t.Error("the hold does not fill the progress bar; a fast solve leaves it nearly empty, which reads as a reset")
	}
	// And it stays full.  Fading a completed bar takes the answer away just as
	// it is read, and adds motion to a screen that is now meant to hold still --
	// the navigation should be the next thing that happens, not the bar leaving.
	if strings.Contains(seg, "style.opacity='0'") {
		t.Error("the hold fades the progress bar out; a full bar should stay until the page navigates away")
	}

	// The message box keeps its first-rendered height regardless.  The body
	// centres vertically, so this element's height IS the page's layout: a
	// shorter line drops the box (measured: 48px -> 24px) and moves the spinner
	// and any operator logo with it, by up to 19px.  Nothing rewrites the line
	// today, but a locale's own wording, a long site name or a future line
	// would, and the hold is what gives a visitor time to watch it happen.
	// Measured at load, not hard-coded: the line count depends on the viewport
	// and on each locale.
	if !strings.Contains(js, "style.minHeight") {
		t.Error("the message box height is not pinned, so a shorter line reflows the page under the visitor")
	}
	pin := strings.Index(js, "style.minHeight")
	if init := strings.Index(js, "textContent=t.verify"); init < 0 || pin < init {
		t.Error("the height floor is not taken from the first rendered line")
	}
	// And the CAPTCHA chain branches before the hold runs.
	chain := strings.Index(js, "if (chainPoWThenCaptcha)")
	if chain < 0 {
		t.Fatal("cannot locate the chain branch")
	}
	if chain > hold {
		t.Error("the display floor runs before the CAPTCHA branch, so the operator's floor delays a screen that needs interaction")
	}
}
