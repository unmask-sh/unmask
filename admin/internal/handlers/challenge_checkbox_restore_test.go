package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The CAPTCHA page's "I'm not a robot" box must reach the visitor unticked,
// whatever the browser remembers.  Form state is restored on a reload and on a
// Back navigation, and a restored tick fires no change event -- so the page sat
// there with the box already checked and did nothing until the visitor
// unticked and reticked it (reported from tool1-sg, 2026-09-09).  Two things
// keep that from happening, and a page that lost either is the bug again:
// autocomplete="off" on the input, and a reset before the handler is wired.
func TestCaptchaCheckboxIsNeverPreTicked(t *testing.T) {
	// Read the embedded assets, not whatever this machine has installed.
	origHTML, origJS := challengeHTMLPackagePath, challengeJSPackagePath
	dir := t.TempDir()
	challengeHTMLPackagePath = dir + "/absent.html"
	challengeJSPackagePath = dir + "/absent.js"
	t.Cleanup(func() { challengeHTMLPackagePath, challengeJSPackagePath = origHTML, origJS })

	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	rr := httptest.NewRecorder()
	h.ForceCaptcha(rr, httptest.NewRequest(http.MethodGet, "/unmask/test/force-captcha", nil))
	// The challenge page is served as the challenge status (403), not 200.
	if rr.Code != http.StatusForbidden && rr.Code != http.StatusOK {
		t.Fatalf("force-captcha: status %d", rr.Code)
	}
	page := rr.Body.String()

	// The input itself.
	idAt := strings.Index(page, `id="notRobot"`)
	if idAt < 0 {
		t.Fatal("the built-in checkbox is not on the page")
	}
	open := strings.LastIndex(page[:idAt], "<input")
	if open < 0 {
		t.Fatal("the checkbox id is not on an <input>")
	}
	tag := page[open:]
	tag = tag[:strings.Index(tag, ">")+1]
	if !strings.Contains(tag, `autocomplete="off"`) {
		t.Errorf("the checkbox must opt out of form-state restoration, got %s", tag)
	}
	if strings.Contains(tag, "checked") {
		t.Errorf("the checkbox must never render pre-ticked, got %s", tag)
	}

	// The script the visitor runs (inlined into the page) clears the box after
	// looking it up and before wiring the change handler, so a tick the
	// browser restored cannot sit there inert.
	wire := strings.Index(page, `cb.addEventListener('change'`)
	if wire < 0 {
		t.Fatal("the checkbox change handler is not in the served script")
	}
	before := page[:wire]
	lookup := strings.LastIndex(before, `getElementById('notRobot')`)
	reset := strings.LastIndex(before, "cb.checked = false;")
	if lookup < 0 {
		t.Fatal("the script does not look the checkbox up before wiring it")
	}
	if reset < 0 || reset < lookup {
		t.Error("the script must clear a restored tick between looking the checkbox up and wiring the handler")
	}
}
