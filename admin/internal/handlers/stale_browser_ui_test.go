package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestSettingsUAFilterTabRendersStaleCard executes the UA-filter tab (the
// stale-browser card's home — it is a UA-string rule) so an execute-time break
// in the card — a missing data field like .StaleBrowserBaseline, a bad pipeline
// — is caught in `go test` (TestAdminTemplatesParse only PARSES; the docker e2e
// never renders this tab).
func TestSettingsUAFilterTabRendersStaleCard(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Global.StaleBrowserChallenge = true
		s.Global.StaleBrowserLag = 12
		// CurrentChromeMajor left 0 on purpose: the field is an optional
		// override and the card must render the built-in baseline placeholder.
	})
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=ua-filter", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`name="stale_browser_challenge"`,                  // the toggle
		`name="current_chrome_major"`,                     // the optional override field
		`name="current_firefox_major"`,                    // the Firefox twin
		`name="stale_browser_lag" `,                       // the lag field
		`name="stale_browser_action"`,                     // the action select
		strconv.Itoa(settings.DefaultCurrentChromeMajor),  // baseline placeholder
		strconv.Itoa(settings.DefaultCurrentFirefoxMajor), // firefox baseline placeholder
		`</html>`, // no truncation
	} {
		if !strings.Contains(body, want) {
			t.Errorf("ua-filter tab render missing %q", want)
		}
	}
	// The toggle is on -> it must render checked.
	if !strings.Contains(body, `name="stale_browser_challenge" value="1" checked`) {
		t.Error("stale toggle on must render checked")
	}
	// The operator's lag (12) must be the selected value, not the default.
	if !strings.Contains(body, `value="12"`) {
		t.Error("configured lag must render in the field")
	}
	// CurrentChromeMajor unset -> the AUTOMATIC radio is selected and the
	// manual input is disabled (so a form submit round-trips the unset state).
	if !strings.Contains(body, `name="stale_chrome_src" value="auto" checked`) {
		t.Error("unset chrome major must select the automatic radio")
	}
	if !strings.Contains(body, `id="stale-chrome-manual" name="current_chrome_major" min="1" max="999" value="" disabled`) {
		t.Error("unset chrome major must disable the manual input")
	}
}

// TestSettingsUAFilterStaleManualRadio: an operator-pinned current major flips
// the row to the MANUAL radio with the input enabled and carrying the value.
func TestSettingsUAFilterStaleManualRadio(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Global.StaleBrowserChallenge = true
		s.Global.CurrentChromeMajor = 148
	})
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=ua-filter", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, `name="stale_chrome_src" value="manual" checked`) {
		t.Error("pinned chrome major must select the manual radio")
	}
	if !strings.Contains(body, `name="current_chrome_major" min="1" max="999" value="148" `) ||
		strings.Contains(body, `value="148" disabled`) {
		t.Error("pinned chrome major must render enabled with the value")
	}
	// Firefox stays automatic.
	if !strings.Contains(body, `name="stale_firefox_src" value="auto" checked`) {
		t.Error("firefox must stay on the automatic radio")
	}
}
