package handlers

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestSettingsGlobalTabRendersStaleCard executes the Operating-mode (global)
// tab so an execute-time break in the stale-browser card — a missing data
// field like .StaleBrowserBaseline, a bad pipeline — is caught in `go test`
// (TestAdminTemplatesParse only PARSES; the docker e2e never renders this tab).
func TestSettingsGlobalTabRendersStaleCard(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Global.StaleBrowserChallenge = true
		s.Global.StaleBrowserLag = 12
		// CurrentChromeMajor left 0 on purpose: the field is an optional
		// override and the card must render the built-in baseline placeholder.
	})
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=global", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`name="global_stale_browser_challenge"`,          // the toggle
		`name="global_current_chrome_major"`,             // the optional override field
		`name="global_stale_browser_lag" `,               // the lag field
		`name="global_stale_browser_action"`,             // the action select
		strconv.Itoa(settings.DefaultCurrentChromeMajor), // baseline placeholder
		`</html>`, // no truncation
	} {
		if !strings.Contains(body, want) {
			t.Errorf("global tab render missing %q", want)
		}
	}
	// The toggle is on -> it must render checked.
	if !strings.Contains(body, `name="global_stale_browser_challenge" value="1" checked`) {
		t.Error("stale toggle on must render checked")
	}
	// The operator's lag (12) must be the selected value, not the default.
	if !strings.Contains(body, `value="12"`) {
		t.Error("configured lag must render in the field")
	}
}
