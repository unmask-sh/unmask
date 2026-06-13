package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The challenge tab carries the global Roaming section (cap input + 3-way rebind
// mode radios).  A missing data key or a template error would silently truncate
// the page at HTTP 200, so assert the controls render AND the document closes.
func TestSettingsChallengeTabRoaming(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Rebind.MaxEntries = 12
		s.Rebind.SetRebindMode("any")
	})
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=challenge", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`name="roaming_cap"`,
		`name="rebind_mode" value="asn"`,
		`name="rebind_mode" value="strict"`,
		`name="rebind_mode" value="any"`,
		`</html>`, // page must not truncate mid-template
	} {
		if !strings.Contains(body, want) {
			t.Errorf("challenge tab Roaming render missing %q", want)
		}
	}
	// the saved mode ("any") is the checked radio.
	if !strings.Contains(body, `value="any" checked`) {
		t.Errorf("saved rebind mode (any) must be the checked radio")
	}
}
