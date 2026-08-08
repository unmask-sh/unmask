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
		s.Rebind.SetRebindMode("asn")
	})
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=challenge", nil)
	req.SetPathValue("tab", "challenge")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`name="roaming_cap"`,
		`name="rebind_mode" value="any"`,
		`name="rebind_mode" value="asn"`,
		`name="rebind_mode" value="strict"`,
		`value="asn" checked`, // the saved mode is the checked radio
		`</html>`,             // page must not truncate mid-template
	} {
		if !strings.Contains(body, want) {
			t.Errorf("challenge tab Roaming render missing %q", want)
		}
	}
	// asn is selected but the test handler has no ASN db, so the "degrades to
	// any" warning must show, linking to the network tab to install one.
	if !strings.Contains(body, `/admin/settings/network/`) {
		t.Errorf("asn mode without an ASN db must render the degrade warning (network-tab link)")
	}
}
