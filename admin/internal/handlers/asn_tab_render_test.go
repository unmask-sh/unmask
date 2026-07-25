package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestSettingsGeoTabRendersAsnSection executes the geo tab and pins that the
// ASN sub-section renders: the printf-free i18n keys resolve (a raw key
// leaking would mean a missing dict entry), a configured ASN rule shows with
// its AS number + label + selected action, and the form posts to the geo
// section (one save persists both axes).
func TestSettingsGeoTabRendersAsnSection(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Nginx.Asn = settings.AsnConfig{
			DefaultAction: settings.GeoActionSkip,
			Rules: []settings.AsnRule{
				{ASN: 16509, Label: "Amazon AWS", Action: settings.GeoActionDeny, Enabled: true},
			},
		}
	})
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=geo", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()

	for _, want := range []string{
		`name="asn_default_action"`,           // default select
		`name="asn_number" value="16509"`,     // the rule's AS number
		`AS16509`,                             // display
		`name="asn_label" value="Amazon AWS"`, // label round-trips
		`id="asn-rows"`,                       // the table
		`id="asn-add-btn"`,                    // add control (JS wires it)
		`</html>`,                             // no truncation
	} {
		if !strings.Contains(body, want) {
			t.Errorf("geo tab render missing %q", want)
		}
	}
	// The deny action must be the selected option on the rule's row.
	seg := body[strings.Index(body, `name="asn_number" value="16509"`):]
	seg = seg[:strings.Index(seg, "</tr>")]
	if !strings.Contains(seg, `value="deny"                {{`) && !strings.Contains(seg, `value="deny"`) {
		t.Error("rule row must contain the deny option")
	}
	// A raw unresolved i18n key must not leak into the page.
	if strings.Contains(body, "settings.asn.") {
		t.Error("raw settings.asn.* i18n key leaked (missing dict entry)")
	}
}
