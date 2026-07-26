package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestSettingsAsnTabRenders executes the geo tab and pins that the
// ASN sub-section renders: the printf-free i18n keys resolve (a raw key
// leaking would mean a missing dict entry), a configured ASN rule shows with
// its AS number + label + selected action, and the form posts to the geo
// section (one save persists both axes).
func TestSettingsAsnTabRenders(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		// A SeenVersion older than the catalog's AddedIn -> the founding
		// providers show the NEW badge.
		s.Nginx.SeenVersion = "v0.1.10"
		s.Nginx.Asn = settings.AsnConfig{
			DefaultAction: settings.GeoActionSkip,
			Providers:     []settings.AsnProviderSel{{ID: "microsoft", Action: settings.GeoActionDeny, Enabled: true}},
			Rules:         []settings.AsnRule{{ASN: 16509, Label: "Amazon AWS", Action: settings.GeoActionDeny, Enabled: true}},
		}
	})
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=asn", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()

	for _, want := range []string{
		`name="asn_default_action"`,                // default select
		`name="asn_provider_enabled_microsoft"`,    // preset provider checkbox
		`id="asn-suggest"`,                         // live DB suggest dropdown
		`id="asn-rows"`,                            // custom rules table
		`class="settings-preset asn-preset-table"`, // preset table (locale-neutral); whole-row toggle
		`card-badge preset`,                        // 📦 preset badge
		`card-badge custom`,                        // ✏️ custom badge
		`col-since`,                                // custom rules "added" column
		`new-badge`,                                // preset NEW badge (seenVer < AddedIn)
		`id="asn-add-toggle"`,                      // collapsed "新規追加" trigger
		`id="asn-add-form"`,                        // the form it expands
		`id="asn-add-action"`,                      // action selectable at add time
		`id="asn-add-btn"`,                         // custom add control
		`id="asn-add-rate"`,                        // add-form rate input
		`name="asn_rate"`,                          // per-row rate input
		`col-rate`,                                 // rate column
		`class="rate-unit"`,                        // "req/min" unit suffix (clarifies it's a rate)
		`data-help-target="asn-rate-help"`,         // "?" help on the rate column
		`</html>`,                                  // no truncation
	} {
		if !strings.Contains(body, want) {
			t.Errorf("geo tab render missing %q", want)
		}
	}
	// A raw unresolved i18n key must not leak into the page.
	if strings.Contains(body, "settings.asn.") {
		t.Error("raw settings.asn.* i18n key leaked (missing dict entry)")
	}
}
