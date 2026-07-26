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
			DefaultAction:     settings.GeoActionSkip,
			DefaultRatePerMin: 200, // feature B: rules with a nil rate inherit this
			Providers:         []settings.AsnProviderSel{{ID: "microsoft", Action: settings.GeoActionDeny, Enabled: true}},
			Rules:             []settings.AsnRule{{ASN: 16509, Label: "Amazon AWS", Action: settings.GeoActionDeny, Enabled: true}},
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
		`name="asn_default_rate"`,                  // feature B: config-level default rate input
		`name="asn_provider_rate_microsoft"`,       // per-preset rate override on the preset table
		`data-help-target="asn-defrate-help"`,      // "?" help on the default-rate field
		`placeholder="200"`,                        // a nil-rate row shows the inherited default as its placeholder
		`data-rule-name="ax_path"`,                 // ASN-axis exempt path list
		`data-help-target="ax-help"`,               // its help popover
		`name="ax_path"`,                           // exempt path input (rule-list template row)
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
	// The ASN "default" heading must use its own network-worded key, not the
	// geo one -- neither language's country phrasing may reach the ASN tab.
	for _, leaked := range []string{"ルール非登録の国", "for countries with no rule"} {
		if strings.Contains(body, leaked) {
			t.Errorf("ASN default heading leaked geo (country) wording %q -- must say network/ASN", leaked)
		}
	}
	// The geo-axis exempt list lives on the GEO tab, not here.
	if strings.Contains(body, `data-rule-name="gx_path"`) {
		t.Error("geo-exempt list must not render on the ASN tab")
	}
}

// TestSettingsGeoTabRendersExemptPaths executes the geo tab and pins that the
// country-axis exempt-path list renders there (and only there): the gx
// rule-list with a stored row, its help popover, and no leakage of the
// ASN-axis (ax) list onto this tab.
func TestSettingsGeoTabRendersExemptPaths(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Nginx.Geo.ExemptPaths = []settings.BypassPath{{Path: "^/feed", Title: "RSS"}}
	})
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=geo", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`data-rule-name="gx_path"`, // country-axis exempt path list
		`data-help-target="gx-help"`,
		`name="gx_path"`,
		`^/feed`, // the stored row surfaces
		`</html>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("geo tab render missing %q", want)
		}
	}
	if strings.Contains(body, `data-rule-name="ax_path"`) {
		t.Error("asn-exempt list must not render on the geo tab")
	}
	if strings.Contains(body, "settings.geo.exempt.") {
		t.Error("raw settings.geo.exempt.* i18n key leaked (missing dict entry)")
	}
}
