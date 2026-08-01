package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A geo rule reads as "JP Japan (日本)" plus its action / rate pills.  All of
// that lives inside one .pat cell, and the shared rule-list confirm button
// used to overwrite the cell with the raw input -- which dropped the country
// name AND both pills until the next page load.  The row markup and the
// datalist the repair reads from both have to be present.
func TestGeoRowCarriesNameAndPills(t *testing.T) {
	var base settings.Settings
	base.Server.BasePath = "/unmask"
	base.Nginx.Geo.Rules = []settings.GeoRule{{Country: "JP", Label: "home", Action: "skip", Enabled: true}}
	h := newTestHandler(t)
	h.SetSettings(base)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=geo", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("geo tab: %d", rr.Code)
	}
	body := rr.Body.String()

	i := strings.Index(body, `data-orig-pat="JP"`)
	if i < 0 {
		t.Fatal("the JP rule row did not render")
	}
	// Slice to the end of this row's markup: the next row starts at the next
	// data-orig-pat, and the list is followed by the add button.
	row := body[i:]
	if end := strings.Index(row, "rule-add-bottom"); end > 0 {
		row = row[:end]
	}
	for _, want := range []string{"cc-code", "Japan", "geo-act-pill", "asn-rate-pill"} {
		if !strings.Contains(row, want) {
			t.Errorf("the geo row is missing %q", want)
		}
	}
	// The name comes from the datalist on re-render, so the input must point
	// at it and the list must carry labels.
	if !strings.Contains(body, `list="geo-country-datalist"`) {
		t.Error("the country input is not bound to the datalist the row re-render reads")
	}
	if !strings.Contains(body, "JP — Japan") {
		t.Error("the datalist option carries no label to recover the name from")
	}
}
