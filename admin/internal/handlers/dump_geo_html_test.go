package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Not a test: dumps the REAL geo tab for jsdom verification.
func TestDumpGeoHTMLForMeasurement(t *testing.T) {
	out := os.Getenv("UNMASK_DUMP_GEO")
	if out == "" {
		t.Skip("set UNMASK_DUMP_GEO=<path> to dump the geo tab")
	}
	var base settings.Settings
	base.Server.BasePath = "/unmask"
	base.Nginx.Geo.Rules = []settings.GeoRule{
		{Country: "JP", Label: "home", Action: "skip", Enabled: true},
	}
	h := newTestHandler(t)
	h.SetSettings(base)
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=geo", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("geo tab: %d", rr.Code)
	}
	if err := os.WriteFile(out, rr.Body.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d bytes to %s", rr.Body.Len(), out)
}
