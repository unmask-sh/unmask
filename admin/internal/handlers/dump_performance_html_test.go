package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// Not a test: dumps the REAL performance tab for jsdom verification.
func TestDumpPerformanceHTMLForMeasurement(t *testing.T) {
	out := os.Getenv("UNMASK_DUMP_PERF")
	if out == "" {
		t.Skip("set UNMASK_DUMP_PERF=<path> to dump the performance tab")
	}
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=performance", nil)
	r.SetPathValue("tab", "performance")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("performance tab: %d", rr.Code)
	}
	if err := os.WriteFile(out, rr.Body.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d bytes to %s", rr.Body.Len(), out)
}
