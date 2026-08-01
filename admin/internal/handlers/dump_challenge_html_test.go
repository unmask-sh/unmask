package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// Not a test: dumps the REAL challenge tab for browser / jsdom verification.
func TestDumpChallengeHTMLForMeasurement(t *testing.T) {
	out := os.Getenv("UNMASK_DUMP_CH")
	if out == "" {
		t.Skip("set UNMASK_DUMP_CH=<path> to dump the challenge tab")
	}
	h := newTestHandler(t)
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=challenge", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("challenge tab: %d", rr.Code)
	}
	if err := os.WriteFile(out, rr.Body.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d bytes to %s", rr.Body.Len(), out)
}
