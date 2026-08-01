package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Not a test: dumps the REAL rate-limit tab for browser / jsdom verification.
// Enabled only when UNMASK_DUMP_RL points at a file, so `go test ./...`
// ignores it.
func TestDumpRateLimitHTMLForMeasurement(t *testing.T) {
	out := os.Getenv("UNMASK_DUMP_RL")
	if out == "" {
		t.Skip("set UNMASK_DUMP_RL=<path> to dump the rate-limit tab")
	}
	var base settings.Settings
	base.Server.BasePath = "/unmask"
	base.Nginx.ProtectedPaths.EnabledPresets = []string{"unmask"}
	base.RateLimit.Zones = []settings.RateZone{
		{Name: "api_strict", PathPatterns: []string{"/api/"}, RequestsPerMin: 30, ChallengeMode: "pow_only"},
		{Name: "admin_deny", PathPatterns: []string{"/unmask/admin/x/"}, RequestsPerMin: 5, ChallengeMode: "deny"},
		{Name: "ja4_flood", Key: "ja4", RequestsPerMin: 600, Burst: 100},
	}
	h := newTestHandler(t)
	h.SetSettings(base)
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=rate-limit", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("rate-limit tab: %d", rr.Code)
	}
	if err := os.WriteFile(out, rr.Body.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d bytes to %s", rr.Body.Len(), out)
}
