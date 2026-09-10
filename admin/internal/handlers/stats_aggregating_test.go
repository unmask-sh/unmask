package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
)

// On a table past the raw-scan ceiling, with no aggregate pass done, the
// 30-day serve cards are not attempted: the page says "aggregating" at once
// instead of running a scan to its deadline and then calling it a failure.
func TestStatsAggregatingShortCircuit(t *testing.T) {
	h := newTestHandler(t)
	when := time.Now().UTC().Add(-time.Hour).Format("2006-01-02 15:04:05.000")
	for i := 0; i < 3; i++ {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event (site, host, ip_address, phase, date_created) VALUES ('', '', X'0a000001', 'serve', ?)`, when); err != nil {
			t.Fatal(err)
		}
	}
	orig := dashboard.RawScanCeiling
	dashboard.RawScanCeiling = 1 // three rows is "too many" for this test
	dashboard.ResetHourlyAggReadyForTest()
	t.Cleanup(func() { dashboard.RawScanCeiling = orig; dashboard.ResetHourlyAggReadyForTest() })

	get := func() (string, time.Duration) {
		t0 := time.Now()
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/stats/default/?range=24h", nil)
		req.SetPathValue("site", "default")
		rr := httptest.NewRecorder()
		h.AdminStats(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("stats page status %d", rr.Code)
		}
		return rr.Body.String(), time.Since(t0)
	}
	body, took := get()
	if !strings.Contains(body, `class="muted card-aggregating"`) || !strings.Contains(body, "集計中") {
		t.Error("the serve card must say it is aggregating")
	}
	for _, name := range []string{"DailyServeByKind", "CountriesByServe"} {
		if strings.Contains(body, name) {
			t.Errorf("%s must not be listed as failed: it was not attempted", name)
		}
	}
	if took > 5*time.Second {
		t.Errorf("the short-circuit must not wait on a scan, took %v", took)
	}

	// Below the ceiling the scan runs as before and the page shows data, no
	// aggregating note.
	dashboard.RawScanCeiling = 1_000_000
	body, _ = get()
	if strings.Contains(body, `card-aggregating`) {
		t.Error("a small table is scanned, not told to wait")
	}
}
