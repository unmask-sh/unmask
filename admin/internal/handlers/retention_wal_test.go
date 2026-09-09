package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The retention tab shows the write-ahead log next to the database size and
// warns once the log is past the point where checkpoints evidently do not
// complete -- the state that made a 10 GB file on 2026-09-08 visible only in
// a directory listing.
func TestRetentionTabShowsWALSize(t *testing.T) {
	h := newTestHandler(t)
	// A write leaves frames in the log.
	if _, err := h.DB.Exec(`INSERT INTO unmask_event (site, host, ip_address, phase, date_created) VALUES ('', '', X'0a000001', 'serve', datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	if h.DB.WALSize() == 0 {
		t.Fatal("the test database keeps no write-ahead log")
	}
	get := func() string {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=retention", nil)
		req.SetPathValue("tab", "retention")
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("want 200, got %d", rr.Code)
		}
		return rr.Body.String()
	}
	body := get()
	if !strings.Contains(body, "WAL <strong>") {
		t.Error("the tab must show the write-ahead log size next to the database size")
	}
	if strings.Contains(body, `id="retention-wal-warn"`) {
		t.Error("a small log is no warning")
	}

	orig := retentionWALLarge
	retentionWALLarge = 1
	t.Cleanup(func() { retentionWALLarge = orig })
	body = get()
	if !strings.Contains(body, `id="retention-wal-warn"`) || !strings.Contains(body, "checkpoint") {
		t.Error("a large log must show the banner and say that checkpoints are not completing")
	}
}
