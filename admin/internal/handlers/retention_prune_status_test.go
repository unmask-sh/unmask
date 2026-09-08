package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The retention tab shows the prune's last run and warns when it is not
// keeping up -- the state that used to be visible only in the daemon log.
func TestRetentionTabShowsPruneStatusAndBacklog(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) { s.EventsRetentionDays = 7 })
	// A row far past the window, and a run that ended on its budget without
	// ever completing.
	if _, err := h.DB.Exec(`INSERT INTO unmask_event (site, host, ip_address, phase, date_created) VALUES ('', '', X'0a000001', 'serve', ?)`,
		time.Now().UTC().Add(-20*24*time.Hour).Format("2006-01-02 15:04:05.000")); err != nil {
		t.Fatal(err)
	}
	if err := h.DB.SaveMaintState(context.Background(), db.MaintEventsPrune, db.PruneRecord{
		StartedAt: time.Now().Unix() - 600, EndedAt: time.Now().Unix(), Retention: 7, Deleted: 120000, Chunks: 60, BusyRetries: 2, Seconds: 2700, Err: "budget reached",
	}); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=retention", nil)
	req.SetPathValue("tab", "retention")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{`id="retention-prune-status"`, "120000", "budget reached", `id="retention-prune-warn"`, "db-prune"} {
		if !strings.Contains(body, want) {
			t.Errorf("retention tab missing %q", want)
		}
	}

	// A prune that completed just now, no backlog: status line, no banner.
	if _, err := h.DB.Exec(`DELETE FROM unmask_event`); err != nil {
		t.Fatal(err)
	}
	if err := h.DB.SaveMaintState(context.Background(), db.MaintEventsPrune, db.PruneRecord{
		StartedAt: time.Now().Unix() - 30, EndedAt: time.Now().Unix(), CompletedAt: time.Now().Unix(), Retention: 7, Deleted: 800, Chunks: 3, Seconds: 4,
	}); err != nil {
		t.Fatal(err)
	}
	rr = httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	body = rr.Body.String()
	if !strings.Contains(body, `id="retention-prune-status"`) || strings.Contains(body, `id="retention-prune-warn"`) {
		t.Errorf("a completed prune shows its status and no warning")
	}
}
