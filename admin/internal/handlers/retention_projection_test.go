package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// projectRetentionDisk turns (size, oldest, retention, free) into the retention
// tab's forecast.  Pinned: linear steady-state math, the steady-state clamp
// once the span reaches the retention, the 90%-of-free fill warning, the
// infinite-retention horizon, and the not-enough-data guards.
func TestProjectRetentionDisk(t *testing.T) {
	const day = int64(86400)
	const gb = int64(1 << 30)
	now := int64(1_700_000_000)

	// alink-shaped: 8.7 GB after 8 days, retention 30, 78 GB free.
	p := projectRetentionDisk(87*gb/10, now-8*day, now, 30, 78*gb)
	if !p.Show {
		t.Fatal("8 days of history must be enough to project")
	}
	if got, want := p.Projected/gb, int64(32); got < want || got > want+2 {
		t.Errorf("30d projection = %d GB, want ~32-34 GB", got)
	}
	if p.FillRisk {
		t.Error("growth ~24 GB against 78 GB free must not warn")
	}

	// Same node, 25 GB free: remaining growth (~24 GB) > 90% of free -> warn.
	p = projectRetentionDisk(87*gb/10, now-8*day, now, 30, 25*gb)
	if !p.FillRisk || p.DaysToFull <= 0 {
		t.Errorf("growth ~24 GB against 25 GB free must warn with a days-to-full: %+v", p)
	}

	// Steady state reached (span >= retention): projected == current, no growth,
	// no warning even with little free space.
	p = projectRetentionDisk(8*gb, now-40*day, now, 30, 1*gb)
	if p.Projected != 8*gb {
		t.Errorf("steady state should project the current size, got %d", p.Projected)
	}
	if p.FillRisk {
		t.Error("steady state adds no growth; must not warn")
	}

	// Infinite retention: no steady size; warn only inside the horizon.
	p = projectRetentionDisk(1*gb, now-10*day, now, 0, 5*gb) // 100 MB/day -> ~50 days
	if p.Projected != 0 {
		t.Errorf("infinite retention has no steady-state size, got %d", p.Projected)
	}
	if !p.FillRisk || p.DaysToFull == 0 {
		t.Errorf("50 days to full is inside the %d-day horizon: %+v", fillRiskHorizonDays, p)
	}
	p = projectRetentionDisk(1*gb, now-10*day, now, 0, 100*gb) // ~1000 days
	if p.FillRisk {
		t.Error("1000 days of headroom must not warn")
	}

	// Guards: no size / no oldest / under a day of history -> hidden.
	for _, bad := range []retentionProjection{
		projectRetentionDisk(0, now-8*day, now, 30, gb),
		projectRetentionDisk(gb, 0, now, 30, gb),
		projectRetentionDisk(gb, now-day/2, now, 30, gb),
	} {
		if bad.Show {
			t.Errorf("insufficient data must hide the projection: %+v", bad)
		}
	}
}

// The retention tab executes the projection's VISIBLE branch (growth label,
// tf-formatted size label, free-disk figure) without a template error once the
// DB carries a day of history.  The sqlite test DB file is real, so disk free
// resolves via statfs on Linux and the whole line renders.
func TestRetentionTabRendersProjection(t *testing.T) {
	h := newTestHandler(t)
	// The test handler's settings carry no DB block (the DB size feeding the
	// projection comes from os.Stat on Settings.DB.SQLitePath).  Point it at a
	// real file with real bytes, and give the projection a retention to name.
	dbFile := filepath.Join(t.TempDir(), "proj.sqlite")
	if err := os.WriteFile(dbFile, make([]byte, 1<<20), 0o644); err != nil {
		t.Fatal(err)
	}
	s := *h.cfg()
	s.DB = settings.DB{Driver: "sqlite", SQLitePath: dbFile}
	s.EventsRetentionDays = 7
	h.SetSettings(s)
	// One event 3 days old -> span >= 1 day, so ProjShow flips on.
	old := time.Now().UTC().Add(-72 * time.Hour).Format("2006-01-02 15:04:05")
	if _, err := h.DB.Exec(`INSERT INTO unmask_event
		(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
		VALUES ('','','',0,?,'UA','','ok',0,'serve',0,0,'','','{}',?)`,
		[]byte{10, 0, 0, 9}, old); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/retention/", nil)
	req.SetPathValue("tab", "retention")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("retention tab: want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Growth") && !strings.Contains(body, "増加ペース") {
		t.Error("retention tab must render the growth line once a day of history exists")
	}
	// The tf-formatted label carries the configured retention days -- the piece
	// most likely to break (int arg through tf into safeHTML-free text).
	days := fmt.Sprintf("%d", h.cfg().EventsRetentionDays)
	if !strings.Contains(body, days+"-day retention") && !strings.Contains(body, "保持 "+days+" 日") {
		t.Errorf("retention tab must render the projected-size label with the %s-day setting", days)
	}
}
