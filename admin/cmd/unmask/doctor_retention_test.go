package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func retentionTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "d.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	return d
}

func seedEvent(t *testing.T, d *db.DB, when time.Time) {
	t.Helper()
	if _, err := d.Exec(`INSERT INTO unmask_event (site,host,ip_address,user_agent,phase,date_created) VALUES ('','',X'0a000001','ua','serve',?)`,
		when.UTC().Format("2006-01-02 15:04:05.000")); err != nil {
		t.Fatal(err)
	}
}

// doctor's retention check: the oldest row against the window, and the
// prune's own record.  A prune that is not keeping up used to be visible only
// in the daemon log.
func TestCheckEventsRetention(t *testing.T) {
	run := func(d *db.DB, retention int) (oks, warns []string) {
		checkEventsRetention(settings.Settings{EventsRetentionDays: retention}, d,
			func(_, m string) { oks = append(oks, m) }, func(_, m string) { warns = append(warns, m) })
		return
	}

	d := retentionTestDB(t)
	seedEvent(t, d, time.Now().Add(-3*24*time.Hour))
	if oks, warns := run(d, 7); len(warns) != 0 || len(oks) != 1 {
		t.Errorf("inside the window: oks=%v warns=%v", oks, warns)
	}
	if oks, warns := run(d, 0); len(warns) != 0 || len(oks) != 1 || !strings.Contains(oks[0], "unlimited") {
		t.Errorf("retention 0: oks=%v warns=%v", oks, warns)
	}

	// Backlog: the oldest row is 20 days old against a 7-day window.
	seedEvent(t, d, time.Now().Add(-20*24*time.Hour))
	oks, warns := run(d, 7)
	if len(warns) != 1 || !strings.Contains(warns[0], "20 days old") || !strings.Contains(warns[0], "db-prune") {
		t.Errorf("backlog must WARN naming the age and the fix, got oks=%v warns=%v", oks, warns)
	}

	// A prune that keeps failing before ever completing.
	d2 := retentionTestDB(t)
	seedEvent(t, d2, time.Now().Add(-time.Hour))
	if err := d2.SaveMaintState(context.Background(), db.MaintEventsPrune, db.PruneRecord{StartedAt: time.Now().Unix() - 60, EndedAt: time.Now().Unix(), Retention: 7, Deleted: 50000, Chunks: 1, Err: "database is locked (5) (SQLITE_BUSY)"}); err != nil {
		t.Fatal(err)
	}
	oks, warns = run(d2, 7)
	if len(warns) != 1 || !strings.Contains(warns[0], "has not completed") || !strings.Contains(warns[0], "SQLITE_BUSY") {
		t.Errorf("a failing prune must WARN with its error, got oks=%v warns=%v", oks, warns)
	}

	// A prune that completed recently reads OK with its summary.
	if err := d2.SaveMaintState(context.Background(), db.MaintEventsPrune, db.PruneRecord{StartedAt: time.Now().Unix() - 60, EndedAt: time.Now().Unix(), CompletedAt: time.Now().Unix(), Retention: 7, Deleted: 1200, Chunks: 4}); err != nil {
		t.Fatal(err)
	}
	oks, warns = run(d2, 7)
	if len(warns) != 0 || len(oks) != 1 || !strings.Contains(oks[0], "1200 rows in 4 chunks") {
		t.Errorf("a recent completion reads OK, got oks=%v warns=%v", oks, warns)
	}

	// A completion older than two days is stale.
	if err := d2.SaveMaintState(context.Background(), db.MaintEventsPrune, db.PruneRecord{StartedAt: time.Now().Unix() - 3*86400, CompletedAt: time.Now().Unix() - 3*86400, Retention: 7}); err != nil {
		t.Fatal(err)
	}
	if _, warns = run(d2, 7); len(warns) != 1 || !strings.Contains(warns[0], "last completed") {
		t.Errorf("a stale completion must WARN, got %v", warns)
	}
}
