package dashboard

import (
	"context"
	"testing"
	"time"
)

// Before a pass there is no cursor and the whole table is backlog; after one
// the cursor sits on the newest event and the status reads caught up.  This
// is what doctor reports from outside the daemon, where the in-process
// readiness flag cannot be seen.
func TestReadAggregateStatusTracksThePass(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	when := time.Now().UTC().Add(-30 * time.Minute).Format("2006-01-02 15:04:05.000")
	for i := 0; i < 5; i++ {
		if _, err := d.Exec(`INSERT INTO unmask_event (site,host,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','',X'0a000001','ua','','ok',0,'serve',0,0,'','','{}',?)`, when); err != nil {
			t.Fatal(err)
		}
	}
	a, err := ReadAggregateStatus(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if a.HasCursor || a.CaughtUp() || a.Backlog != 5 || a.Events != 5 {
		t.Errorf("before a pass: %+v (want no cursor, backlog 5, not caught up)", a)
	}

	defer hourlyReady.Store(false)
	if err := AggregateHourly(ctx, d, nil); err != nil {
		t.Fatal(err)
	}
	a, err = ReadAggregateStatus(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if !a.HasCursor || !a.CaughtUp() || a.Backlog != 0 || a.Cursor != a.MaxID || a.UpdatedAt.IsZero() {
		t.Errorf("after a pass: %+v (want cursor at max id, backlog 0, caught up, updated_at set)", a)
	}

	// New rows after the pass are backlog again until the next tick folds them.
	for i := 0; i < 3; i++ {
		if _, err := d.Exec(`INSERT INTO unmask_event (site,host,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','',X'0a000002','ua','','ok',0,'serve',0,0,'','','{}',?)`, when); err != nil {
			t.Fatal(err)
		}
	}
	a, _ = ReadAggregateStatus(ctx, d)
	if a.Backlog != 3 || !a.CaughtUp() {
		t.Errorf("three new rows: backlog=%d caughtUp=%v (a backlog inside one chunk is the normal lag)", a.Backlog, a.CaughtUp())
	}
}

// The raw 30-day fallback is hopeless only when the aggregate is not ready
// AND the table is past the ceiling; a ready aggregate or a small table is
// never hopeless.
func TestRawScanHopeless(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	when := time.Now().UTC().Add(-time.Hour).Format("2006-01-02 15:04:05.000")
	for i := 0; i < 10; i++ {
		if _, err := d.Exec(`INSERT INTO unmask_event (site,host,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','',X'0a000001','ua','','ok',0,'serve',0,0,'','','{}',?)`, when); err != nil {
			t.Fatal(err)
		}
	}
	hourlyReady.Store(false)
	orig := RawScanCeiling
	t.Cleanup(func() { RawScanCeiling = orig; hourlyReady.Store(false) })

	RawScanCeiling = 1_000_000
	if h, n := RawScanHopeless(ctx, d); h || n != 10 {
		t.Errorf("a small table is never hopeless: hopeless=%v rows=%d", h, n)
	}
	RawScanCeiling = 5
	if h, _ := RawScanHopeless(ctx, d); !h {
		t.Error("past the ceiling with no aggregate pass, the raw scan is hopeless")
	}
	hourlyReady.Store(true)
	if h, _ := RawScanHopeless(ctx, d); h {
		t.Error("a ready aggregate is never hopeless: the cards read the rollup, not the raw table")
	}
	// A cursor at the newest row and no pass in this process (a restart):
	// the cards read the rollup up to the cursor and scan nothing raw.
	hourlyReady.Store(false)
	if _, err := d.Exec(`INSERT INTO unmask_aggregate_state (name, last_id, updated_at) VALUES (?, (SELECT MAX(id) FROM unmask_event), CURRENT_TIMESTAMP)`, hourlyState); err != nil {
		t.Fatal(err)
	}
	if h, n := RawScanHopeless(ctx, d); h || n != 0 {
		t.Errorf("nothing left to fold is never hopeless: hopeless=%v remainder=%d", h, n)
	}
}

// Every aggregate table's oldest row is measured against the shared window;
// a row the prune should have removed is reported with its age, and the
// prune clears the finding.
func TestAuditAggregateWindowsFlagsAnUnprunedTable(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	nowMin := time.Now().Unix() / 60
	if _, err := d.Exec(`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt) VALUES (?,?,?,?)`,
		nowMin-1440*100, "", "total", 1); err != nil { // 100 days old
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt) VALUES (?,?,?,?)`,
		nowMin-5, "", "total", 1); err != nil {
		t.Fatal(err)
	}
	ws, err := AuditAggregateWindows(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	var cm *AggregateWindow
	for i := range ws {
		if ws[i].Table == "unmask_cookie_minute" {
			cm = &ws[i]
		}
	}
	if cm == nil || !cm.Over || cm.OldestAge < 99*24*time.Hour {
		t.Fatalf("a 100-day-old row must be reported as over the window: %+v", cm)
	}
	for _, w := range ws {
		if w.Table != "unmask_cookie_minute" && w.Over {
			t.Errorf("%s reported over the window on a fresh database", w.Table)
		}
	}
	if err := PruneHourly(ctx, d); err != nil {
		t.Fatal(err)
	}
	ws, _ = AuditAggregateWindows(ctx, d)
	for _, w := range ws {
		if w.Over {
			t.Errorf("after the prune nothing may be over the window: %+v", w)
		}
	}
}
