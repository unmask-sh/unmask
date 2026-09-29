package main

import (
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/db"
)

// doctor's hourly-aggregate line: caught up is OK; behind, or no pass yet,
// WARNs and says what the stats page does meanwhile -- raw scans on a
// table the scan can finish, "aggregating" on one it cannot.
func TestAggregateStatusVerdict(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	orig := dashboard.RawScanCeiling
	dashboard.RawScanCeiling = 2_000_000
	t.Cleanup(func() { dashboard.RawScanCeiling = orig })

	if warn, msg := aggregateStatusVerdict(dashboard.AggregateStatus{}, now); warn || !strings.Contains(msg, "no events") {
		t.Errorf("empty install: warn=%v msg=%q", warn, msg)
	}
	small := dashboard.AggregateStatus{Events: 300_000, Backlog: 300_000, MaxID: 300_000}
	if warn, msg := aggregateStatusVerdict(small, now); !warn || !strings.Contains(msg, "no pass has completed") || !strings.Contains(msg, "read raw events") {
		t.Errorf("small table, no pass: warn=%v msg=%q", warn, msg)
	}
	large := dashboard.AggregateStatus{Events: 25_000_000, Backlog: 25_000_000, MaxID: 25_000_000}
	if warn, msg := aggregateStatusVerdict(large, now); !warn || !strings.Contains(msg, "'aggregating'") || !strings.Contains(msg, "25.0M") {
		t.Errorf("large table, no pass: warn=%v msg=%q", warn, msg)
	}
	behind := dashboard.AggregateStatus{HasCursor: true, Cursor: 100, MaxID: 100_100, Backlog: 100_000, Events: 100_100, UpdatedAt: now.Add(-3 * time.Hour)}
	if warn, msg := aggregateStatusVerdict(behind, now); !warn || !strings.Contains(msg, "100k events behind") || !strings.Contains(msg, "3h0m0s ago") {
		t.Errorf("behind: warn=%v msg=%q", warn, msg)
	}
	ok := dashboard.AggregateStatus{HasCursor: true, Cursor: 5000, MaxID: 5100, Backlog: 100, Events: 5100, UpdatedAt: now.Add(-time.Minute)}
	if warn, msg := aggregateStatusVerdict(ok, now); warn || !strings.Contains(msg, "caught up") {
		t.Errorf("caught up: warn=%v msg=%q", warn, msg)
	}
}

// doctor's aggregate-window line names every table past the window with its
// age, skips empty tables, and is OK when all are inside.
func TestAggregateWindowsVerdict(t *testing.T) {
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	ws := []dashboard.AggregateWindow{
		{Table: "unmask_aggregate_hourly", OldestAge: 20 * 24 * time.Hour},
		{Table: "unmask_cookie_minute", OldestAge: 102 * 24 * time.Hour, Over: true},
		{Table: "unmask_crawler_minute", Empty: true},
	}
	justPruned := db.AggregatePruneRecord{StartedAt: now.Add(-10 * time.Minute).Unix(), CompletedAt: now.Add(-10 * time.Minute).Unix()}
	warn, msg := aggregateWindowsVerdict(ws, justPruned, true, now)
	if !warn || !strings.Contains(msg, "unmask_cookie_minute (oldest row 102d)") || strings.Contains(msg, "aggregate_hourly") {
		t.Errorf("over: warn=%v msg=%q", warn, msg)
	}
	if !strings.Contains(msg, "is not trimming it") {
		t.Errorf("a table still over its window minutes after a completed prune is the prune's doing: msg=%q", msg)
	}
	ws[1].Over = false
	ws[1].OldestAge = 30 * 24 * time.Hour
	if warn, msg := aggregateWindowsVerdict(ws, justPruned, true, now); warn || !strings.Contains(msg, "2 table(s) within") {
		t.Errorf("clean (empty table not counted): warn=%v msg=%q", warn, msg)
	}
}

// A table past its window is only the prune's fault once a prune has been
// over it.  Right after an upgrade from a version that did not prune the
// table, the rows that piled up under the old version are still there and the
// first prune is minutes away: doctor said "the hourly prune is not trimming
// it" of exactly that state, and an operator went to report a defect that was
// about to fix itself.
func TestAggregateWindowsVerdictTellsNotYetFromNotWorking(t *testing.T) {
	now := time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)
	ws := []dashboard.AggregateWindow{
		{Table: "unmask_traffic_country_hourly", OldestAge: 46 * 24 * time.Hour, Over: true},
		{Table: "unmask_aggregate_hourly", OldestAge: 20 * 24 * time.Hour},
	}
	const table = "unmask_traffic_country_hourly (oldest row 46d)"

	// No prune on record: the version that records them has only just started.
	warn, msg := aggregateWindowsVerdict(ws, db.AggregatePruneRecord{}, false, now)
	if warn {
		t.Errorf("no prune has run yet: this is not a warning (msg=%q)", msg)
	}
	if !strings.Contains(msg, table) || !strings.Contains(msg, "look again in an hour") || strings.Contains(msg, "not trimming") {
		t.Errorf("no prune has run yet: msg=%q", msg)
	}
	// A run that started and has not completed one yet reads the same.
	started := db.AggregatePruneRecord{StartedAt: now.Add(-time.Minute).Unix()}
	if warn, msg := aggregateWindowsVerdict(ws, started, true, now); warn || !strings.Contains(msg, "look again in an hour") {
		t.Errorf("first prune under way: warn=%v msg=%q", warn, msg)
	}

	// The prune failed on the table: a warning that names it and says why.
	failed := db.AggregatePruneRecord{
		StartedAt: now.Add(-20 * time.Minute).Unix(), CompletedAt: now.Add(-80 * time.Minute).Unix(),
		Failed: map[string]string{"unmask_traffic_country_hourly": "database is locked"},
	}
	warn, msg = aggregateWindowsVerdict(ws, failed, true, now)
	if !warn || !strings.Contains(msg, "failed on unmask_traffic_country_hourly: database is locked") || !strings.Contains(msg, "20m0s ago") {
		t.Errorf("failed prune: warn=%v msg=%q", warn, msg)
	}

	// The prune has not completed for hours: the daemon is what to look at.
	stale := db.AggregatePruneRecord{StartedAt: now.Add(-9 * time.Hour).Unix(), CompletedAt: now.Add(-9 * time.Hour).Unix()}
	warn, msg = aggregateWindowsVerdict(ws, stale, true, now)
	if !warn || !strings.Contains(msg, "last completed 9h0m0s ago") || !strings.Contains(msg, "daemon is running") {
		t.Errorf("stale prune: warn=%v msg=%q", warn, msg)
	}
}
