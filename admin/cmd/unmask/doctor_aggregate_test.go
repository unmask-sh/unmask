package main

import (
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
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
	ws := []dashboard.AggregateWindow{
		{Table: "unmask_aggregate_hourly", OldestAge: 20 * 24 * time.Hour},
		{Table: "unmask_cookie_minute", OldestAge: 102 * 24 * time.Hour, Over: true},
		{Table: "unmask_crawler_minute", Empty: true},
	}
	warn, msg := aggregateWindowsVerdict(ws)
	if !warn || !strings.Contains(msg, "unmask_cookie_minute (oldest row 102d)") || strings.Contains(msg, "aggregate_hourly") {
		t.Errorf("over: warn=%v msg=%q", warn, msg)
	}
	ws[1].Over = false
	ws[1].OldestAge = 30 * 24 * time.Hour
	if warn, msg := aggregateWindowsVerdict(ws); warn || !strings.Contains(msg, "2 table(s) within") {
		t.Errorf("clean (empty table not counted): warn=%v msg=%q", warn, msg)
	}
}
