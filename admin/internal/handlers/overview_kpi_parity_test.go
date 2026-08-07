package handlers

import (
	"context"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/db"
)

// The rollup and the scan must agree on the same database.
//
// The landing page reads its counters from the hourly rollup and falls back to
// scanning raw events; the two are supposed to be the same number by
// construction, which is exactly the kind of "supposed to" that drifts.  This
// runs both against one populated database and compares -- if a future bucket
// gains a filter the scan does not have, or the scan gains one the bucket
// misses, an operator would see the figure change depending on whether a site
// filter happens to be set, and only this test would notice.
func TestLandingKPIAggregateMatchesScan(t *testing.T) {
	h := newTestHandler(t)
	// The shared harness lays down only unmask_event; the rollup needs the rest
	// of the schema (and its cursor table) to run at all.
	if err := db.Migrate(h.DB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC().Format("2006-01-02 15:04:05")

	// A mix wide enough that a wrong filter shows up as a wrong number.
	rows := []struct{ phase, payload string }{
		{"serve", `{}`}, {"serve", `{}`}, {"serve", `{"rl":"1"}`},
		{"load", `{"chmode":"pow_only"}`},
		{"load", `{"chmode":"pow_only","force_reason":"none"}`},
		{"load", `{"chmode":"pow_only","force_reason":"ua_target"}`},
		{"load", `{"chmode":"captcha_only"}`},
		{"abandon", `{"chmode":"pow_only"}`},
		{"abandon", `{"chmode":"pow_only","force_reason":"ja4_bot"}`},
		{"bv_pow_only", `{}`}, {"bv_captcha_only", `{}`},
	}
	for i, r := range rows {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site, host, ip_address, phase, flags, reload_count, payload_json, date_created)
			VALUES ('s', 'h', ?, ?, 0, 0, ?, ?)`,
			[]byte{10, 0, 0, byte(i)}, r.phase, r.payload, now); err != nil {
			t.Fatal(err)
		}
	}
	// Leave the global "aggregate is ready" flag as we found it; see
	// ResetHourlyAggReadyForTest for what forgetting costs.
	defer dashboard.ResetHourlyAggReadyForTest()
	if err := dashboard.AggregateHourly(ctx, h.DB, nil); err != nil {
		t.Fatalf("aggregate: %v", err)
	}

	// countEvents / countUnruledPoW take the aggregate path with no filters
	// and the scan path with a site filter.  Same database, so same answer.
	for _, phase := range []string{"serve", "load", "abandon", "bv_pow_only", "bv_captcha_only"} {
		agg := countEvents(ctx, h, 1440, phase, "", nil)
		scan := countEvents(ctx, h, 1440, phase, "s", nil)
		if agg != scan {
			t.Errorf("phase %q: rollup=%d scan=%d", phase, agg, scan)
		}
	}
	for _, phase := range []string{"load", "abandon"} {
		agg := countUnruledPoW(ctx, h, 1440, phase, "", nil)
		scan := countUnruledPoW(ctx, h, 1440, phase, "s", nil)
		if agg != scan {
			t.Errorf("unruled %q: rollup=%d scan=%d", phase, agg, scan)
		}
	}
	// And the multi-phase form the CAPTCHA-pass KPI uses.
	phases := []string{"bv_pow_only", "bv_captcha_only"}
	if agg, scan := countEventsPhases(ctx, h, 1440, phases, "", nil),
		countEventsPhases(ctx, h, 1440, phases, "s", nil); agg != scan {
		t.Errorf("phases %v: rollup=%d scan=%d", phases, agg, scan)
	}
	// Sanity: the fixture must actually exercise the filter, or the comparison
	// above is two identical zeroes agreeing with each other.
	if n := countEvents(ctx, h, 1440, "serve", "", nil); n != 3 {
		t.Fatalf("fixture not counted (serve=%d, want 3) -- the parity check above proves nothing", n)
	}
}
