package dashboard

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestCaptchaForceBreakdown_AggMatchesScan seeds a fixed mix of load events
// (= every reason kind + an unknown fallback) and verifies the aggregate
// path returns the same per-kind count + uniq IP as the raw scan.  This
// guards the parity we promised in the ROADMAP entry; if either path drifts,
// dashboard numbers diverge between the install-wide and host-filtered
// views.
func TestCaptchaForceBreakdown_AggMatchesScan(t *testing.T) {
	tmp, _ := os.MkdirTemp("", "cftest-*")
	defer os.RemoveAll(tmp)
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(tmp, "t.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// 9 seeded events:
	//   - ja4_bot   ×2  (= 2 distinct IPs, exercises a non-trivial uniq)
	//   - honeypot  ×1
	//   - banned    ×1
	//   - protected ×1
	//   - rate_limit×1
	//   - test      ×1
	//   - none      ×1
	//   - unknown   ×1  (= payload with bogus force_reason → CASE ELSE fold)
	seed := []struct {
		ip      string
		payload string
	}{
		{"1.1.1.1", `{"force_reason":"ja4_bot"}`},
		{"2.2.2.2", `{"force_reason":"ja4_bot"}`},
		{"3.3.3.3", `{"force_reason":"honeypot"}`},
		{"4.4.4.4", `{"force_reason":"banned"}`},
		{"5.5.5.5", `{"force_reason":"protected"}`},
		{"6.6.6.6", `{"force_reason":"rate_limit"}`},
		{"7.7.7.7", `{"force_reason":"test"}`},
		{"8.8.8.8", `{"force_reason":"none"}`},
		{"9.9.9.9", `{"force_reason":"bogus_value"}`},
	}
	// Plant each row at "30 minutes ago" so both window cutoffs include it:
	//   - scan:  date_created > NowMinusMinutes(hours*60) -- fine for any hours>=1
	//   - agg:   bucket_hour >= hourAgoExpr(N) -- the 30-min point's hour bucket
	//            is the previous-or-current UTC hour, well inside any N>=1 window
	// sqlite-specific timestamp generator; this test file already lives in
	// the same in-memory-sqlite world as tz_test.go.
	for i, s := range seed {
		if _, err := d.Exec(
			`INSERT INTO unmask_event
				(site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id,
				 phase, flags, reload_count, cookie_bv, cookie_br, payload_json, date_created)
			 VALUES ('','','','','`+s.ip+`','UA','','',0,'load',0,0,'','',?,datetime('now','-30 minutes'))`,
			s.payload); err != nil {
			t.Fatalf("seed[%d]: %v", i, err)
		}
	}

	ctx := context.Background()

	// Run scan first (= still works without aggregate ready).
	scanRows, err := captchaForceBreakdownScan(ctx, d, "", nil, 36)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	// Force a hourly rollup so the agg path has data.  AggregateHourly flips
	// the package-level hourlyReady flag on success; reset it on test exit
	// so sibling tests (= tz_test etc.) that don't run their own rollup
	// keep seeing the scan path they were written for.
	if err := AggregateHourly(ctx, d, nil); err != nil {
		t.Fatalf("rollup: %v", err)
	}
	defer hourlyReady.Store(false)

	aggRows, err := captchaForceBreakdownAgg(ctx, d, 36)
	if err != nil {
		t.Fatalf("agg: %v", err)
	}

	if len(scanRows) != len(aggRows) {
		t.Fatalf("row count: scan=%d agg=%d", len(scanRows), len(aggRows))
	}
	for i := range scanRows {
		if scanRows[i].Kind != aggRows[i].Kind {
			t.Errorf("[%d] kind: scan=%q agg=%q", i, scanRows[i].Kind, aggRows[i].Kind)
		}
		if scanRows[i].Count != aggRows[i].Count {
			t.Errorf("[%s] count: scan=%d agg=%d", scanRows[i].Kind, scanRows[i].Count, aggRows[i].Count)
		}
		// HLL is approximate; with N≤2 distinct IPs per bucket the estimate
		// happens to be exact, but assert with a tolerance to stay honest
		// about the sketch's nature.
		diff := scanRows[i].UniqIP - aggRows[i].UniqIP
		if diff < 0 {
			diff = -diff
		}
		if diff > 1 {
			t.Errorf("[%s] uniq IP diff > 1: scan=%d agg=%d",
				scanRows[i].Kind, scanRows[i].UniqIP, aggRows[i].UniqIP)
		}
	}

	// Sanity: expected counts per kind from the seed mix.
	want := map[string]int{
		"none":       1,
		"ja4_bot":    2,
		"honeypot":   1,
		"banned":     1,
		"protected":  1,
		"rate_limit": 1,
		"test":       1,
		"unknown":    1, // bogus_value folds here
	}
	got := map[string]int{}
	for _, r := range aggRows {
		got[r.Kind] = r.Count
	}
	for k, n := range want {
		if got[k] != n {
			t.Errorf("agg[%s] count = %d, want %d", k, got[k], n)
		}
	}
}

// (compile-time sanity that the const list the test asserts against is the
// one queries.go actually uses for display order)
var _ = fmt.Sprint(captchaForceKinds)
