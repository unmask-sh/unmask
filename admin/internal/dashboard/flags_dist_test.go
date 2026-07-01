package dashboard

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestFlagsDistribution_AggMatchesScan seeds a mix of phase=load events
// across several flags values + a non-keyFlag exotic value, then verifies
// the aggregate path returns the same per-flags count + uniq IP as the
// scan path.  Same parity discipline as captcha_force_test.go.
func TestFlagsDistribution_AggMatchesScan(t *testing.T) {
	tmp, _ := os.MkdirTemp("", "fltest-*")
	defer os.RemoveAll(tmp)
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(tmp, "t.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// 7 seeded events:
	//   flags=0  ×3 (= 2 distinct IPs)  -- the default "no signal" bucket
	//   flags=1  ×2 (= 2 distinct IPs)  -- webdriver
	//   flags=17 ×1                     -- webdriver + chrome-spoof (a keyFlag)
	//   flags=64 ×1                     -- not in keyFlags (= "remaining observed" path)
	seed := []struct {
		ip    string
		flags int
	}{
		{"1.1.1.1", 0},
		{"2.2.2.2", 0},
		{"1.1.1.1", 0}, // repeat IP -> uniq stays 2
		{"3.3.3.3", 1},
		{"4.4.4.4", 1},
		{"5.5.5.5", 17},
		{"6.6.6.6", 64},
	}
	for i, s := range seed {
		if _, err := d.Exec(
			`INSERT INTO unmask_event
				(site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id,
				 phase, flags, reload_count, cookie_bv, cookie_br, payload_json, date_created)
			 VALUES ('','','','','`+s.ip+`','UA','','',0,'load',?,0,'','','{}',datetime('now','-30 minutes'))`,
			s.flags); err != nil {
			t.Fatalf("seed[%d]: %v", i, err)
		}
	}

	ctx := context.Background()

	scanRows, err := flagsDistributionScan(ctx, d, "", nil, 36)
	if err != nil {
		t.Fatalf("scan: %v", err)
	}

	if err := AggregateHourly(ctx, d, nil); err != nil {
		t.Fatalf("rollup: %v", err)
	}
	defer hourlyReady.Store(false)

	aggRows, err := flagsDistributionAgg(ctx, d, 36)
	if err != nil {
		t.Fatalf("agg: %v", err)
	}

	if len(scanRows) != len(aggRows) {
		t.Fatalf("row count: scan=%d agg=%d", len(scanRows), len(aggRows))
	}
	// orderFlagsRows guarantees identical ordering (= same keyFlags front
	// + same count-desc/flags-asc tail).  Compare positionally.
	for i := range scanRows {
		if scanRows[i].Flags != aggRows[i].Flags {
			t.Errorf("[%d] flags: scan=%d agg=%d", i, scanRows[i].Flags, aggRows[i].Flags)
		}
		if scanRows[i].Count != aggRows[i].Count {
			t.Errorf("[flags=%d] count: scan=%d agg=%d",
				scanRows[i].Flags, scanRows[i].Count, aggRows[i].Count)
		}
		diff := scanRows[i].UniqIP - aggRows[i].UniqIP
		if diff < 0 {
			diff = -diff
		}
		if diff > 1 {
			t.Errorf("[flags=%d] uniq IP diff > 1: scan=%d agg=%d",
				scanRows[i].Flags, scanRows[i].UniqIP, aggRows[i].UniqIP)
		}
	}

	// Sanity on agg counts.
	gotCount := map[int]int{}
	gotUniq := map[int]int{}
	for _, r := range aggRows {
		gotCount[r.Flags] = r.Count
		gotUniq[r.Flags] = r.UniqIP
	}
	wantCount := map[int]int{0: 3, 1: 2, 17: 1, 64: 1}
	wantUniq := map[int]int{0: 2, 1: 2, 17: 1, 64: 1}
	for fl, n := range wantCount {
		if gotCount[fl] != n {
			t.Errorf("agg count[flags=%d] = %d, want %d", fl, gotCount[fl], n)
		}
	}
	for fl, u := range wantUniq {
		// ±1 HLL tolerance (= small N, sketch should hit exact but we
		// stay honest about its approximate nature).
		diff := gotUniq[fl] - u
		if diff < 0 {
			diff = -diff
		}
		if diff > 1 {
			t.Errorf("agg uniq[flags=%d] = %d, want %d (±1)", fl, gotUniq[fl], u)
		}
	}
}
