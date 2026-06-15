package dashboard

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestDailyUniqueIPs_RollupMatchesDirectMerge seeds per-minute traffic sketches
// spanning rolled (>= trafficSettleHours old) and live (< 1h old) minutes, then
// asserts DailyUniqueIPs reproduces a direct per-day merge of every minute —
// before the rollup (all live), after the rollup (rollup + live tail), and
// after deleting the raw rows for the rolled hours (settled days must then be
// served entirely from unmask_aggregate_hll). HLL register-wise max is
// associative, so minute->hour->day must equal minute->day exactly.
func TestDailyUniqueIPs_RollupMatchesDirectMerge(t *testing.T) {
	tmp, _ := os.MkdirTemp("", "duiptest-*")
	defer os.RemoveAll(tmp)
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(tmp, "t.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	nowMin := time.Now().Unix() / 60

	mkIPs := func(prefix string, n int) []string {
		out := make([]string, n)
		for i := 0; i < n; i++ {
			out[i] = fmt.Sprintf("%s.%d", prefix, i)
		}
		return out
	}
	// minutesAgo >= 120 falls into the rollup (hour <= now-trafficSettleHours);
	// minutesAgo < 60 is the live tail.
	groups := []struct {
		minutesAgo int64
		ips        []string
	}{
		{4000, mkIPs("10.0", 40)}, // old day -> rolled
		{4001, mkIPs("10.1", 35)}, // same old day, different minute
		{2600, mkIPs("10.2", 30)}, // another old day -> rolled
		{200, mkIPs("10.3", 25)},  // ~3h ago -> rolled
		{30, mkIPs("10.4", 20)},   // live tail
		{3, mkIPs("10.5", 15)},    // live tail
	}

	insert := func(bm int64, ips []string) {
		var s hll
		for _, ip := range ips {
			s.add([]byte(ip))
		}
		if _, err := d.ExecContext(ctx,
			`INSERT INTO unmask_traffic_hll (bucket_min, site, kind, sketch) VALUES (?,?,?,?)`,
			bm, "", "ip", s[:]); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}

	// Reference: direct per-UTC-day merge of every inserted minute.
	ref := map[string]*hll{}
	for _, g := range groups {
		bm := nowMin - g.minutesAgo
		insert(bm, g.ips)
		date := time.Unix(bm*60, 0).In(time.UTC).Format("2006-01-02")
		s := ref[date]
		if s == nil {
			s = &hll{}
			ref[date] = s
		}
		for _, ip := range g.ips {
			s.add([]byte(ip))
		}
	}

	assertMatch := func(label string) {
		t.Helper()
		got, err := DailyUniqueIPs(ctx, d, "", 30, time.UTC)
		if err != nil {
			t.Fatalf("%s: DailyUniqueIPs: %v", label, err)
		}
		gotByDate := map[string]int64{}
		for _, r := range got {
			gotByDate[r.Date] = r.UniqIPs
		}
		if len(gotByDate) != len(ref) {
			t.Fatalf("%s: day count = %d, want %d (got=%v)", label, len(gotByDate), len(ref), gotByDate)
		}
		for date, s := range ref {
			if want, gotv := int64(s.estimate()), gotByDate[date]; gotv != want {
				t.Errorf("%s: %s uniq = %d, want %d", label, date, gotv, want)
			}
		}
	}

	// 1) cursor=-1 -> entirely live. Must already match.
	assertMatch("pre-rollup (all live)")

	// 2) roll up; the cursor must advance and 'tip' rows must appear.
	if err := RollupTrafficHLL(ctx, d); err != nil {
		t.Fatalf("rollup: %v", err)
	}
	cur, err := trafficRollupCursor(ctx, d)
	if err != nil {
		t.Fatalf("cursor: %v", err)
	}
	if cur < 0 {
		t.Fatalf("cursor did not advance (still -1)")
	}
	var tipRows int
	if err := d.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM unmask_aggregate_hll WHERE bucket_kind=?`, hkTrafficIP).Scan(&tipRows); err != nil {
		t.Fatalf("count tip: %v", err)
	}
	if tipRows == 0 {
		t.Fatalf("no hkTrafficIP rows after rollup")
	}
	assertMatch("post-rollup (rollup + live tail)")

	// 3) delete raw rows for the rolled hours: settled days must now be served
	//    from the rollup alone. A wrong/unused rollup would undercount here.
	if _, err := d.ExecContext(ctx,
		`DELETE FROM unmask_traffic_hll WHERE bucket_min < ?`, (cur+1)*60); err != nil {
		t.Fatalf("delete raw: %v", err)
	}
	assertMatch("post-delete (settled days from rollup only)")
}

// TestRollupTrafficHLL_Idempotent verifies a second pass is a no-op cursor-wise
// and the stored sketches are unchanged (= a re-run after a crash mid-window
// neither double-counts nor regresses).
func TestRollupTrafficHLL_Idempotent(t *testing.T) {
	tmp, _ := os.MkdirTemp("", "duip2-*")
	defer os.RemoveAll(tmp)
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(tmp, "t.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	nowMin := time.Now().Unix() / 60

	var s hll
	for i := 0; i < 50; i++ {
		s.add([]byte(fmt.Sprintf("9.9.9.%d", i)))
	}
	if _, err := d.ExecContext(ctx,
		`INSERT INTO unmask_traffic_hll (bucket_min, site, kind, sketch) VALUES (?,?,?,?)`,
		nowMin-3000, "", "ip", s[:]); err != nil {
		t.Fatalf("insert: %v", err)
	}

	if err := RollupTrafficHLL(ctx, d); err != nil {
		t.Fatalf("rollup 1: %v", err)
	}
	first, err := DailyUniqueIPs(ctx, d, "", 30, time.UTC)
	if err != nil {
		t.Fatalf("read 1: %v", err)
	}
	cur1, _ := trafficRollupCursor(ctx, d)

	if err := RollupTrafficHLL(ctx, d); err != nil {
		t.Fatalf("rollup 2: %v", err)
	}
	second, err := DailyUniqueIPs(ctx, d, "", 30, time.UTC)
	if err != nil {
		t.Fatalf("read 2: %v", err)
	}
	cur2, _ := trafficRollupCursor(ctx, d)

	if cur2 < cur1 {
		t.Fatalf("cursor regressed: %d -> %d", cur1, cur2)
	}
	if len(first) != len(second) {
		t.Fatalf("row count changed across passes: %d -> %d", len(first), len(second))
	}
	for i := range first {
		if first[i] != second[i] {
			t.Fatalf("estimate changed across passes at %d: %+v -> %+v", i, first[i], second[i])
		}
	}
}
