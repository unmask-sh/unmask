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

func iwTestDB(t *testing.T) *db.DB {
	t.Helper()
	tmp, _ := os.MkdirTemp("", "iwtest-*")
	t.Cleanup(func() { os.RemoveAll(tmp) })
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(tmp, "t.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return d
}

// TestDailyPassByDay_RollupMatchesLiveScan seeds per-minute cookie counts across
// several sites, spanning rolled (>= trafficSettleHours old) and live (< 1h old)
// minutes, and asserts DailyPassByDay's default (site="") view reproduces a
// direct all-site, per-UTC-day sum — before the rollup (all live), after the
// rollup (install-wide hourly + live tail), and after deleting the raw rows for
// the settled hours (settled days must then be served entirely from
// unmask_aggregate_hourly). The install-wide rollup sums across sites, so the
// default view must equal the sum of every site's minute counts.
func TestDailyPassByDay_RollupMatchesLiveScan(t *testing.T) {
	d := iwTestDB(t)
	ctx := context.Background()
	nowMin := time.Now().Unix() / 60

	// (minutesAgo, site, {kind: cnt}). minutesAgo >= 120 rolls up; < 60 is the
	// live tail. Two sites share old minutes so the install-wide sum is exercised.
	type seed struct {
		minutesAgo int64
		site       string
		kinds      map[string]int
	}
	seeds := []seed{
		{4000, "s1", map[string]int{"total": 100, "captcha": 10, "pow": 20, "challenge_served": 5}},
		{4000, "s2", map[string]int{"total": 50, "captcha": 5}},
		{2600, "s1", map[string]int{"total": 30, "challenge_served": 3}},
		{200, "s1", map[string]int{"total": 40, "captcha": 4, "pow": 8, "challenge_served": 2}},
		{30, "s2", map[string]int{"total": 25, "pow": 5, "challenge_served": 1}}, // live tail
		{3, "s1", map[string]int{"total": 15, "captcha": 2}},                     // live tail
	}

	type cacc struct{ total, bv, bp, fc int }
	ref := map[string]*cacc{}
	for _, s := range seeds {
		bm := nowMin - s.minutesAgo
		for k, c := range s.kinds {
			if _, err := d.ExecContext(ctx,
				`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt) VALUES (?,?,?,?)`,
				bm, s.site, k, c); err != nil {
				t.Fatalf("insert: %v", err)
			}
		}
		date := time.Unix(bm*60, 0).UTC().Format("2006-01-02")
		a := ref[date]
		if a == nil {
			a = &cacc{}
			ref[date] = a
		}
		a.total += s.kinds["total"]
		a.bv += s.kinds["captcha"]
		a.bp += s.kinds["pow"]
		a.fc += s.kinds["challenge_served"]
	}

	assertMatch := func(label string) {
		t.Helper()
		daily, totals, err := DailyPassByDay(ctx, d, "", nil, 30, time.UTC)
		if err != nil {
			t.Fatalf("%s: DailyPassByDay: %v", label, err)
		}
		gotTotal := map[string]int{}
		for _, tot := range totals {
			gotTotal[tot.Date] = tot.Req
		}
		gotKind := map[string]map[int]int{}
		for _, b := range daily {
			if gotKind[b.Date] == nil {
				gotKind[b.Date] = map[int]int{}
			}
			gotKind[b.Date][b.Kind] = b.Req
		}
		if len(gotTotal) != len(ref) {
			t.Fatalf("%s: day count = %d, want %d", label, len(gotTotal), len(ref))
		}
		for date, a := range ref {
			notPass := a.fc
			white := a.total - a.bv - a.bp - a.fc
			if white < 0 {
				white = 0
			}
			if gotTotal[date] != a.total {
				t.Errorf("%s: %s total = %d, want %d", label, date, gotTotal[date], a.total)
			}
			want := map[int]int{}
			if white > 0 {
				want[KindWhitePass] = white
			}
			if a.bv > 0 {
				want[KindCaptchaPass] = a.bv
			}
			if a.bp > 0 {
				want[KindPoWPass] = a.bp
			}
			if notPass > 0 {
				want[KindNotPass] = notPass
			}
			for k, v := range want {
				if gotKind[date][k] != v {
					t.Errorf("%s: %s kind %d = %d, want %d", label, date, k, gotKind[date][k], v)
				}
			}
			if len(gotKind[date]) != len(want) {
				t.Errorf("%s: %s kind buckets = %v, want %v", label, date, gotKind[date], want)
			}
		}
	}

	// 1) cursor=-1 -> entirely live. Must already match.
	assertMatch("pre-rollup (all live)")

	// 2) roll up; the install-wide cursor advances and hkCookiePass rows appear.
	if err := RollupInstallWideHourly(ctx, d); err != nil {
		t.Fatalf("rollup: %v", err)
	}
	cur, err := stateCursor(ctx, d, installWideState)
	if err != nil {
		t.Fatalf("cursor: %v", err)
	}
	if cur < 0 {
		t.Fatalf("cursor did not advance (still -1)")
	}
	var ckRows int
	if err := d.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM unmask_aggregate_hourly WHERE bucket_kind=?`, hkCookiePass).Scan(&ckRows); err != nil {
		t.Fatalf("count ckph: %v", err)
	}
	if ckRows == 0 {
		t.Fatalf("no hkCookiePass rows after rollup")
	}
	assertMatch("post-rollup (rollup + live tail)")

	// 3) delete raw rows for the settled hours: settled days must now be served
	//    from the hourly rollup alone.
	if _, err := d.ExecContext(ctx,
		`DELETE FROM unmask_cookie_minute WHERE bucket_min < ?`, (cur+1)*60); err != nil {
		t.Fatalf("delete raw: %v", err)
	}
	assertMatch("post-delete (settled days from rollup only)")
}

// TestRollupInstallWide_MultiSiteUnionAndPerSite verifies the install-wide IP
// sketch is the union across every site (the site="" view), while a site-scoped
// view still reports that site's own distinct IPs — both after the raw
// per-minute rows are deleted so each is served purely from its rollup.
func TestRollupInstallWide_MultiSiteUnionAndPerSite(t *testing.T) {
	d := iwTestDB(t)
	ctx := context.Background()
	nowMin := time.Now().Unix() / 60
	bm := nowMin - 3000 // settled

	insert := func(site string, ips []string) {
		var s hll
		for _, ip := range ips {
			s.add([]byte(ip))
		}
		if _, err := d.ExecContext(ctx,
			`INSERT INTO unmask_traffic_hll (bucket_min, site, kind, sketch) VALUES (?,?,?,?)`,
			bm, site, "ip", s[:]); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	s1IPs := []string{"a", "b", "c"}
	s2IPs := []string{"c", "d"} // overlaps 'c'
	insert("s1", s1IPs)
	insert("s2", s2IPs)

	// Reference estimates: same register math the read path uses.
	var refUnion, refS1 hll
	for _, ip := range append(append([]string{}, s1IPs...), s2IPs...) {
		refUnion.add([]byte(ip))
	}
	for _, ip := range s1IPs {
		refS1.add([]byte(ip))
	}

	// Drive both rollups, then delete the raw rows so each view is served purely
	// from its rollup (install-wide for site="", per-site for site="s1").
	if err := RollupInstallWideHourly(ctx, d); err != nil {
		t.Fatalf("install-wide rollup: %v", err)
	}
	if err := RollupTrafficHLL(ctx, d); err != nil {
		t.Fatalf("per-site rollup: %v", err)
	}
	cur, _ := stateCursor(ctx, d, installWideState)
	if _, err := d.ExecContext(ctx,
		`DELETE FROM unmask_traffic_hll WHERE bucket_min < ?`, (cur+1)*60); err != nil {
		t.Fatalf("delete raw: %v", err)
	}

	uniqOn := func(site string) int64 {
		got, err := DailyUniqueIPs(ctx, d, site, 30, time.UTC)
		if err != nil {
			t.Fatalf("DailyUniqueIPs(%q): %v", site, err)
		}
		var sum int64
		for _, r := range got {
			sum += r.UniqIPs
		}
		return sum
	}
	if got, want := uniqOn(""), int64(refUnion.estimate()); got != want {
		t.Errorf("install-wide uniq = %d, want union %d", got, want)
	}
	if got, want := uniqOn("s1"), int64(refS1.estimate()); got != want {
		t.Errorf("per-site s1 uniq = %d, want %d", got, want)
	}
}

// TestRollupInstallWide_Idempotent verifies a second install-wide pass neither
// advances behind the first nor changes the reported values (crash-replay safe).
func TestRollupInstallWide_Idempotent(t *testing.T) {
	d := iwTestDB(t)
	ctx := context.Background()
	nowMin := time.Now().Unix() / 60

	var s hll
	for i := 0; i < 40; i++ {
		s.add([]byte(fmt.Sprintf("7.7.7.%d", i)))
	}
	if _, err := d.ExecContext(ctx,
		`INSERT INTO unmask_traffic_hll (bucket_min, site, kind, sketch) VALUES (?,?,?,?)`,
		nowMin-3000, "s1", "ip", s[:]); err != nil {
		t.Fatalf("insert hll: %v", err)
	}
	if _, err := d.ExecContext(ctx,
		`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt) VALUES (?,?,?,?)`,
		nowMin-3000, "s1", "total", 99); err != nil {
		t.Fatalf("insert cookie: %v", err)
	}

	if err := RollupInstallWideHourly(ctx, d); err != nil {
		t.Fatalf("rollup 1: %v", err)
	}
	uniq1 := 0
	if got, err := DailyUniqueIPs(ctx, d, "", 30, time.UTC); err == nil {
		for _, r := range got {
			uniq1 += int(r.UniqIPs)
		}
	} else {
		t.Fatalf("read1: %v", err)
	}
	_, tot1, err := DailyPassByDay(ctx, d, "", nil, 30, time.UTC)
	if err != nil {
		t.Fatalf("pass1: %v", err)
	}
	cur1, _ := stateCursor(ctx, d, installWideState)

	if err := RollupInstallWideHourly(ctx, d); err != nil {
		t.Fatalf("rollup 2: %v", err)
	}
	uniq2 := 0
	if got, err := DailyUniqueIPs(ctx, d, "", 30, time.UTC); err == nil {
		for _, r := range got {
			uniq2 += int(r.UniqIPs)
		}
	} else {
		t.Fatalf("read2: %v", err)
	}
	_, tot2, err := DailyPassByDay(ctx, d, "", nil, 30, time.UTC)
	if err != nil {
		t.Fatalf("pass2: %v", err)
	}
	cur2, _ := stateCursor(ctx, d, installWideState)

	if cur2 < cur1 {
		t.Fatalf("cursor regressed: %d -> %d", cur1, cur2)
	}
	if uniq1 != uniq2 {
		t.Fatalf("uniq changed across passes: %d -> %d", uniq1, uniq2)
	}
	if len(tot1) != len(tot2) || (len(tot1) == 1 && tot1[0].Req != tot2[0].Req) {
		t.Fatalf("totals changed across passes: %+v -> %+v", tot1, tot2)
	}
}
