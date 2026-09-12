package dashboard

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// seedServeRows plants phase=serve rows spread over the last three days: two
// user agents, two verdicts, a handful of addresses, and a few rate-limit
// serves the card excludes.  Returns how many rows were written.
func seedServeRows(t *testing.T, d *db.DB) int {
	t.Helper()
	n := 0
	base := time.Now().UTC().Add(-70 * time.Hour)
	for i := 0; i < 42; i++ {
		ts := base.Add(time.Duration(i) * 95 * time.Minute)
		ua, verdict := "Mozilla/5.0 (X11; Linux x86_64)", ""
		if i%3 == 0 {
			ua, verdict = "curl/8.0", "bot_curl"
		}
		payload := "{}"
		if i%7 == 0 {
			payload = `{"rl":1}`
		}
		ip := fmt.Sprintf("10.0.%d.%d", i%4, i%9)
		if _, err := d.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,?,?,'t13d',?,0,'serve',0,0,'','',?,?)`,
			[]byte(ip), ua, verdict, payload, ts.Format("2006-01-02 15:04:05.000")); err != nil {
			t.Fatal(err)
		}
		n++
	}
	return n
}

func sameDaily(t *testing.T, what string, got, want []DailyKindBucket) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: %d daily rows, want %d\n got=%+v\nwant=%+v", what, len(got), len(want), got, want)
	}
	for i := range want {
		if got[i].Date != want[i].Date || got[i].Kind != want[i].Kind || got[i].Req != want[i].Req {
			t.Errorf("%s: daily[%d] = %+v, want %+v", what, i, got[i], want[i])
		}
	}
}

func sameTotals(t *testing.T, what string, got, want []DailyTotal) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: %d total rows, want %d\n got=%+v\nwant=%+v", what, len(got), len(want), got, want)
	}
	for i := range want {
		if got[i].Date != want[i].Date || got[i].Req != want[i].Req {
			t.Errorf("%s: totals[%d] = %+v, want %+v", what, i, got[i], want[i])
		}
		// Distinct addresses are exact on the scan and a sketch on the rollup:
		// for a handful of addresses the sketch is exact to within one.
		if diff := got[i].UniqIPs - want[i].UniqIPs; diff > 1 || diff < -1 {
			t.Errorf("%s: totals[%d].UniqIPs = %d, want about %d", what, i, got[i].UniqIPs, want[i].UniqIPs)
		}
	}
}

// The 30-day serve card reads every hour the rollup has settled from the
// rollup and scans only the remainder, and the answer is the same as a full
// raw scan at every stage: before any pass, with the cursor mid-table, and
// once everything is folded (operator, 2026-09-12: "daily で値が確定するので
// 毎回計算する必要無いのでは").
func TestDailyServeByKindSettledMatchesScan(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	hourlyReady.Store(false)
	hourlyChunkRows.Store(0)
	t.Cleanup(func() { hourlyReady.Store(false); hourlyChunkRows.Store(0) })
	total := seedServeRows(t, d)
	bots := []string{"bot_curl"}

	wantDaily, wantTotals, err := dailyServeByKindScan(ctx, d, "", nil, 30, bots, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	if len(wantTotals) < 3 {
		t.Fatalf("seed did not spread over three days: %+v", wantTotals)
	}

	// 1. No cursor yet: the settled read is the scan.
	if _, _, ok, err := hourlySettledBoundary(ctx, d); err != nil || ok {
		t.Fatalf("before any pass: ok=%v err=%v, want no boundary", ok, err)
	}
	gotDaily, gotTotals, err := DailyServeByKind(ctx, d, "", nil, 30, bots, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	sameDaily(t, "no cursor", gotDaily, wantDaily)
	sameTotals(t, "no cursor", gotTotals, wantTotals)

	// 2. Cursor mid-table: one small chunk folded, the rest unfolded.
	hourlyChunkRows.Store(11)
	n, maxID, err := aggregateHourlyChunk(ctx, d, nil, 0)
	if err != nil || n != 11 {
		t.Fatalf("partial fold: n=%d err=%v", n, err)
	}
	cursor, boundary, ok, err := hourlySettledBoundary(ctx, d)
	if err != nil || !ok || cursor != maxID {
		t.Fatalf("boundary after a partial fold: cursor=%d ok=%v err=%v (want cursor %d)", cursor, ok, err, maxID)
	}
	var firstUnfolded any
	if err := d.QueryRow(`SELECT date_created FROM unmask_event WHERE id > ? ORDER BY id LIMIT 1`, cursor).Scan(&firstUnfolded); err != nil {
		t.Fatal(err)
	}
	if ft, ok := normalizeEventTime(firstUnfolded); !ok || !boundary.Equal(ft.UTC().Truncate(time.Hour)) {
		t.Errorf("boundary = %v, want the first unfolded row's hour (%v)", boundary, firstUnfolded)
	}
	if HourlyAggReady() {
		t.Fatal("a partial fold must not mark the rollup ready")
	}
	gotDaily, gotTotals, err = DailyServeByKind(ctx, d, "", nil, 30, bots, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	sameDaily(t, "cursor mid-table", gotDaily, wantDaily)
	sameTotals(t, "cursor mid-table", gotTotals, wantTotals)

	// 3. Everything folded, but no pass completed in this process (a restart
	//    with an up-to-date cursor): the settled read is the rollup alone.
	hourlyChunkRows.Store(0)
	for {
		n, _, err := aggregateHourlyChunk(ctx, d, nil, cursor)
		if err != nil {
			t.Fatal(err)
		}
		if n == 0 {
			break
		}
		cursor, _, _, _ = hourlySettledBoundary(ctx, d)
	}
	hourlyReady.Store(false)
	if _, boundary, ok, _ := hourlySettledBoundary(ctx, d); !ok || !boundary.After(time.Now().UTC()) {
		t.Errorf("everything folded: boundary = %v ok=%v, want the hour after now", boundary, ok)
	}
	gotDaily, gotTotals, err = DailyServeByKind(ctx, d, "", nil, 30, bots, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	sameDaily(t, "all folded", gotDaily, wantDaily)
	sameTotals(t, "all folded", gotTotals, wantTotals)
	_ = total
}

// The remainder a settled read scans raw: the boundary hour onward, plus the
// rows before it the cursor has not folded -- each clause indexable alone.
func TestSettledRemainderClauses(t *testing.T) {
	lo := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	hi := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	w := Window{Start: lo.Unix(), End: hi.Unix()}
	if got := settledRemainderClauses(w, 5, lo.Add(-time.Hour)); len(got) != 1 || got[0] != "date_created >= '2026-09-01 00:00:00' AND date_created <= '2026-09-03 12:00:00'" {
		t.Errorf("boundary before the window: %q", got)
	}
	got := settledRemainderClauses(w, 5, time.Date(2026, 9, 2, 7, 0, 0, 0, time.UTC))
	if len(got) != 2 ||
		got[0] != "date_created >= '2026-09-02 07:00:00' AND date_created <= '2026-09-03 12:00:00'" ||
		got[1] != "id > 5 AND date_created >= '2026-09-01 00:00:00' AND date_created < '2026-09-02 07:00:00'" {
		t.Errorf("boundary inside the window: %q", got)
	}
	got = settledRemainderClauses(w, 5, hi.Add(time.Hour))
	if len(got) != 1 || got[0] != "id > 5 AND date_created >= '2026-09-01 00:00:00' AND date_created < '2026-09-03 13:00:00'" {
		t.Errorf("boundary after the window: %q", got)
	}
}

// The fold chunk follows the host: slow chunks halve it down to a floor,
// quick ones double it back up to hourlyBatch.
func TestAdaptHourlyChunk(t *testing.T) {
	hourlyChunkRows.Store(0)
	t.Cleanup(func() { hourlyChunkRows.Store(0) })
	if currentHourlyChunk() != hourlyBatch {
		t.Fatalf("default chunk = %d, want %d", currentHourlyChunk(), hourlyBatch)
	}
	adaptHourlyChunk(hourlyChunkSlow + time.Second)
	if currentHourlyChunk() != hourlyBatch/2 {
		t.Errorf("after a slow chunk: %d, want %d", currentHourlyChunk(), hourlyBatch/2)
	}
	for i := 0; i < 12; i++ {
		adaptHourlyChunk(time.Minute)
	}
	if currentHourlyChunk() != hourlyChunkMin {
		t.Errorf("slow chunks bottom out at %d, got %d", hourlyChunkMin, currentHourlyChunk())
	}
	adaptHourlyChunk(10 * time.Second)
	if currentHourlyChunk() != hourlyChunkMin {
		t.Errorf("an ordinary chunk leaves the size alone, got %d", currentHourlyChunk())
	}
	for i := 0; i < 12; i++ {
		adaptHourlyChunk(time.Second)
	}
	if currentHourlyChunk() != hourlyBatch {
		t.Errorf("quick chunks grow back to %d, got %d", hourlyBatch, currentHourlyChunk())
	}
}
