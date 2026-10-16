package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// seedBlockedRows writes three days of challenge sessions: serves, the two
// kinds of pass, and abandons -- some by ordinary visitors on the transparent
// chain (the ones the figure subtracts), some by visitors a rule pointed at
// or on another chain (the ones it keeps).  Returns the terms per UTC day
// the way DailyBlockedByDay should read them.
func seedBlockedRows(t *testing.T, d *db.DB) map[string]DailyBlockedDay {
	t.Helper()
	want := map[string]DailyBlockedDay{}
	base := time.Now().UTC().Add(-70 * time.Hour).Truncate(time.Hour)
	insert := func(ts time.Time, phase, payload string) {
		if _, err := d.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,?,'Mozilla/5.0','t13d','',0,?,0,0,'','',?,?)`,
			[]byte("10.0.0.1"), phase, payload, ts.Format("2006-01-02 15:04:05.000")); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 60; i++ {
		ts := base.Add(time.Duration(i) * 67 * time.Minute)
		date := ts.Format("2006-01-02")
		w := want[date]
		w.Date = date
		insert(ts, "serve", "{}")
		w.Serves++
		switch i % 6 {
		case 0:
			insert(ts, "bv_pow_only", "{}")
			w.PoW++
		case 1:
			insert(ts, "bv_captcha_only", "{}")
			w.Captcha++
		case 2:
			insert(ts, "bv_pow_then_captcha", "{}")
			w.Captcha++
		case 3:
			// An ordinary visitor on the transparent chain who left: subtracted.
			insert(ts, "abandon", `{"chmode":"pow_only"}`)
			w.Abandon++
		case 4:
			// A visitor a rule pointed at: kept (counted as blocked).
			insert(ts, "abandon", `{"chmode":"pow_only","force_reason":"honeypot"}`)
		case 5:
			// Left a CAPTCHA, not the proof-of-work: kept.
			insert(ts, "abandon", `{"chmode":"captcha_only"}`)
		}
		want[date] = w
	}
	return want
}

func sameBlocked(t *testing.T, what string, got []DailyBlockedDay, want map[string]DailyBlockedDay) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s: %d days, want %d: %+v", what, len(got), len(want), got)
	}
	for _, g := range got {
		w, ok := want[g.Date]
		if !ok {
			t.Errorf("%s: a day the seed has not: %+v", what, g)
			continue
		}
		if g != w {
			t.Errorf("%s: %s = %+v, want %+v", what, g.Date, g, w)
		}
	}
}

// TestDailyBlockedByDayAgreesAcrossSources: the scan, the settled read (rollup
// up to the boundary, events after it) and the pure rollup read give the same
// per-day terms, with the abandon counted only for an ordinary visitor on the
// transparent chain.
func TestDailyBlockedByDayAgreesAcrossSources(t *testing.T) {
	d := openTestDB(t)
	ctx := context.Background()
	hourlyReady.Store(false)
	hourlyChunkRows.Store(0)
	t.Cleanup(func() { hourlyReady.Store(false); hourlyChunkRows.Store(0) })
	want := seedBlockedRows(t, d)
	if len(want) < 3 {
		t.Fatalf("seed did not spread over three days: %+v", want)
	}
	// No pass yet, no boundary: the scan.
	got, err := DailyBlockedByDay(ctx, d, "", nil, 30, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	sameBlocked(t, "scan", got, want)
	// A partial fold: the settled hours from the rollup, the rest from events.
	hourlyChunkRows.Store(37)
	if n, _, err := aggregateHourlyChunk(ctx, d, nil, 0); err != nil || n != 37 {
		t.Fatalf("partial fold: n=%d err=%v", n, err)
	}
	if _, _, ok, err := hourlySettledBoundary(ctx, d); err != nil || !ok {
		t.Fatalf("no boundary after a partial fold: ok=%v err=%v", ok, err)
	}
	got, err = DailyBlockedByDay(ctx, d, "", nil, 30, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	sameBlocked(t, "settled", got, want)
	// The whole table folded and a pass completed: the rollup alone.
	hourlyChunkRows.Store(100000)
	var after int64
	if err := d.QueryRow(`SELECT COALESCE(MAX(last_id), 0) FROM unmask_aggregate_state WHERE name = ?`, hourlyState).Scan(&after); err != nil {
		t.Fatal(err)
	}
	if _, _, err := aggregateHourlyChunk(ctx, d, nil, after); err != nil {
		t.Fatal(err)
	}
	hourlyReady.Store(true)
	got, err = DailyBlockedByDay(ctx, d, "", nil, 30, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	sameBlocked(t, "rollup", got, want)
	// A site filter takes the scan whatever the rollup knows; the seed's rows
	// carry no site, so a named site sees nothing.
	if got, err = DailyBlockedByDay(ctx, d, "shop.example", nil, 30, time.UTC); err != nil || len(got) != 0 {
		t.Fatalf("site-scoped: %d days, err %v", len(got), err)
	}
	// Day boundaries follow the operator's zone: the same rows, relabelled.
	tokyo := time.FixedZone("JST", 9*3600)
	got, err = DailyBlockedByDay(ctx, d, "", nil, 30, tokyo)
	if err != nil {
		t.Fatal(err)
	}
	sum := func(rows []DailyBlockedDay) (s DailyBlockedDay) {
		for _, r := range rows {
			s.Serves += r.Serves
			s.PoW += r.PoW
			s.Captcha += r.Captcha
			s.Abandon += r.Abandon
		}
		return s
	}
	wantAll := DailyBlockedDay{}
	for _, w := range want {
		wantAll.Serves += w.Serves
		wantAll.PoW += w.PoW
		wantAll.Captcha += w.Captcha
		wantAll.Abandon += w.Abandon
	}
	if s := sum(got); s != wantAll {
		t.Errorf("JST relabelling changed the totals: %+v, want %+v", s, wantAll)
	}
}
