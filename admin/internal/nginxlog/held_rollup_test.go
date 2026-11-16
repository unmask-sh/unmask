package nginxlog

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/db"
)

// Review finding D9, for the access log's counts.  The dashboard's traffic
// rollups (distinct addresses per site and install-wide, the pass counts,
// the country counts, the challenged and passed addresses) fold an hour once
// and move their cursor past it, and they take an hour two back as settled.
// The minute buckets counted during a hold of the database's writes stay in
// the reader's memory until the first flush after it, and the rollups and
// the reader's flush each run on a tick of their own.  After a hold longer
// than the settle horizon, a pass that came before the flush folded the
// hours of the hold without their counts, the flush then wrote them into
// hours the cursors had passed, and every card that reads a folded hour from
// the rollup stayed short of them.
func TestTrafficRollupsWaitForCountsHeldThroughAHold(t *testing.T) {
	d := handoverDB(t)
	r := Start("", d)
	t.Cleanup(r.Close)
	ctx := context.Background()
	hour := time.Now().Unix()/3600 - 3
	date := time.Unix(hour*3600, 0).UTC().Format("2006-01-02")

	// What the reader counted in a minute of the hold, three hours back: five
	// addresses, every one challenged, two of them back on a PoW pass.
	d.HoldWrites(true)
	b := &bucket{total: 5, kinds: map[string]int{"challenge_served": 3, "pow": 2}}
	for i := 1; i <= 5; i++ {
		ip := []byte(fmt.Sprintf("192.0.2.%d", i))
		b.ipAll.Add(ip)
		b.ipChal.Add(ip)
		if i <= 2 {
			b.ipPass.Add(ip)
		}
	}
	r.mu.Lock()
	r.buckets[bucketKey{minute: hour*60 + 10, site: "held.example"}] = b
	r.countryHourlyBuckets[countryHourKey{hour: hour, site: "held.example"}] = &countryHourBucket{total: 5, kinds: map[string]int{"challenge_served": 3, "pow": 2}}
	r.mu.Unlock()
	r.flushOnce(false) // stands back while the writes are held

	// The hold ends, and the rollups' tick comes before the reader's flush.
	runTrafficRollups(t, d)
	d.HoldWrites(false)
	r.flushOnce(false)
	runTrafficRollups(t, d)

	for _, site := range []string{"", "held.example"} {
		days, err := dashboard.DailyUniqueIPs(ctx, d, site, 1, time.UTC)
		if err != nil {
			t.Fatal(err)
		}
		var got int64
		for _, day := range days {
			if day.Date == date {
				got = day.UniqIPs
			}
		}
		if got != 5 {
			t.Errorf("distinct addresses on %s (site %q) = %d, want the 5 of the hold", date, site, got)
		}
	}
	_, totals, err := dashboard.DailyPassByDay(ctx, d, "", nil, 1, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	var reqs int
	for _, day := range totals {
		if day.Date == date {
			reqs = day.Req
		}
	}
	if reqs != 5 {
		t.Errorf("requests on %s = %d, want the 5 of the hold", date, reqs)
	}
	byCountry, err := dashboard.DailyPassByCountry(ctx, d, "", 1, time.UTC)
	if err != nil {
		t.Fatal(err)
	}
	reqs = 0
	for _, row := range byCountry {
		if row.Date == date {
			reqs += row.Req
		}
	}
	if reqs != 5 {
		t.Errorf("requests by country on %s = %d, want the 5 of the hold", date, reqs)
	}
	total, blocked, _, err := dashboard.TrafficUniqueAgg(ctx, d, 6*60)
	if err != nil {
		t.Fatal(err)
	}
	if total != 5 || blocked != 3 {
		t.Errorf("non-human share: %d addresses, %d blocked; want 5 and 3", total, blocked)
	}
}

// runTrafficRollups is the access-log half of the daemon's rollup pass.
func runTrafficRollups(t *testing.T, d *db.DB) {
	t.Helper()
	ctx := context.Background()
	for name, fn := range map[string]func(context.Context, *db.DB) error{
		"traffic":                  dashboard.RollupTrafficHLL,
		"install-wide":             dashboard.RollupInstallWideHourly,
		"install-wide country":     dashboard.RollupInstallWideCountry,
		"install-wide blocked ips": dashboard.RollupInstallWideBlocked,
	} {
		if err := fn(ctx, d); err != nil {
			t.Fatalf("%s rollup: %v", name, err)
		}
	}
}

// A flush takes its counts out of memory and then writes them, the backlog of
// a long hold in one transaction that can take minutes.  Meanwhile they are
// neither in memory nor in the database, and a rollup pass in that moment
// must still see them kept.  Another writer's transaction holds the flush at
// its first statement for the look.
func TestCountsOnTheirWayToTheDatabaseAreStillUnwritten(t *testing.T) {
	d := handoverDB(t)
	r := Start("", d)
	t.Cleanup(r.Close)
	ctx := context.Background()
	minute := (time.Now().Unix()/3600-3)*60 + 10
	r.mu.Lock()
	r.buckets[bucketKey{minute: minute, site: "held.example"}] = &bucket{total: 1, kinds: map[string]int{}}
	r.mu.Unlock()

	lock, err := d.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Close() })
	if _, err := lock.ExecContext(ctx, "BEGIN IMMEDIATE"); err != nil {
		t.Fatal(err)
	}
	flushed := make(chan struct{})
	go func() {
		defer close(flushed)
		r.flushOnce(false)
	}()
	waitFor(t, "the flush to take the counts out", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.buckets) == 0
	})
	if at, ok := d.OldestUnwritten(db.UnwrittenAccessLog); !ok || at.Unix() != minute*60 {
		t.Errorf("counts on their way to the database: kept since %v (%v), want the minute at %v", at, ok, time.Unix(minute*60, 0))
	}
	if _, err := lock.ExecContext(ctx, "ROLLBACK"); err != nil {
		t.Fatal(err)
	}
	<-flushed

	var n int
	if err := d.QueryRow(`SELECT COALESCE(SUM(cnt), 0) FROM unmask_cookie_minute WHERE bucket_min = ? AND kind = 'total'`, minute).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("the flush wrote %d requests for the minute, want 1", n)
	}
	if at, ok := d.OldestUnwritten(db.UnwrittenAccessLog); ok {
		t.Errorf("written, and still kept since %v", at)
	}
}
