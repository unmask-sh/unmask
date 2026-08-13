package dashboard

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The stats page reaches back only as far as BOTH its sources do.
//
// Its summary figures and per-day series read unmask_aggregate_hourly, pruned
// on a fixed window that deliberately ignores events_retention_days; its
// funnel / country / flag cards read raw unmask_event, which follows it.  The
// range picker used to ask only how old the oldest EVENT was, so an install
// keeping 90 days of raw events offered "90d" while the aggregates held about
// a month -- and the totals under that label were a month of data wearing a
// quarter's name, with nothing on screen to say so.
//
// OldestAggregateTS is the second bound.  These pin what it reports, since the
// picker's arithmetic is only as honest as this number.
func TestOldestAggregateTSBoundsTheRange(t *testing.T) {
	d := openBoundTestDB(t)
	ctx := context.Background()

	// Nothing aggregated yet: 0, so the caller can tell "no history" from "one
	// hour of history" and decline to offer a long range on either.
	if ts, err := OldestAggregateTS(ctx, d); err != nil || ts != 0 {
		t.Fatalf("empty aggregate: got ts=%d err=%v, want 0", ts, err)
	}

	// Two buckets, 40 and 5 days back.  The oldest is what bounds the page.
	now := time.Now().UTC()
	for _, back := range []int{5, 40} {
		bucket := now.Add(-time.Duration(back) * 24 * time.Hour).Format("2006-01-02 15")
		if _, err := d.Exec(
			`INSERT INTO unmask_aggregate_hourly (bucket_hour, bucket_kind, bucket_key, cnt)
			 VALUES (?, 'fnl', 'k', 1)`, bucket); err != nil {
			t.Fatalf("seed bucket %s: %v", bucket, err)
		}
	}
	ts, err := OldestAggregateTS(ctx, d)
	if err != nil {
		t.Fatalf("OldestAggregateTS: %v", err)
	}
	gotDays := (now.Unix() - ts) / 86400
	if gotDays != 40 {
		t.Errorf("oldest aggregate is %d days back, want 40 -- the picker sizes the offered "+
			"ranges off this, so a wrong answer offers a span the page cannot fill", gotDays)
	}
}

// The bound the handler applies: the LATER of the two oldest marks, because a
// later mark is a shorter reach.  Kept here beside the query it pairs with so
// the direction cannot be flipped without a test noticing -- getting it
// backwards would offer the LONGER of the two, which is exactly the bug.
func TestShorterOfTwoHistoriesWins(t *testing.T) {
	now := time.Now().Unix()
	events := now - 90*86400 // 90 days of raw events
	agg := now - 32*86400    // but only 32 days of aggregates

	oldest := int64(0)
	if events > 0 && agg > 0 {
		oldest = events
		if agg > oldest {
			oldest = agg
		}
	}
	if days := (now - oldest) / 86400; days != 32 {
		t.Errorf("bound = %d days, want 32 (the aggregate's reach, not the event log's)", days)
	}

	// Either source missing means no long range at all: half a page of real
	// numbers beside half a page of blanks is not a range the page can serve.
	for _, c := range []struct{ ev, ag int64 }{{events, 0}, {0, agg}, {0, 0}} {
		oldest := int64(0)
		if c.ev > 0 && c.ag > 0 {
			oldest = c.ev
			if c.ag > oldest {
				oldest = c.ag
			}
		}
		if oldest != 0 {
			t.Errorf("events=%d agg=%d produced a bound of %d, want 0", c.ev, c.ag, oldest)
		}
	}
}

func openBoundTestDB(t *testing.T) *db.DB {
	t.Helper()
	tmp, err := os.MkdirTemp("", "boundtest-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(tmp) })
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(tmp, "t.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return d
}
