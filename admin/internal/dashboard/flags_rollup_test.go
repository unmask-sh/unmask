package dashboard

import (
	"context"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/events"
)

// The hourly rollup keys a count and a sketch by a load's flags.  Rows that
// were written before the beacon held the value to its known bits can carry
// any number; counted as they are, each is a rollup row and a 1 KiB sketch
// kept for a month.  The rollup counts the known bits.
func TestRollupCountsTheKnownFlagBits(t *testing.T) {
	d := openTestDB(t)
	defer d.Close()
	ctx := context.Background()
	hourlyReady.Store(false)
	for i := 0; i < 200; i++ {
		if err := events.Insert(ctx, d, &events.Event{Site: "example.org", Host: "h", IPPacked: []byte{198, 51, 100, 7},
			UserAgent: "x", Phase: "load", Flags: 100000 + i, Payload: map[string]any{"bt": "t"}}); err != nil {
			t.Fatal(err)
		}
	}
	if err := AggregateHourly(ctx, d, nil); err != nil {
		t.Fatal(err)
	}
	var keys, sketches int
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_aggregate_hourly WHERE bucket_kind = ?`, hkFlags).Scan(&keys); err != nil {
		t.Fatal(err)
	}
	if err := d.QueryRow(`SELECT COUNT(*) FROM unmask_aggregate_hll WHERE bucket_kind = ?`, hkFlagsIP).Scan(&sketches); err != nil {
		t.Fatal(err)
	}
	// 200 consecutive numbers hold at most the 32 values of five bits.
	if keys > 32 || sketches > 32 {
		t.Errorf("200 loads with made-up flags became %d count rows and %d sketches; five bits have 32 values", keys, sketches)
	}
	if keys == 0 {
		t.Error("no flags row was written at all")
	}
}
