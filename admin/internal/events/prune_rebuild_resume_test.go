package events

import (
	"context"
	"testing"
	"time"
)

// A rebuild that keeps no row went on with ids from 1: the drop took the
// sqlite_sequence row with it, and the hourly aggregate's cursor -- past the
// old ids -- skipped every new row while it reported itself caught up.  The
// counter goes on from where the old table was.
func TestRebuildKeepingNothingKeepsTheIDs(t *testing.T) {
	d := pruneTestDB(t)
	seedEvents(t, d, 30, time.Now().Add(-20*24*time.Hour))
	var oldMax int64
	if err := d.QueryRow(`SELECT MAX(id) FROM unmask_event`).Scan(&oldMax); err != nil {
		t.Fatal(err)
	}
	res, err := RebuildEvents(context.Background(), d, 7, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Kept != 0 {
		t.Fatalf("kept %d", res.Kept)
	}
	seedEvents(t, d, 1, time.Now())
	var id int64
	if err := d.QueryRow(`SELECT MAX(id) FROM unmask_event`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	if id <= oldMax {
		t.Errorf("the first id after the rebuild is %d, at or under the old %d", id, oldMax)
	}
}

// A rebuild stopped after its swap left the new table without some of its
// indexes, for good: the next start does not create them, and the next
// rebuild read the table as it found it.  The swap records the list, the
// next rebuild works it first, and doctor's check sees it meanwhile.
func TestInterruptedRebuildIndexesAreCreatedNextTime(t *testing.T) {
	d := pruneTestDB(t)
	ctx := context.Background()
	seedEvents(t, d, 20, time.Now().Add(-time.Hour))
	if _, err := RebuildEvents(ctx, d, 7, nil); err != nil {
		t.Fatal(err)
	}
	if p, err := PendingRebuildIndexes(ctx, d); err != nil || len(p) != 0 {
		t.Fatalf("a finished rebuild left a list: %v %v", p, err)
	}
	// The state a stop between the swap and the last index leaves.
	var name, sqlText string
	if err := d.QueryRow(`SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='unmask_event' AND sql IS NOT NULL ORDER BY name LIMIT 1`).Scan(&name, &sqlText); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{`DROP INDEX ` + name, rebuildPendingCreate} {
		if _, err := d.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := d.Exec(`INSERT INTO `+rebuildPendingTable+`(name, sql) VALUES (?, ?)`, name, sqlText); err != nil {
		t.Fatal(err)
	}
	if p, _ := PendingRebuildIndexes(ctx, d); len(p) != 1 || p[0][0] != name {
		t.Fatalf("the list after a stop: %v", p)
	}
	if _, err := RebuildEvents(ctx, d, 7, nil); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?`, name).Scan(&n); err != nil || n != 1 {
		t.Errorf("index %s after the next rebuild: %d (%v)", name, n, err)
	}
	if p, _ := PendingRebuildIndexes(ctx, d); len(p) != 0 {
		t.Errorf("the list is still there: %v", p)
	}
}
