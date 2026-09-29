package dashboard

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// PruneHourly used to return at the first table that failed.  The tables are
// pruned in a fixed order, so one table in trouble ended the pruning of every
// table listed after it, run after run, and nothing said so: the tables
// behind it grew without bound.  Every table gets its turn now, and the run
// records which ones failed.
func TestPruneHourlyCarriesOnPastATableThatFails(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/p.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	nowHour := time.Now().Unix() / 3600
	nowMin := time.Now().Unix() / 60
	// Old rows in a table pruned EARLY in the order and in one pruned LATE.
	if _, err := d.Exec(`INSERT INTO unmask_traffic_hll (bucket_min, site, kind, sketch) VALUES (?,?,?,?)`,
		nowMin-1440*int64(hourlyKeep+5), "", "ip", []byte{0}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`INSERT INTO unmask_traffic_country_hourly (bucket_hour, site, country, kind, cnt) VALUES (?,?,?,?,?)`,
		nowHour-24*int64(hourlyKeep+5), "", "JP", "total", 1); err != nil {
		t.Fatal(err)
	}
	// And a table in between that cannot be pruned at all.
	if _, err := d.Exec(`DROP TABLE unmask_cookie_minute`); err != nil {
		t.Fatal(err)
	}

	err = PruneHourly(ctx, d)
	if err == nil || !strings.Contains(err.Error(), "unmask_cookie_minute") {
		t.Fatalf("err = %v, want it to name the table that failed", err)
	}
	for _, table := range []string{"unmask_traffic_hll", "unmask_traffic_country_hourly"} {
		var n int
		if err := d.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			t.Errorf("%s still holds its old row: the failure of another table stopped its prune", table)
		}
	}

	var rec db.AggregatePruneRecord
	ok, err := d.LoadMaintState(ctx, db.MaintAggregatePrune, &rec)
	if err != nil || !ok {
		t.Fatalf("no record of the run (%v)", err)
	}
	if rec.StartedAt == 0 || rec.CompletedAt != 0 {
		t.Errorf("a run with a failure is not a completed one: %+v", rec)
	}
	if _, named := rec.Failed["unmask_cookie_minute"]; !named || len(rec.Failed) != 1 {
		t.Errorf("failed = %v, want the one table", rec.Failed)
	}

	// Once the table is back the run completes, and the record says when.
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	if err := PruneHourly(ctx, d); err != nil {
		t.Fatalf("prune with every table present: %v", err)
	}
	rec = db.AggregatePruneRecord{}
	if _, err := d.LoadMaintState(ctx, db.MaintAggregatePrune, &rec); err != nil {
		t.Fatal(err)
	}
	if rec.CompletedAt == 0 || len(rec.Failed) != 0 {
		t.Errorf("after a clean run: %+v", rec)
	}
}
