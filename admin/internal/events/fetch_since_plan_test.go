package events

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestFetchSinceWalksABoundedRangeByRowid: with a site, phase or host filter,
// SQLite planned the live tail's poll on that filter's index -- every row of
// the site, phase or host, then a sort into id order -- whatever few rows
// were new.  A bounded range is walked by rowid, the filters checked on the
// way; an open range (the CLI tail) keeps the planner's choice.
func TestFetchSinceWalksABoundedRangeByRowid(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	for _, f := range []struct {
		name, site, phase string
		hosts             []string
	}{
		{"site", "busy.example", "", nil},
		{"phase", "", "serve", nil},
		{"site and phase", "busy.example", "serve", nil},
		{"hosts", "", "", []string{"a.example", "b.example"}},
		{"no filter", "", "", nil},
	} {
		stmt, args := fetchSinceSQL(d.Driver, 100, 200, f.site, f.phase, f.hosts, 100)
		plan := planOf(t, d, stmt, args...)
		if !strings.Contains(plan, "INTEGER PRIMARY KEY") || strings.Contains(plan, "TEMP B-TREE") {
			t.Errorf("%s, bounded: not a walk of the id range:\n%s", f.name, plan)
		}
		open, _ := fetchSinceSQL(d.Driver, 100, 0, f.site, f.phase, f.hosts, 100)
		if strings.Contains(open, "NOT INDEXED") {
			t.Errorf("%s, open range: pinned to the rowid walk, which can run the length of the table", f.name)
		}
	}
	mdb, _ := fetchSinceSQL(db.DriverMariaDB, 100, 200, "busy.example", "", nil, 100)
	if strings.Contains(mdb, "NOT INDEXED") {
		t.Error("MariaDB was given SQLite's NOT INDEXED")
	}
}

// TestFetchSinceStopsAtUpTo: the bound is inclusive, the anchor exclusive,
// and the filters still apply inside the range.
func TestFetchSinceStopsAtUpTo(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		site := "a.example"
		if i%2 == 1 {
			site = "b.example"
		}
		if _, err := d.Exec(`INSERT INTO unmask_event (site, host, ip_address, user_agent, phase, payload_json) VALUES (?, 'h', x'cb007101', 'UA', 'serve', '{}')`, site); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	rows, err := FetchSince(ctx, d, 2, 7, "b.example", "", nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	var ids []int64
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	if len(ids) != 2 || ids[0] != 4 || ids[1] != 6 {
		t.Fatalf("site b.example in (2, 7]: ids %v, want [4 6]", ids)
	}
	rows, err = FetchSince(ctx, d, 2, 0, "b.example", "", nil, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 4 {
		t.Fatalf("site b.example after 2, open range: %d rows, want 4", len(rows))
	}
}
