package events

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The support lookup used to scan the whole table (`payload_json LIKE
// '%"ref":"..."%'`) -- 53 seconds against a 3.4M-row production database, on
// the path an operator walks while a blocked visitor waits.  Migration 0025
// exposes the id as an indexed generated column; this checks the query plan
// actually uses it, since the query still looks ordinary and a dropped index
// would silently restore the scan.
func TestRefLookupUsesTheIndex(t *testing.T) {
	d := refTestDB(t)
	var plan strings.Builder
	rows, err := d.Query(`EXPLAIN QUERY PLAN
	    SELECT id FROM unmask_event WHERE ref_id = ?`, "abc0123456789def")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var a, b, c int
		var detail string
		if err := rows.Scan(&a, &b, &c, &detail); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(detail + "\n")
	}
	got := plan.String()
	if !strings.Contains(got, "idx_unmask_event_ref") {
		t.Errorf("the ref lookup is not using its index -- this is the full-table scan again:\n%s", got)
	}
	if strings.Contains(got, "SCAN unmask_event") && !strings.Contains(got, "USING INDEX") {
		t.Errorf("query plan still scans the table:\n%s", got)
	}
}

// The column is filled by the writer, so it is only as good as that one line
// in prepareInsertArgs: miss it and every event goes in with ref_id NULL, the
// lookup keeps working, and it silently finds nothing forever.  The Go-side
// extractRef is the oracle -- the same function decorates rows on the way out,
// so writer and reader cannot disagree about what the ref is.
func TestWriterFillsTheRefColumn(t *testing.T) {
	d := refTestDB(t)
	seed := []map[string]any{
		{"ref": "abc0123456789def", "bt": "s1", "force_reason": "none"},
		{"bt": "s1"}, // no ref at all
		{"ref": "0000111122223333"},
		{"orig_path": "/a", "ref": "deadbeefdeadbeef", "rl": 0}, // ref mid-payload
	}
	for _, pl := range seed {
		if err := Insert(context.Background(), d, &Event{
			IPPacked: []byte{127, 0, 0, 1}, Phase: "serve", Payload: pl,
		}); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := d.Query(`SELECT payload_json, COALESCE(ref_id,'') FROM unmask_event ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	n := 0
	for rows.Next() {
		var payload, col string
		if err := rows.Scan(&payload, &col); err != nil {
			t.Fatal(err)
		}
		if want := extractRef(payload); col != want {
			t.Errorf("stored ref_id = %q but the reader extracts %q from %s", col, want, payload)
		}
		n++
	}
	if n != len(seed) {
		t.Fatalf("read %d rows, wrote %d", n, len(seed))
	}

	got, err := FetchByRef(context.Background(), d, "deadbeefdeadbeef", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Ref != "deadbeefdeadbeef" {
		t.Errorf("FetchByRef returned %d rows, want the one event carrying that ref", len(got))
	}
}

// Events stored before the upgrade keep ref_id NULL: the migration does not
// backfill, so they drop out of ref search rather than being rewritten.  That
// is the accepted trade -- refs are quoted within hours and those rows age out
// on the retention window -- and it is pinned here because the tempting "fix"
// is to OR the old payload_json LIKE back in as a fallback, which restores the
// full-table scan this whole change exists to remove.
func TestPreUpgradeRowsAreNotSearchedFor(t *testing.T) {
	d := refTestDB(t)
	// A row as it looks after the migration ran: payload intact, column NULL.
	if _, err := d.Exec(`INSERT INTO unmask_event (site,host,ip_address,phase,payload_json,date_created)
	    VALUES ('','',x'7f000001','serve','{"ref":"0ldref0000000000"}',datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	got, err := FetchByRef(context.Background(), d, "0ldref0000000000", 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("FetchByRef found %d pre-upgrade rows -- if a payload_json fallback came back, "+
			"so did the 53-second scan", len(got))
	}
}

func refTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "e.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return d
}
