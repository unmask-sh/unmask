package handlers

import (
	"context"
	"database/sql"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// openMigratedDB opens a SQLite database with every migration applied -- the
// schema a production install has, indexes included -- where newTestHandler's
// hand-written schema stops at the indexes the handlers pin by name.
func openMigratedDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dbTempDir(t), "migrated.sqlite")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return d
}

// The partial index of migration 0039 changes how fast the Community Bans
// impact figure reads, never what it answers: the same count and distinct
// addresses come from the index as from the table.  With the index the query
// is pinned to it -- SQLite refuses a pin it cannot use, so a query that stops
// naming the index's terms fails here -- and without it (MariaDB, or a large
// install whose operator has not applied the schema update yet) the query is
// the scan it was.  A payload that is not JSON fails neither its write nor
// the read.
func TestCommunityHitsIndexAnswersAsTheTable(t *testing.T) {
	d := openMigratedDB(t)
	ctx := context.Background()
	if err := d.RefreshIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	if !d.HasIndex(db.IdxEventCommunityBans) {
		t.Fatalf("migration 0039 did not build %s", db.IdxEventCommunityBans)
	}

	add := func(ip byte, phase, payload string, minutesAgo int) {
		t.Helper()
		var p sql.NullString
		if payload != "" {
			p = sql.NullString{String: payload, Valid: true}
		}
		if _, err := d.Exec(`INSERT INTO unmask_event
			(site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id,
			 phase, flags, reload_count, cookie_bv, cookie_br, payload_json, date_created)
			VALUES ('default', 'node1', 'https', 443, ?, 'UA', 't13d1516h2_aaaaaaaaaaaa_bbbbbbbbbbbb', 'ok', 0,
			        ?, 0, 0, '', '', ?, datetime('now', ?))`,
			[]byte{10, 0, 0, ip}, phase, p, "-"+strconv.Itoa(minutesAgo)+" minutes"); err != nil {
			t.Fatalf("insert %s for .%d: %v", phase, ip, err)
		}
	}
	// Counted: three serves the feed sent to a challenge, from two addresses,
	// inside the window -- the HTML page's and the JSON answer's alike.
	add(1, "serve", `{"force_reason":"community_bans","ch_mode":"pow_then_captcha","rl":0}`, 10)
	add(1, "serve", `{"force_reason":"community_bans","non_html_client":1}`, 20)
	add(2, "serve", `{"force_reason":"community_bans"}`, 30)
	// Not counted: outside the window; another reason; the word elsewhere in
	// the payload; a load, not a serve; no payload; a payload that is not
	// JSON (kept out of the index, not a failed write).
	add(3, "serve", `{"force_reason":"community_bans"}`, 31*24*60)
	add(4, "serve", `{"force_reason":"banned","ban":1}`, 5)
	add(5, "serve", `{"force_reason":"none","orig_path":"/community_bans/"}`, 5)
	add(6, "load", `{"force_reason":"community_bans"}`, 5)
	add(7, "serve", "", 5)
	add(8, "serve", `{"force_reason":`, 5)
	want := communityHitStats{Count: 3, UniqueIP: 2}

	q := communityHitsSQL(d)
	if !strings.Contains(q, " INDEXED BY "+db.IdxEventCommunityBans) {
		t.Fatalf("with the index built the query is not pinned to it:\n%s", q)
	}
	if strings.Contains(q, "LIKE") {
		t.Errorf("with the index the query still carries the LIKE prefilter, which reads the table for every indexed row:\n%s", q)
	}
	if plan := queryPlan(t, d, q); !strings.Contains(plan, db.IdxEventCommunityBans) {
		t.Errorf("the plan does not use the index:\n%s", plan)
	}
	got, err := communityBansHits30d(ctx, d)
	if err != nil {
		t.Fatalf("with the index: %v", err)
	}
	if got != want {
		t.Errorf("with the index: got %+v, want %+v", got, want)
	}

	if _, err := d.ExecContext(ctx, `DROP INDEX `+db.IdxEventCommunityBans); err != nil {
		t.Fatal(err)
	}
	if err := d.RefreshIndexes(ctx); err != nil {
		t.Fatal(err)
	}
	q = communityHitsSQL(d)
	if strings.Contains(q, "INDEXED BY") {
		t.Fatalf("without the index the query still pins one:\n%s", q)
	}
	if !strings.Contains(q, "LIKE '%community_bans%'") {
		t.Errorf("without the index the query lost its LIKE prefilter:\n%s", q)
	}
	got, err = communityBansHits30d(ctx, d)
	if err != nil {
		t.Fatalf("without the index: %v", err)
	}
	if got != want {
		t.Errorf("without the index: got %+v, want %+v", got, want)
	}
}

// queryPlan is SQLite's EXPLAIN QUERY PLAN for a query, one detail per line.
func queryPlan(t *testing.T, d *db.DB, q string) string {
	t.Helper()
	rows, err := d.QueryContext(context.Background(), "EXPLAIN QUERY PLAN "+q)
	if err != nil {
		t.Fatalf("explain: %v", err)
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var id, parent, notUsed int
		var detail string
		if err := rows.Scan(&id, &parent, &notUsed, &detail); err != nil {
			t.Fatalf("explain scan: %v", err)
		}
		lines = append(lines, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return strings.Join(lines, "\n")
}
