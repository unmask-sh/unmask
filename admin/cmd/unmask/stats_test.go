package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func TestParseLookback(t *testing.T) {
	ok := []struct {
		in   string
		want int
	}{
		{"90m", 90},
		{"24h", 24 * 60},
		{"7d", 7 * 24 * 60},
		{"1d", 24 * 60},
		{" 12h ", 12 * 60},
		{"30s", 1}, // sub-minute rounds up rather than becoming a zero-length window
	}
	for _, c := range ok {
		got, err := parseLookback(c.in)
		if err != nil {
			t.Errorf("parseLookback(%q): %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("parseLookback(%q) = %d minutes, want %d", c.in, got, c.want)
		}
	}
	// A window that cannot be honoured must be refused, not silently turned
	// into "everything" or "nothing" -- both would be reported as fact.
	for _, bad := range []string{"", "3x", "-2h", "0d", "0h", "d", "seven days"} {
		if got, err := parseLookback(bad); err == nil {
			t.Errorf("parseLookback(%q) = %d, want an error", bad, got)
		}
	}
}

func TestSelectStatsKinds(t *testing.T) {
	all, err := selectStatsKinds("all")
	if err != nil {
		t.Fatalf("all: %v", err)
	}
	if len(all) != len(statsKinds) {
		t.Errorf("-kind all selected %d of %d reports", len(all), len(statsKinds))
	}
	for _, k := range statsKinds {
		got, err := selectStatsKinds(k.name)
		if err != nil {
			t.Errorf("-kind %s: %v", k.name, err)
			continue
		}
		if len(got) != 1 || got[0].name != k.name {
			t.Errorf("-kind %s selected %v", k.name, got)
		}
	}
	if _, err := selectStatsKinds("nope"); err == nil {
		t.Error("an unknown -kind was accepted")
	} else if !strings.Contains(err.Error(), "traffic") {
		t.Errorf("the error should list the valid kinds, got %q", err)
	}
}

// A share of an unknown total is not 0%.  Printing "0.0%" next to a count
// would state a proportion nobody measured.
func TestShareOfNothingIsBlankNotZero(t *testing.T) {
	if got := share(0, 0); got != "" {
		t.Errorf("share(0,0) = %q, want empty", got)
	}
	if got := share(5, 0); got != "" {
		t.Errorf("share(5,0) = %q, want empty", got)
	}
	if got := share(1, 4); got != "25.0%" {
		t.Errorf("share(1,4) = %q, want 25.0%%", got)
	}
}

// Under -tsv the stream has to stay parseable: one record per line, the report
// name first, and commentary out of the way on stderr.
func TestTSVOutputIsRecordsOnly(t *testing.T) {
	var out bytes.Buffer
	w := &statsWriter{w: &out, tsv: true}
	w.section("ip", "top source addresses", "address", "events", "")
	w.row("ip", "192.0.2.7", "12", "")
	w.note("cut off at -limit 1; there may be more")
	w.end()

	got := out.String()
	lines := strings.Split(strings.TrimRight(got, "\n"), "\n")
	if len(lines) != 1 {
		t.Fatalf("expected exactly one record on stdout, got %d:\n%s", len(lines), got)
	}
	if lines[0] != "ip\t192.0.2.7\t12" {
		t.Errorf("record = %q, want %q", lines[0], "ip\t192.0.2.7\t12")
	}
	if strings.Contains(got, "cut off") {
		t.Error("a note leaked into the TSV stream -- a parser would read it as a record")
	}
	if strings.Contains(got, "address") {
		t.Error("a heading leaked into the TSV stream")
	}
}

// The human form keeps its heading and shows the note inline.
func TestTableOutputKeepsHeadingsAndNotes(t *testing.T) {
	var out bytes.Buffer
	w := &statsWriter{w: &out, tsv: false}
	w.section("phase", "challenge events by phase", "phase", "events", "share")
	w.row("phase", "serve", "10", "100.0%")
	w.note("no events in this window")
	w.end()

	got := out.String()
	for _, want := range []string{"== phase --", "phase", "events", "share", "serve", "(no events in this window)"} {
		if !strings.Contains(got, want) {
			t.Errorf("table output missing %q:\n%s", want, got)
		}
	}
}

// Every report has to survive contact with a real database: these queries are
// assembled as SQL strings, so a typo is invisible until something runs them.
// Seeds one event and one counter row, then runs all of them.
func TestEveryReportRunsAgainstSQLite(t *testing.T) {
	d := openStatsTestDB(t)
	if _, err := d.Exec(
		`INSERT INTO unmask_event
		   (site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id,
		    phase, flags, reload_count, cookie_bv, cookie_br, payload_json, date_created)
		 VALUES ('example.com','','','','192.0.2.7','curl/8.0','t13d_abc','bot_curl',0,
		         'serve',0,0,'','','{}',datetime('now','-10 minutes'))`); err != nil {
		t.Fatalf("seed event: %v", err)
	}
	if _, err := d.Exec(
		`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt)
		 VALUES (strftime('%s','now')/60 - 5, 'example.com', 'total', 3)`); err != nil {
		t.Fatalf("seed counter: %v", err)
	}

	for _, k := range statsKinds {
		t.Run(k.name, func(t *testing.T) {
			var out bytes.Buffer
			w := &statsWriter{w: &out, tsv: true}
			err := k.run(context.Background(), w, d, statsOpts{minutes: 60, limit: 10})
			if err != nil {
				t.Fatalf("%s: %v", k.name, err)
			}
			if !strings.HasPrefix(out.String(), k.name+"\t") {
				t.Errorf("%s produced no record for the seeded row:\n%s", k.name, out.String())
			}
		})
	}
}

// The site filter has to reach the queries that claim to honour it: a filter
// that silently matches everything is worse than no filter, because the
// numbers look scoped.
func TestSiteFilterExcludesOtherSites(t *testing.T) {
	d := openStatsTestDB(t)
	for _, site := range []string{"a.example", "b.example"} {
		if _, err := d.Exec(
			`INSERT INTO unmask_event
			   (site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id,
			    phase, flags, reload_count, cookie_bv, cookie_br, payload_json, date_created)
			 VALUES (?,'','','','192.0.2.7','curl/8.0','t13d_abc','',0,
			         'serve',0,0,'','','{}',datetime('now','-10 minutes'))`, site); err != nil {
			t.Fatalf("seed %s: %v", site, err)
		}
	}
	var out bytes.Buffer
	w := &statsWriter{w: &out, tsv: true}
	if err := statsPhase(context.Background(), w, d, statsOpts{minutes: 60, site: "a.example", limit: 10}); err != nil {
		t.Fatalf("phase: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "phase\tserve\t1\t100.0%" {
		t.Errorf("site filter did not scope the count, got %q (want 1 event, not 2)", got)
	}

	// The rankings go through a different code path (the events package), and
	// a -site that quietly fails to apply there would still print a heading
	// and plausible numbers -- install-wide ones.
	for _, k := range []struct {
		name string
		run  func(context.Context, *statsWriter, *db.DB, statsOpts) error
	}{{"ip", statsTopIP}, {"ua", statsTopUA}, {"ja4", statsTopJA4}} {
		var rout bytes.Buffer
		rw := &statsWriter{w: &rout, tsv: true}
		if err := k.run(context.Background(), rw, d, statsOpts{minutes: 60, site: "a.example", limit: 10}); err != nil {
			t.Fatalf("%s: %v", k.name, err)
		}
		// Both events share one IP / UA / JA4, so an unscoped ranking reports
		// 2 against the single row the filter should leave.
		if got := strings.TrimSpace(rout.String()); !strings.HasSuffix(got, "\t1") {
			t.Errorf("%s ranking ignored -site: %q (want a count of 1)", k.name, got)
		}
	}
}

// An apostrophe in -site must not be able to close the quoted literal the
// query builds.  Operator-controlled input, but the shape is worth pinning.
func TestSiteFilterNeutralisesQuotes(t *testing.T) {
	d := openStatsTestDB(t)
	var out bytes.Buffer
	w := &statsWriter{w: &out, tsv: true}
	// Would be a syntax error if the quote survived into the statement.
	if err := statsPhase(context.Background(), w, d, statsOpts{minutes: 60, site: `x' OR '1'='1`, limit: 10}); err != nil {
		t.Fatalf("a quoted site broke the query: %v", err)
	}
	if strings.TrimSpace(out.String()) != "" {
		t.Errorf("the injected condition matched rows: %q", out.String())
	}
}

func openStatsTestDB(t *testing.T) *db.DB {
	t.Helper()
	tmp := t.TempDir()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(tmp, "stats.db")})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return d
}

// The command must not write.  An operator reaches for it precisely when the
// database is in a state they do not want to disturb, and it is run on live
// production hosts.
func TestStatsDoesNotModifyTheDatabase(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "ro.db")
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: path})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if _, err := d.Exec(
		`INSERT INTO unmask_event
		   (site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id,
		    phase, flags, reload_count, cookie_bv, cookie_br, payload_json, date_created)
		 VALUES ('example.com','','','','192.0.2.7','curl/8.0','t13d','',0,
		         'serve',0,0,'','','{}',datetime('now','-10 minutes'))`); err != nil {
		t.Fatalf("seed: %v", err)
	}
	d.Close()

	before := dbBytes(t, path)
	d2, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: path})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	for _, k := range statsKinds {
		var out bytes.Buffer
		w := &statsWriter{w: &out, tsv: true}
		if err := k.run(context.Background(), w, d2, statsOpts{minutes: 60, limit: 10}); err != nil {
			t.Fatalf("%s: %v", k.name, err)
		}
	}
	d2.Close()

	if after := dbBytes(t, path); !bytes.Equal(before, after) {
		t.Errorf("the database changed after running the reports (%d -> %d bytes)", len(before), len(after))
	}
}

func dbBytes(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return b
}
