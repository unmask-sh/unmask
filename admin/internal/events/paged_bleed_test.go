package events

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func bleedTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "b.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return d
}

func insertPlain(t *testing.T, d *db.DB, n int, payload func(i int) string) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := d.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
			 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','https',443,x'7f000001','ua','','',0,'serve',0,0,'','',?,datetime('now'))`,
			payload(i)); err != nil {
			t.Fatal(err)
		}
	}
}

// The n=1000 page used to collapse to 100 rows: FetchPaged reset any limit
// over 1000 back to 100, and the bleed pushed the request past the cap the
// moment it existed.  Out-of-range limits must clamp to the bound instead.
func TestFetchPagedLimitClampsInsteadOfResetting(t *testing.T) {
	d := bleedTestDB(t)
	insertPlain(t, d, maxFetchRows+50, func(i int) string { return "{}" })

	rows, err := FetchPaged(context.Background(), d, "", "", "", "", "", "", "", nil, 1440, 1000+2*SessionBleed, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1000+2*SessionBleed {
		t.Errorf("full-page-plus-bleed read returned %d rows, want %d", len(rows), 1000+2*SessionBleed)
	}
	rows, err = FetchPaged(context.Background(), d, "", "", "", "", "", "", "", nil, 1440, maxFetchRows+10, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != maxFetchRows {
		t.Errorf("over-cap limit should clamp to %d, got %d", maxFetchRows, len(rows))
	}
}

// A session whose rows are interleaved far apart (here 60 rows of unrelated
// traffic between its two events -- past the old 8-row bleed) must still come
// back whole for the page that owns its newest row, and contribute nothing to
// the page that owns neither.
func TestFetchPagedWithBleedCompletesInterleavedSessions(t *testing.T) {
	d := bleedTestDB(t)
	// Layout (newest-first order after insert): 30 filler, tok tail, 60
	// filler, tok head, 30 filler.  The page window (limit 50, offset 0)
	// contains the head; the tail sits ~60 rows past the window's end.
	insertPlain(t, d, 30, func(int) string { return "{}" })
	insertPlain(t, d, 1, func(int) string { return `{"bt":"tok-spread"}` })
	insertPlain(t, d, 60, func(int) string { return "{}" })
	insertPlain(t, d, 1, func(int) string { return `{"bt":"tok-spread"}` })
	insertPlain(t, d, 30, func(int) string { return "{}" })

	rows, windowStart, err := FetchPagedWithBleed(context.Background(), d, "", "", "", "", "", "", "", nil, 1440, 50, 0)
	if err != nil {
		t.Fatal(err)
	}
	if windowStart != 0 {
		t.Errorf("first page windowStart = %d, want 0", windowStart)
	}
	count := 0
	for _, r := range rows {
		if r.BeaconToken == "tok-spread" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("the fetched slice carries %d rows of the interleaved session, want both (bleed too small?)", count)
	}
}
