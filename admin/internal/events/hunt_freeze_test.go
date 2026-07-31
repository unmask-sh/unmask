package events

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Offset paging over a table that is still being written shows the same rows
// twice: `?offset=100` means "skip the newest 100", so every event that arrives
// while the operator reads page 1 pushes one of those rows down past the mark,
// and page 2 opens with rows they have already seen.  On a busy node the
// arrival rate is high enough to repeat the entire page.
//
// The freeze pins paging to the rows that existed when it started.  This walks
// the reported scenario: read a page, let the log grow, read the next one.
func TestPagingDoesNotRepeatRowsWhenTheLogGrows(t *testing.T) {
	d := freezeTestDB(t)
	const pageSize = 10

	// A log with some history in it.
	base := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	insertAt := func(d *db.DB, n int, from time.Time) {
		t.Helper()
		for i := 0; i < n; i++ {
			if _, err := d.Exec(`INSERT INTO unmask_event
			    (site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
			     phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			    VALUES ('','','',0,?,'UA','','',0,'serve',0,0,'','',?,?)`,
				[]byte{10, 0, 0, 1}, fmt.Sprintf(`{"ref":"%016x"}`, i),
				from.Add(time.Duration(i)*time.Second).Format(eventTimeFormat)); err != nil {
				t.Fatal(err)
			}
		}
	}
	insertAt(d, 40, base)

	page := func(ctx context.Context, offset int) []Row {
		t.Helper()
		rows, err := FetchPaged(ctx, d, "", "", "", "", "", "", "", nil, 0, pageSize, offset)
		if err != nil {
			t.Fatal(err)
		}
		return rows
	}
	ids := func(rows []Row) map[int64]bool {
		out := map[int64]bool{}
		for _, r := range rows {
			out[r.ID] = true
		}
		return out
	}

	// The operator opens the hunt page.  The freeze is taken here.
	freezeAt, err := MaxEventID(context.Background(), d)
	if err != nil {
		t.Fatal(err)
	}
	frozen := WithHuntFreeze(context.Background(), freezeAt)
	first := page(frozen, 0)
	if len(first) != pageSize {
		t.Fatalf("page 1 returned %d rows, want %d", len(first), pageSize)
	}

	// They read it.  Traffic keeps coming: 15 new events, more than a page.
	insertAt(d, 15, base.Add(time.Hour))

	// They press next.
	second := page(frozen, pageSize)
	seen := ids(first)
	repeated := 0
	for _, r := range second {
		if seen[r.ID] {
			repeated++
		}
	}
	if repeated > 0 {
		t.Errorf("page 2 repeats %d of the %d rows already shown on page 1", repeated, len(second))
	}
	for _, r := range second {
		if r.ID > freezeAt {
			t.Errorf("row %d arrived after paging started and must not appear mid-sequence", r.ID)
		}
	}

	// And the bug is real without the freeze -- otherwise this test proves
	// nothing about why the freeze is there.
	live := page(context.Background(), pageSize)
	liveRepeated := 0
	for _, r := range live {
		if seen[r.ID] {
			liveRepeated++
		}
	}
	if liveRepeated == 0 {
		t.Error("precondition: unfrozen paging was expected to repeat rows here; " +
			"if it no longer does, this test has stopped covering the bug")
	}
}

// A freeze must not hide history: everything stored before it stays reachable
// by paging to the end, so an operator hunting an old event still finds it.
func TestFreezeKeepsTheWholeHistoryReachable(t *testing.T) {
	d := freezeTestDB(t)
	base := time.Date(2026, 7, 31, 12, 0, 0, 0, time.UTC)
	for i := 0; i < 25; i++ {
		if _, err := d.Exec(`INSERT INTO unmask_event
		    (site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
		     phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
		    VALUES ('','','',0,?,'UA','','',0,'serve',0,0,'','','{}',?)`,
			[]byte{10, 0, 0, 1},
			base.Add(time.Duration(i)*time.Second).Format(eventTimeFormat)); err != nil {
			t.Fatal(err)
		}
	}
	freezeAt, _ := MaxEventID(context.Background(), d)
	ctx := WithHuntFreeze(context.Background(), freezeAt)

	got := map[int64]bool{}
	for offset := 0; offset < 100; offset += 10 {
		rows, err := FetchPaged(ctx, d, "", "", "", "", "", "", "", nil, 0, 10, offset)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) == 0 {
			break
		}
		for _, r := range rows {
			if got[r.ID] {
				t.Errorf("row %d handed out twice while paging a frozen view", r.ID)
			}
			got[r.ID] = true
		}
	}
	if len(got) != 25 {
		t.Errorf("paged through %d rows, want all 25 stored before the freeze", len(got))
	}
}

func freezeTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(t.TempDir(), "f.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return d
}
