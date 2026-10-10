package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func TestRateLimitedServes(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/r.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	hourlyReady.Store(false)
	t.Cleanup(func() { hourlyReady.Store(false) })

	// Before the rollup's first pass: no figure, no error.
	if n, known, err := RateLimitedServes(ctx, d, "", nil, 24); err != nil || known || n != 0 {
		t.Errorf("not ready: n=%d known=%v err=%v", n, known, err)
	}
	hourlyReady.Store(true)
	// bucket_hour is the hour as UTC "YYYY-MM-DD HH" text, the form the window
	// clause compares against.
	h := time.Now().UTC().Truncate(time.Hour)
	for _, row := range []struct {
		hour time.Time
		cnt  int
	}{{h, 5}, {h.Add(-time.Hour), 7}, {h.Add(-48 * time.Hour), 100}} {
		if _, err := d.ExecContext(ctx, `INSERT INTO unmask_aggregate_hourly (bucket_kind, bucket_hour, bucket_key, cnt) VALUES (?, ?, ?, ?)`, hkServeRL, row.hour.Format("2006-01-02 15"), "1|bot_x", row.cnt); err != nil {
			t.Fatal(err)
		}
	}
	n, known, err := RateLimitedServes(ctx, d, "", nil, 24)
	if err != nil || !known || n != 12 {
		t.Errorf("24h: n=%d known=%v err=%v, want 12 known", n, known, err)
	}
	// Filtered views have no install-wide rollup to read.
	if _, known, _ := RateLimitedServes(ctx, d, "shop", nil, 24); known {
		t.Error("a site filter must not read the install-wide rollup")
	}
	if _, known, _ := RateLimitedServes(ctx, d, "", []string{"h1"}, 24); known {
		t.Error("a host filter must not read the install-wide rollup")
	}
	if _, known, _ := RateLimitedServes(ctx, nil, "", nil, 24); known {
		t.Error("nil db")
	}
}
