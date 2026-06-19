package dashboard

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestWindowFromRange(t *testing.T) {
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		rng       string
		from, to  int64
		wantStart int64
		wantEnd   int64
	}{
		{"24h", 0, 0, now.Add(-24 * time.Hour).Unix(), now.Unix()},
		{"7d", 0, 0, now.Add(-24 * 7 * time.Hour).Unix(), now.Unix()},
		{"30d", 0, 0, now.Add(-24 * 30 * time.Hour).Unix(), now.Unix()},
		{"", 0, 0, now.Add(-24 * time.Hour).Unix(), now.Unix()}, // unknown -> 24h
		{"custom", 1000, 2000, 1000, 2000},
		{"custom", 0, 0, now.Add(-24 * time.Hour).Unix(), now.Unix()},       // invalid custom -> 24h trailing
		{"custom", 2000, 1000, now.Add(-24 * time.Hour).Unix(), now.Unix()}, // inverted -> 24h trailing
	}
	for _, c := range cases {
		w := WindowFromRange(c.rng, now, c.from, c.to)
		if w.Start != c.wantStart || w.End != c.wantEnd {
			t.Errorf("WindowFromRange(%q,%d,%d) = {%d,%d}, want {%d,%d}",
				c.rng, c.from, c.to, w.Start, w.End, c.wantStart, c.wantEnd)
		}
	}
}

// TestHourWindowCtxOverride: a ctx Window bounds BOTH ends; without one, the
// helper falls back to a trailing-hours window (so un-migrated/preset callers
// are unchanged).
func TestHourWindowCtxOverride(t *testing.T) {
	// custom window: 2026-06-01 00:00 .. 2026-06-10 23:00 UTC.
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).Unix()
	end := time.Date(2026, 6, 10, 23, 0, 0, 0, time.UTC).Unix()
	ctx := WithWindow(context.Background(), Window{Start: start, End: end})

	got := hourWindow(ctx, 24, "bucket_hour")
	wantLo := "bucket_hour >= '2026-06-01 00'"
	wantHi := "bucket_hour <= '2026-06-10 23'"
	if !strings.Contains(got, wantLo) || !strings.Contains(got, wantHi) {
		t.Errorf("hourWindow custom = %q, want both %q and %q", got, wantLo, wantHi)
	}

	// No ctx window -> trailing fallback has an upper bound at ~now (not a fixed
	// past date), so it must NOT contain the custom upper bound.
	fb := hourWindow(context.Background(), 24, "bucket_hour")
	if strings.Contains(fb, "2026-06-10 23") {
		t.Errorf("hourWindow fallback unexpectedly used the custom end: %q", fb)
	}
	if !strings.Contains(fb, "bucket_hour >=") || !strings.Contains(fb, "bucket_hour <=") {
		t.Errorf("hourWindow fallback missing lower+upper bound: %q", fb)
	}
}

func TestTsAndMinWindowColumns(t *testing.T) {
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).Unix()
	end := time.Date(2026, 6, 2, 0, 0, 0, 0, time.UTC).Unix()
	ctx := WithWindow(context.Background(), Window{Start: start, End: end})

	ts := tsWindow(ctx, 24, "date_created")
	if !strings.Contains(ts, "date_created >= '2026-06-01 00:00:00'") || !strings.Contains(ts, "date_created <= '2026-06-02 00:00:00'") {
		t.Errorf("tsWindow = %q", ts)
	}
	mn := minWindow(ctx, 24, "bucket_min")
	if !strings.Contains(mn, "bucket_min >=") || !strings.Contains(mn, "bucket_min <=") {
		t.Errorf("minWindow = %q", mn)
	}
}
