package dashboard

import (
	"context"
	"strconv"
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

// TestDateAndHourIntWindow covers the daily-bucket helpers (ccip date-only
// string column + DailyPassByCountry unix/3600 integer column).
func TestDateAndHourIntWindow(t *testing.T) {
	start := time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC).Unix()
	end := time.Date(2026, 6, 10, 0, 0, 0, 0, time.UTC).Unix()
	ctx := WithWindow(context.Background(), Window{Start: start, End: end})

	dt := dateWindow(ctx, 24, "bucket")
	if !strings.Contains(dt, "bucket >= '2026-06-01'") || !strings.Contains(dt, "bucket <= '2026-06-10'") {
		t.Errorf("dateWindow = %q", dt)
	}
	hi := hourIntWindow(ctx, 24, "bucket_hour")
	wantLo := start / 3600
	wantHi := end / 3600
	if !strings.Contains(hi, "bucket_hour >= "+itoa(wantLo)) || !strings.Contains(hi, "bucket_hour <= "+itoa(wantHi)) {
		t.Errorf("hourIntWindow = %q (want lo=%d hi=%d)", hi, wantLo, wantHi)
	}
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// TestWindowFromRangeExtended covers the longer trailing presets and "all".
func TestWindowFromRangeExtended(t *testing.T) {
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	oldest := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	cases := []struct {
		rng       string
		from, to  int64
		wantStart int64
		wantEnd   int64
	}{
		{"90d", 0, 0, now.Add(-24 * 90 * time.Hour).Unix(), now.Unix()},
		{"180d", 0, 0, now.Add(-24 * 180 * time.Hour).Unix(), now.Unix()},
		{"365d", 0, 0, now.Add(-24 * 365 * time.Hour).Unix(), now.Unix()},
		{"all", oldest, now.Unix(), oldest, now.Unix()},                  // handler passes [oldest, now]
		{"all", 0, 0, now.Add(-24 * 365 * time.Hour).Unix(), now.Unix()}, // no oldest -> 1y fallback
	}
	for _, c := range cases {
		w := WindowFromRange(c.rng, now, c.from, c.to)
		if w.Start != c.wantStart || w.End != c.wantEnd {
			t.Errorf("WindowFromRange(%q,%d,%d) = {%d,%d}, want {%d,%d}", c.rng, c.from, c.to, w.Start, w.End, c.wantStart, c.wantEnd)
		}
	}
}

// TestWindowFromRangeShortPresets: the sub-day presets resolve through
// RangeHours -- the one token table -- so the picker, the queries and the
// window can never disagree about what "3h" spans.
func TestWindowFromRangeShortPresets(t *testing.T) {
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	for tok, hours := range map[string]int{"1h": 1, "3h": 3, "6h": 6, "12h": 12, "24h": 24, "7d": 24 * 7} {
		w := WindowFromRange(tok, now, 0, 0)
		wantStart := now.Add(-time.Duration(hours) * time.Hour).Unix()
		if w.Start != wantStart || w.End != now.Unix() {
			t.Errorf("WindowFromRange(%q) = {%d,%d}, want {%d,%d}", tok, w.Start, w.End, wantStart, now.Unix())
		}
		if got := RangeHours(tok); got != hours {
			t.Errorf("RangeHours(%q) = %d, want %d", tok, got, hours)
		}
	}
	// Unknown tokens keep the historical 24h fallback on both resolvers.
	if got := RangeHours("2h"); got != 24 {
		t.Errorf("RangeHours(unknown) = %d, want 24", got)
	}
}

// TestHourlyAggUsableSubDay: the rollup's finest grain is an hour and its
// window clause is inclusive at both ends, so a sub-day read would answer a
// "what happened since I changed that rule" question with up to an hour of
// pre-change traffic on either side.  Sub-day windows must fall through to the
// raw scan, which bounds on exact timestamps.
func TestHourlyAggUsableSubDay(t *testing.T) {
	hourlyReady.Store(true)
	defer hourlyReady.Store(false)

	for _, tok := range []string{"1h", "3h", "6h", "12h"} {
		if hourlyAggUsable(context.Background(), RangeHours(tok)) {
			t.Errorf("range %q was answered from the hourly rollup", tok)
		}
	}
	for _, tok := range []string{"24h", "7d", "30d"} {
		if !hourlyAggUsable(context.Background(), RangeHours(tok)) {
			t.Errorf("range %q needlessly dropped to the raw scan", tok)
		}
	}
	// A ctx window overrides the trailing hours, so the span it carries -- not
	// the fallback arg -- decides.
	now := time.Date(2026, 6, 19, 12, 0, 0, 0, time.UTC)
	short := WithWindow(context.Background(), WindowTrailing(now, 2))
	if hourlyAggUsable(short, 24*30) {
		t.Error("a 2h ctx window was answered from the rollup because the fallback arg was long")
	}
	// Not ready means not usable regardless of span.
	hourlyReady.Store(false)
	if hourlyAggUsable(context.Background(), 24*7) {
		t.Error("the rollup answered while not ready")
	}
}
