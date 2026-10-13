package events

import (
	"context"
	"testing"
	"time"
)

// RankServes counts challenges served, not events: a browser that loads the
// page leaves several events per challenge, and ranked by events it would
// pass a scanner that was served more challenges.
func TestRankServesCountsServesOnly(t *testing.T) {
	d := asnTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	add := func(ip, ja4, ua, phase string, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			if err := Insert(ctx, d, &Event{IPPacked: PackIP(ip), JA4: ja4, UserAgent: ua, Phase: phase, OccurredAt: now}); err != nil {
				t.Fatal(err)
			}
		}
	}
	// A scanner: three challenges, nothing else.
	add("203.0.113.9", "t13d_scan", "curl/8", "serve", 3)
	// A browser: two challenges, each loaded, abandoned and loaded again.
	add("198.51.100.7", "t13d_chrome", "Chrome/155", "serve", 2)
	add("198.51.100.7", "t13d_chrome", "Chrome/155", "load", 4)
	add("198.51.100.7", "t13d_chrome", "Chrome/155", "abandon", 2)

	for kind, want := range map[string][2]string{
		"ip":  {"203.0.113.9", "198.51.100.7"},
		"ja4": {"t13d_scan", "t13d_chrome"},
		"ua":  {"curl/8", "Chrome/155"},
	} {
		rows, err := RankServes(ctx, d, kind, 60, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 2 || rows[0].Key != want[0] || rows[0].Count != 3 || rows[1].Key != want[1] || rows[1].Count != 2 {
			t.Errorf("%s: %+v, want %s=3 then %s=2", kind, rows, want[0], want[1])
		}
	}
	if byEvents, err := RankByIP(ctx, d, 60, 10, ""); err != nil || len(byEvents) == 0 || byEvents[0].Key != "198.51.100.7" {
		t.Errorf("the hunt's ranking counts every event (the browser first): %+v %v", byEvents, err)
	}
	if _, err := RankServes(ctx, d, "path", 60, 10); err == nil {
		t.Error("an unknown kind must be refused")
	}
}
