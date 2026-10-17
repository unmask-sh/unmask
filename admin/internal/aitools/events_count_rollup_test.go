package aitools

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/events"
)

// events_count answers from the hourly rollup when no filter needs the
// events themselves: the folded hours by phase, the addresses estimated.
// A phase narrows it there too.  A filter reads the window, and a window
// the id range puts past the scan limit is refused with advice.
func TestEventsCountReadsTheRollupAndRefusesAHugeScan(t *testing.T) {
	d := testDeps(t)
	ctx := context.Background()
	// Two earlier hours, two addresses, four events, beside testDeps' three
	// serves of the hour under way from a third address: seven events, three
	// addresses, three hours once folded.
	h0 := time.Now().UTC().Truncate(time.Hour)
	for _, e := range []struct {
		ip    string
		phase string
		at    time.Time
	}{
		{"198.51.100.1", "serve", h0.Add(-90 * time.Minute)},
		{"198.51.100.1", "load", h0.Add(-89 * time.Minute)},
		{"198.51.100.2", "serve", h0.Add(-85 * time.Minute)},
		{"198.51.100.1", "bv_pow_only", h0.Add(-30 * time.Minute)},
	} {
		if err := events.Insert(ctx, d.DB, &events.Event{Site: "s1", IPPacked: events.PackIP(e.ip), Phase: e.phase, UserAgent: "UA-x", OccurredAt: e.at}); err != nil {
			t.Fatal(err)
		}
	}
	if err := dashboard.AggregateHourly(ctx, d.DB, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dashboard.ResetHourlyAggReadyForTest)

	out, err := d.Run(ctx, "events_count", map[string]any{"window_hours": float64(6)})
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	src, _ := m["source"].(string)
	if !strings.HasPrefix(src, "the hourly rollup") || m["total"] != 7 || m["distinct_ips"] != 3 {
		t.Errorf("rollup answer: %v", m)
	}
	phases := m["phases"].(map[string]int)
	hours := m["hours"].([]events.HourCount)
	if phases["serve"] != 5 || phases["load"] != 1 || phases["bv_pow_only"] != 1 || len(hours) != 3 || hours[0].DistinctIPs != 2 || hours[1].DistinctIPs != 1 || hours[2].DistinctIPs != 1 {
		t.Errorf("phases %v hours %+v", phases, hours)
	}
	// A phase narrows the rollup's answer; the addresses are not known then.
	out, err = d.Run(ctx, "events_count", map[string]any{"window_hours": float64(6), "phase": "serve,load"})
	if err != nil {
		t.Fatal(err)
	}
	m = out.(map[string]any)
	src, _ = m["source"].(string)
	if m["total"] != 6 || m["distinct_ips"] != 0 || !strings.Contains(src, "not known under a phase filter") || len(m["hours"].([]events.HourCount)) != 2 {
		t.Errorf("phase-narrowed rollup answer: %v", m)
	}
	// A filter the rollup lacks reads the window's events.
	out, err = d.Run(ctx, "events_count", map[string]any{"window_hours": float64(6), "ua": "curl"})
	if err != nil {
		t.Fatal(err)
	}
	m = out.(map[string]any)
	if _, fromRollup := m["source"]; fromRollup || m["total"] != 3 {
		t.Errorf("filtered answer: %v", m)
	}
	// Too many events for a scan: refused before it, with the way out.
	old := eventsCountScanMax
	eventsCountScanMax = 2
	t.Cleanup(func() { eventsCountScanMax = old })
	if _, err := d.Run(ctx, "events_count", map[string]any{"window_hours": float64(6), "ua": "curl"}); err == nil || !strings.Contains(err.Error(), "too many to count") || !strings.Contains(err.Error(), "narrow window_hours") {
		t.Errorf("a huge window was not refused: %v", err)
	}
	// The rollup still answers an unfiltered count, whatever the size.
	if _, err := d.Run(ctx, "events_count", map[string]any{"window_hours": float64(6)}); err != nil {
		t.Errorf("the rollup answer was refused: %v", err)
	}
}

// WindowRows judges a window by its id range: the events of the window,
// none for an empty one.  It takes the ids as time's order, which is how
// the daemon writes them; a row written later with an earlier time is
// counted in, as the estimate it is.
func TestWindowRows(t *testing.T) {
	d := testDeps(t) // three events in the hour under way
	ctx := context.Background()
	n, err := events.WindowRows(ctx, d.DB, 60)
	if err != nil || n != 3 {
		t.Errorf("WindowRows(60m) = %d, %v; want 3", n, err)
	}
	if n, err := events.WindowRows(ctx, d.DB, 0); err != nil || n != 3 {
		t.Errorf("WindowRows(all) = %d, %v; want 3", n, err)
	}
	if n, err := events.WindowRows(ctx, d.DB, 24*60*400); err != nil || n != 3 {
		t.Errorf("WindowRows(400d) = %d, %v; want 3", n, err)
	}
	if err := events.Insert(ctx, d.DB, &events.Event{IPPacked: events.PackIP("198.51.100.9"), Phase: "serve", OccurredAt: time.Now().UTC().Add(-5 * time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if n, err := events.WindowRows(ctx, d.DB, 60); err != nil || n != 4 {
		t.Errorf("WindowRows(60m) with a backdated row written last = %d, %v; want 4 (the id range)", n, err)
	}
}
