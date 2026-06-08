package handlers

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestCheckOverBlockTripsAndPassesThrough drives the monitor end to end against
// a real (isolated) DB: a synthesised challenge loop -> checkOverBlock samples
// it -> the breaker trips -> the auto-passthrough gate ServeChallenge reads opens.
// An isolated DB is used deliberately: OverBlockStats is a global serves/IP
// signal, so the shared docker e2e would dilute a single-IP loop with the other
// scenarios' diverse IPs (and a real trip would passthrough-leak into them).
func TestCheckOverBlockTripsAndPassesThrough(t *testing.T) {
	h := newTestHandler(t)
	// On by default (Disabled=false); auto-passthrough is opted in for this test.
	h.Settings.OverBlock = settings.OverBlockConfig{
		AutoPassthrough: true,
		WindowMinutes:   60,
		MinServes:       20,
		MaxServesPerIP:  5,
	}
	ctx := context.Background()
	now := time.Now().UTC()

	// A loop: 30 challenge serves to a single IP = 30/IP, well over the 5 threshold.
	for i := 0; i < 30; i++ {
		if err := events.Insert(ctx, h.DB, &events.Event{
			IPPacked: events.PackIP("203.0.113.7"), Phase: "serve", OccurredAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	h.checkOverBlock(ctx)
	if !h.overBlockTripped.Load() {
		t.Fatal("breaker did not trip on a 30-serves/1-IP loop")
	}
	if !h.overBlockPassthrough() {
		t.Error("overBlockPassthrough() is false while tripped + auto_passthrough -- ServeChallenge would still challenge")
	}

	// Disabling the breaker must clear the tripped state so it can't latch (and
	// auto-passthrough recovers on the next request).
	h.Settings.OverBlock.Disabled = true
	h.checkOverBlock(ctx)
	if h.overBlockTripped.Load() {
		t.Error("disabling the breaker did not clear the tripped state")
	}
	if h.overBlockPassthrough() {
		t.Error("overBlockPassthrough() still true after the breaker was disabled")
	}
}

// TestCheckOverBlockHealthyDoesNotTrip confirms ordinary traffic (one serve per
// IP) leaves the breaker untripped, even at the same volume as the loop above.
func TestCheckOverBlockHealthyDoesNotTrip(t *testing.T) {
	h := newTestHandler(t)
	h.Settings.OverBlock = settings.OverBlockConfig{
		WindowMinutes:  60,
		MinServes:      20,
		MaxServesPerIP: 5,
	}
	ctx := context.Background()
	now := time.Now().UTC()

	// 30 serves spread across 30 distinct IPs = 1/IP -- healthy.
	for i := 0; i < 30; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		if err := events.Insert(ctx, h.DB, &events.Event{
			IPPacked: events.PackIP(ip), Phase: "serve", OccurredAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	h.checkOverBlock(ctx)
	if h.overBlockTripped.Load() {
		t.Error("breaker tripped on healthy 1-serve-per-IP traffic")
	}
}
