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
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.OverBlock = settings.OverBlockConfig{
			AutoPassthrough: true,
			WindowMinutes:   60,
			MinServes:       20,
			MaxServesPerIP:  5,
		}
	})
	ctx := context.Background()
	now := time.Now().UTC()

	// A loop: 30 challenge serves to a single IP = 30/IP, well over the 5
	// threshold -- and the visitor LOADS each one, which is what a browser
	// stuck in a loop does and what a scanner farm never does.  Without the
	// loads this is indistinguishable from probing traffic and the breaker
	// deliberately stays quiet.  The serves carry a User-Agent: only
	// browser-grade serves feed the signal, and a trapped browser sends one.
	const loopUA = "Mozilla/5.0 Chrome/126"
	for i := 0; i < 30; i++ {
		if err := events.Insert(ctx, h.DB, &events.Event{
			IPPacked: events.PackIP("203.0.113.7"), Phase: "serve", UserAgent: loopUA, OccurredAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 30; i++ {
		if err := events.Insert(ctx, h.DB, &events.Event{
			IPPacked: events.PackIP("203.0.113.7"), Phase: "load", UserAgent: loopUA, OccurredAt: now,
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
	h.updateSettingsInMemory(func(s *settings.Settings) { s.OverBlock.Disabled = true })
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
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.OverBlock = settings.OverBlockConfig{
			WindowMinutes:  60,
			MinServes:      20,
			MaxServesPerIP: 5,
		}
	})
	ctx := context.Background()
	now := time.Now().UTC()

	// 30 browser-grade serves spread across 30 distinct IPs = 1/IP -- healthy.
	// (With a User-Agent so they COUNT: an all-excluded window not tripping
	// would pass this test for the wrong reason.)
	for i := 0; i < 30; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		if err := events.Insert(ctx, h.DB, &events.Event{
			IPPacked: events.PackIP(ip), Phase: "serve", UserAgent: "Mozilla/5.0 Chrome/126", OccurredAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	h.checkOverBlock(ctx)
	if h.overBlockTripped.Load() {
		t.Error("breaker tripped on healthy 1-serve-per-IP traffic")
	}
}
