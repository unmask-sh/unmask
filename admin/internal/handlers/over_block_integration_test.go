package handlers

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/notifier"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// textMailer hands the text part of each alert mail to a channel.
type textMailer chan string

func (m textMailer) Enabled() bool                       { return true }
func (m textMailer) Send(to, subject, body string) error { return nil }
func (m textMailer) SendAlt(to, subject, text, html string) error {
	m <- text
	return nil
}

// obEvent writes one challenge event for the breaker tests.
func obEvent(t *testing.T, h *Handler, ip, phase, path, reason string, at time.Time) {
	t.Helper()
	pl := map[string]any{"orig_path": path}
	if reason != "" {
		pl["force_reason"] = reason
	}
	if err := events.Insert(context.Background(), h.DB, &events.Event{
		IPPacked: events.PackIP(ip), Site: "s1", Phase: phase, UserAgent: "Mozilla/5.0 Chrome/126", Payload: pl, OccurredAt: at,
	}); err != nil {
		t.Fatal(err)
	}
}

// TestCheckOverBlockTripsAndPassesThrough drives the monitor end to end against
// a real (isolated) DB: a challenge loop -> checkOverBlock reads it -> the
// breaker trips -> the auto-passthrough gate ServeChallenge reads opens.
// An isolated DB is used deliberately: the signal is global, so the shared
// docker e2e would mix a synthetic loop with the other scenarios' traffic (and
// a real trip would passthrough-leak into them).
func TestCheckOverBlockTripsAndPassesThrough(t *testing.T) {
	h := newTestHandler(t)
	// On by default (Disabled=false); auto-passthrough is opted in for this test.
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.OverBlock = settings.OverBlockConfig{AutoPassthrough: true}
	})
	ctx := context.Background()
	now := time.Now().UTC().Add(-time.Minute)

	// A loop: four visitors run the challenge, pass, and are shown it again on
	// the same page a second later -- their pass is not honoured.
	for i := 1; i <= 4; i++ {
		ip := fmt.Sprintf("203.0.113.%d", i)
		obEvent(t, h, ip, "load", "/a", "", now)
		obEvent(t, h, ip, "bv_pow_only", "/a", "", now)
		obEvent(t, h, ip, "serve", "/a", "none", now.Add(time.Second))
	}

	h.checkOverBlock(ctx, true)
	if !h.overBlockTripped.Load() {
		t.Fatal("breaker did not trip on four visitors whose pass was not honoured")
	}
	if !h.overBlockPassthrough() {
		t.Error("overBlockPassthrough() is false while tripped + auto_passthrough -- ServeChallenge would still challenge")
	}
	hh, err := h.OverBlockHealth(ctx)
	if err != nil || !hh.Tripped || hh.Stuck != 4 || hh.Loaders != 4 || hh.StuckPct != 100 {
		t.Errorf("banner signal = %+v (%v), want 4 of 4 stuck", hh, err)
	}

	// Disabling the breaker must clear the tripped state so it can't latch (and
	// auto-passthrough recovers on the next request).
	h.updateSettingsInMemory(func(s *settings.Settings) { s.OverBlock.Disabled = true })
	h.checkOverBlock(ctx, true)
	if h.overBlockTripped.Load() {
		t.Error("disabling the breaker did not clear the tripped state")
	}
	if h.overBlockPassthrough() {
		t.Error("overBlockPassthrough() still true after the breaker was disabled")
	}
}

// TestCheckOverBlockQuietOnScannerTraffic: what set off the old breaker
// (2026-10-07) -- one address hammering a site with a browser's user-agent,
// hundreds of challenges and none of them run, while the visitors in the
// window passed -- must leave it quiet.  So must the stuck addresses of an
// ordinary day.
func TestCheckOverBlockQuietOnScannerTraffic(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()
	now := time.Now().UTC().Add(-time.Minute)
	for i := 0; i < 200; i++ {
		obEvent(t, h, "192.0.2.66", "serve", "/.env", "none", now)
	}
	for i := 1; i <= 30; i++ {
		ip := fmt.Sprintf("198.51.100.%d", i)
		obEvent(t, h, ip, "load", "/", "", now)
		obEvent(t, h, ip, "bv_pow_only", "/", "", now)
	}
	// Two of them drop the cookie and are shown the challenge again.
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		obEvent(t, h, ip, "serve", "/", "none", now.Add(time.Second))
	}
	h.checkOverBlock(ctx, true)
	if h.overBlockTripped.Load() {
		t.Error("breaker tripped on a scanner and two stuck addresses among thirty that passed")
	}
}

// A quiet site: three visitors in an hour, every one of them stuck.  Ten
// minutes never holds three, so the short window cannot say it; the hour can.
func TestCheckOverBlockLongWindow(t *testing.T) {
	h := newTestHandler(t)
	ctx := context.Background()
	for i, ago := range []time.Duration{50 * time.Minute, 30 * time.Minute, 5 * time.Minute} {
		ip := fmt.Sprintf("203.0.113.%d", i+1)
		at := time.Now().UTC().Add(-ago)
		obEvent(t, h, ip, "serve", "/a", "none", at)
		obEvent(t, h, ip, "load", "/a", "", at)
		obEvent(t, h, ip, "verify_ng", "/a", "", at.Add(time.Second))
	}
	mail := make(chan string, 1)
	h.Notifier = notifier.New(notifier.Config{}).WithMail(textMailer(mail), func() []notifier.Recipient {
		return []notifier.Recipient{{Email: "ops@example.com"}}
	}, nil)
	h.checkOverBlock(ctx, false) // the long window not read yet: read once all the same
	if !h.overBlockTripped.Load() {
		t.Fatal("breaker did not trip on three stuck visitors of three in the hour")
	}
	// The mail reports the hour it tripped on, the challenges served in it
	// included (the long window is read without them until it trips).
	select {
	case text := <-mail:
		for _, want := range []string{"In the last 60 minutes, 3 of the 3 addresses", "3 served to 3 addresses"} {
			if !strings.Contains(text, want) {
				t.Errorf("the mail lacks %q:\n%s", want, text)
			}
		}
	case <-time.After(2 * time.Second):
		t.Error("no mail on the trip")
	}
	hh, _ := h.OverBlockHealth(ctx)
	if hh.WindowMin != 60 || hh.Stuck != 3 {
		t.Errorf("banner signal = %+v, want the hour's 3 stuck", hh)
	}
}
