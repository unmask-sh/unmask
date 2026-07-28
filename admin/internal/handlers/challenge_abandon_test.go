package handlers

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
	"github.com/unmask-sh/unmask/admin/internal/events"
)

// TestAbandonBeaconWiring pins the pieces that make an abandoned challenge
// visible.  A visitor who closes the tab or hits Back mid-challenge otherwise
// leaves no trace at all: the phase chain just stops, which is exactly what a
// bot that never ran the JS looks like.  The counts alone therefore cannot
// answer whether real people are giving up, or at which step.
func TestAbandonBeaconWiring(t *testing.T) {
	js, err := assets.Static.ReadFile("static/challenge.js")
	if err != nil {
		t.Fatalf("read challenge.js: %v", err)
	}
	src := string(js)

	// The server must accept the phase, or every beacon is dropped as invalid.
	if !events.IsValidPhase("abandon") {
		t.Error("server rejects the 'abandon' phase — the beacon would be discarded")
	}

	// pagehide is the primary signal; beforeunload is unreliable on mobile and
	// blocks the bfcache, and visibilitychange covers the tab-backgrounded-then
	// -killed case pagehide can miss.
	for _, want := range []string{
		`addEventListener('pagehide'`,
		`addEventListener('visibilitychange'`,
		`_bcDebug('abandon'`,
	} {
		if !strings.Contains(src, want) {
			t.Errorf("challenge.js is missing %q", want)
		}
	}
	if strings.Contains(src, "addEventListener('beforeunload'") {
		t.Error("beforeunload must not be used: unreliable on mobile and it blocks the bfcache")
	}

	// The report is only useful with the phase it left from and how long the
	// visitor waited; elapsed_ms rides every beacon already.
	if !strings.Contains(src, "abandon_phase") {
		t.Error("the abandon beacon must carry the phase the visitor left from")
	}

	// elapsed_ms is when the handler RAN.  An event that arrives while the PoW
	// holds the thread is handled late, so that clock alone says "left right
	// after passing" for someone who gave up during the solve.  event.timeStamp
	// is when the browser CREATED the event -- when the visitor actually left --
	// and does not move when the handler is delayed (measured 474ms apart on a
	// blocked thread).  Both, plus their difference, or the wait-time numbers
	// are quietly wrong.
	for _, want := range []string{"left_at_ms", "notice_delay_ms", "ev.timeStamp"} {
		if !strings.Contains(src, want) {
			t.Errorf("the abandon beacon must report %s", want)
		}
	}
	// The listeners must forward the event object, or timeStamp is unavailable.
	if !strings.Contains(src, "abandon('pagehide', e)") || !strings.Contains(src, "abandon('hidden', e)") {
		t.Error("both listeners must pass the event through so its timeStamp can be read")
	}

	// Passing navigates away on purpose.  Without this guard pagehide fires on
	// the success redirect and every completed challenge is also counted as an
	// abandonment — which would bury the signal entirely.
	if !strings.Contains(src, "__unmaskPassed") {
		t.Error("a successful pass must suppress the abandonment beacon")
	}
	pass := src[strings.Index(src, "function passAndRedirect()"):]
	if i := strings.Index(pass, "}"); i > 0 {
		pass = pass[:i+1]
	}
	if !strings.Contains(pass, "__unmaskPassed = true") {
		t.Error("passAndRedirect must set the passed flag before navigating")
	}

	// Phase tracking lives inside _bcDebug so a phase added later is covered
	// without anyone remembering to update a second place -- and 'abandon'
	// itself must not overwrite the phase it reports.
	dbg := src[strings.Index(src, "function _bcDebug(phase, extra)"):]
	if i := strings.Index(dbg, "var pl = {"); i > 0 {
		dbg = dbg[:i]
	}
	if !strings.Contains(dbg, "__unmaskPhase") || !strings.Contains(dbg, `phase !== 'abandon'`) {
		t.Error("_bcDebug must record the last phase and exclude 'abandon' from it")
	}
}
