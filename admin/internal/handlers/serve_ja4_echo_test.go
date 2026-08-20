package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
)

// A beacon row's JA4 belongs to the beacon's own TLS connection, and the same
// device can present a different fingerprint there than the one the challenge
// was served to -- observed live as a herd client whose serve matched a bot
// JA4 rule (force_reason=ja4_bot) while its abandon beacon arrived on a
// variant fingerprint that matched nothing (verdict "ok"), an honest
// contradiction the row could not explain.  The serve-time JA4 now travels
// the same road force_reason does: embedded in the page, echoed by every
// beacon, extracted onto the row -- so the one row can say when the
// difference is real, which matters exactly when the operator filters to a
// beacon phase and the sibling serve row is off screen.

// TestServeChallengeEmbedsOwnJA4: the page carries the fingerprint it was
// served to.
func TestServeChallengeEmbedsOwnJA4(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest("GET", "/unmask/challenge/", nil)
	req.Header.Set("X-Client-JA4", "t13d1516h2_8daaf6152771_d8a2da3f94cd")
	w := httptest.NewRecorder()
	h.ServeChallenge(w, req)

	if !strings.Contains(w.Body.String(), `serve_ja4: /*__SERVE_JA4__*/"t13d1516h2_8daaf6152771_d8a2da3f94cd"`) {
		t.Error("the served page does not carry its own JA4 for the beacons to echo")
	}
}

// TestServeChallengeSanitizesJA4: the header is client-influencable on a
// direct hit and the value lands inside a <script> block -- anything outside
// the JA4 alphabet must become the empty string, not markup.
func TestServeChallengeSanitizesJA4(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest("GET", "/unmask/challenge/", nil)
	req.Header.Set("X-Client-JA4", `"></script><script>alert(1)`)
	w := httptest.NewRecorder()
	h.ServeChallenge(w, req)

	body := w.Body.String()
	if strings.Contains(body, "alert(1)") {
		t.Fatal("a forged X-Client-JA4 reached the page unsanitized")
	}
	if !strings.Contains(body, `serve_ja4: /*__SERVE_JA4__*/""`) {
		t.Error("an invalid JA4 should embed as empty, keeping the placeholder shape")
	}
}

// TestBeaconEchoWiring pins the transport end to end at the source level: the
// page seeds window.UNMASK.serve_ja4, challenge.js repeats it on every phase
// beacon, and the row decoration lifts it back out.  Any link dropping out
// silently turns the badge off for every future event.
func TestBeaconEchoWiring(t *testing.T) {
	html, err := assets.Static.ReadFile("static/challenge.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), `serve_ja4: /*__SERVE_JA4__*/""`) {
		t.Error("challenge.html no longer seeds window.UNMASK.serve_ja4")
	}
	js, err := assets.Static.ReadFile("static/challenge.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), `serve_ja4: (window.UNMASK && window.UNMASK.serve_ja4) || ''`) {
		t.Error("challenge.js no longer echoes serve_ja4 on beacons")
	}
}

// TestVariationBadgeMarksOnlyRealDifferences: the badge must fire on a real
// difference, stay silent when the fingerprints agree, and stay silent on
// pre-field history -- a blanket badge would just move the confusion.
func TestVariationBadgeMarksOnlyRealDifferences(t *testing.T) {
	raw, err := assets.Templates.ReadFile("templates/partial_events_table.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(raw)
	if !strings.Contains(tpl, `$varied := and .ServeJA4 (ne .ServeJA4 .JA4)`) {
		t.Error("the mark is not gated on an actual serve-vs-beacon difference")
	}
	if !strings.Contains(tpl, `tf $.Lang "hunt.ja4_varied_info" .ServeJA4`) {
		t.Error("the popover does not name the serve-time fingerprint")
	}
	// The mark annotates the fingerprint VALUE: it leads the JA4 cell (the
	// cell ellipsis-truncates on the right, so trailing would clip it) and
	// stays out of the escalation cell, where it used to wrap the pill onto
	// two lines.
	if !strings.Contains(tpl, `cellpop{{ end }}">{{ if $varied }}<span class="ja4var-badge"`) {
		t.Error("the mark no longer leads the JA4 cell")
	}
	if n := strings.Count(tpl, `class="ja4var-badge" data-info`); n != 1 {
		t.Errorf("the mark renders %d times; it belongs in the JA4 cell alone", n)
	}
}
