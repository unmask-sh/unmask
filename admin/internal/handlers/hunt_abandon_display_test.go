package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// TestHuntAbandonRowShowsDetail: an abandon row has to answer "where did they
// leave, and after how long" from the log itself.  The payload holds it, but
// the hunt page renders no payload, so before this the only visible difference
// between one departure and another was the timestamp -- the phase pill said
// "abandon" and nothing else, and hovering it gave the generic list of every
// phase.  The step now rides in the pill (like check(pass) / bv_rebind(reason))
// and the timing detail in its tooltip.
func TestHuntAbandonRowShowsDetail(t *testing.T) {
	h := newTestHandler(t)
	if _, err := h.DB.Exec(`INSERT INTO unmask_event
		(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
		VALUES ('','','',0,x'7f000009','UA','','',0,'abandon',0,0,'','',
		'{"abandon_phase":"captcha","abandon_via":"pagehide","left_at_ms":2450,"notice_delay_ms":37}', datetime('now'))`); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?range=1h", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	body := rr.Body.String()

	// The step the visitor left from, visible without hovering anything.
	if !strings.Contains(body, "abandon(captcha)") {
		t.Error("the pill must name the step the visitor left from")
	}
	// Both clocks in the tooltip: when they left, and how much later we saw it.
	for _, want := range []string{"2450", "37"} {
		if !strings.Contains(body, want) {
			t.Errorf("the departure detail must include %s", want)
		}
	}
	// Back or closed, the only available answer -- and it has to ride INSIDE
	// the pill.  Beside it, the fact wrapped onto its own line on a narrow
	// column and read as another step in the chain.  Nothing else followed this
	// seeded row, so the mark is the empty one.
	if !strings.Contains(body, `abandon(captcha)<span class="ret-mark">∅</span>`) {
		t.Error("the abandon pill must carry what happened next, inside the pill")
	}
}

// TestHuntAbandonSubPhaseForPopover: collapsing a session rebuilds the phase
// cell from data-phase alone, so "abandon" arrives in the chain with no hint of
// where the visitor gave up.  The session popover -- which lists each phase
// with its timestamp -- reads data-sub to print abandon(load), so the timeline
// answers "which step" without the row having to carry prose.  One attribute
// per row, so a session with several such rows labels them all.
func TestHuntAbandonSubPhaseForPopover(t *testing.T) {
	h := newTestHandler(t)
	seed := []struct{ phase, payload string }{
		{"serve", `{"bt":"sess1"}`},
		{"load", `{"bt":"sess1"}`},
		{"abandon", `{"bt":"sess1","abandon_phase":"load","abandon_via":"pagehide","left_at_ms":2824,"notice_delay_ms":12}`},
	}
	for _, s := range seed {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,x'7f000001','UA','','',0,?,0,0,'','',?,datetime('now'))`, s.phase, s.payload); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?range=1h", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, r)
	body := rr.Body.String()

	if !regexp.MustCompile(`data-phase="abandon"[^>]*data-sub="load"`).MatchString(body) {
		t.Error("the abandon row must expose its step as data-sub for the popover")
	}
	// Rows without a sub-value must not grow an empty attribute.
	if strings.Contains(body, `data-sub=""`) {
		t.Error("data-sub must be omitted rather than emitted empty")
	}
	// The popover builder has to consume it.
	if !strings.Contains(body, "data-sub") || !strings.Contains(body, "label += '(' + sub + ')'") {
		t.Error("the session timeline must append the sub-value to the phase label")
	}

	// The prose rides as a footnote, not under the line: the timeline is read
	// as a sequence, and a paragraph between steps breaks that scan.  One note
	// per qualifying row, numbered, so several detailed rows get several notes.
	if !strings.Contains(body, "data-detail") {
		t.Error("the row must carry the explanation for the footnote")
	}
	for _, want := range []string{"session-notes", "session-note-ref", "notes.push(det)"} {
		if !strings.Contains(body, want) {
			t.Errorf("the popover must render numbered footnotes (%s missing)", want)
		}
	}
	// Footnote text must wrap: inheriting the timeline's nowrap ran long notes
	// straight out of the popover box.
	if !strings.Contains(body, "white-space:normal") || !strings.Contains(body, "overflow-wrap:anywhere") {
		t.Error("footnotes must re-enable wrapping so they stay inside the popover")
	}
}
