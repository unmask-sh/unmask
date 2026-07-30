package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
)

// A refused roaming rebind and the challenge it falls through to happen in ONE
// request, so the hunt log should read them as one session:
// "bv_rebind_reject(no_bvj) -> serve -> load -> bv_pow".  They used to sit
// apart because only the serve carried a beacon token -- the reject row was
// minted before the token existed -- so the operator saw a lone red row and
// could not tell whether that client then solved the challenge or gave up.
//
// The token now covers the whole request, and this pins the two properties the
// collapsed view needs from the server: the reject row must carry the SAME bt
// as the serve, and it must expose its refusal reason as data-sub, which is
// what the popover timeline spells out (the inline chain only has room for a
// short phase label).
func TestHuntRebindRejectJoinsServeSession(t *testing.T) {
	h := newTestHandler(t)
	seed := []struct{ phase, payload string }{
		{"bv_rebind_reject", `{"bt":"sessR","reason":"no_bvj","lineage":"lin1"}`},
		{"serve", `{"bt":"sessR","force_reason":"none"}`},
		{"load", `{"bt":"sessR"}`},
		{"bv_pow_only", `{"bt":"sessR"}`},
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
	if rr.Code != http.StatusOK {
		t.Fatalf("hunt: want 200, got %d", rr.Code)
	}
	body := rr.Body.String()

	rejectRow := regexp.MustCompile(`<tr[^>]*data-bt="sessR"[^>]*data-phase="bv_rebind_reject"[^>]*>`)
	m := rejectRow.FindString(body)
	if m == "" {
		t.Fatal("the reject row does not carry the session's beacon token -- it cannot join the serve's chain")
	}
	// data-sub is what the popover timeline appends as "(reason)".  Without it
	// the collapsed session shows a short "bv_rej" pill and the refusal cause
	// is nowhere on the page.
	if !strings.Contains(m, `data-sub="no_bvj"`) {
		t.Errorf("reject row must expose its reason as data-sub for the popover; got %s", m)
	}
	// The row's own pill keeps the full form (it is what a non-collapsed view
	// shows), so the reason survives even when the session is split by paging.
	if !regexp.MustCompile(`phase-pill ph-bv_rebind_reject">bv_rebind_reject\(no_bvj\)`).MatchString(body) {
		t.Error("the standalone pill must still spell out bv_rebind_reject(no_bvj)")
	}
}

// The collapsed chain and the popover have opposite jobs, and the shipped
// asset must reflect that: the chain abbreviates (several pills share one
// line), the popover spells things out (it is where the detail comes back).
// Pinning this from the template keeps a later "make it consistent" edit from
// abbreviating both and leaving "bv_rej" with nowhere to be explained.
func TestEventsTableChainShortensRebindPopoverDoesNot(t *testing.T) {
	raw, err := assets.Templates.ReadFile("templates/partial_events_table.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(raw)
	for _, want := range []string{
		`'bv_rebind_reject':    'bv_rej'`,
		`'bv_rebind':           'bv_reb'`,
		`'bv_rebind_reject':0.5`, // sorts just before the serve it precedes
	} {
		if !strings.Contains(tpl, want) {
			t.Errorf("partial_events_table.html must carry %s", want)
		}
	}
	// The timeline label must be the raw phase, not the short form.
	if !regexp.MustCompile(`(?m)^\s*var label = ph;\s*$`).MatchString(tpl) {
		t.Error("the popover timeline must label rows with the full phase name (var label = ph)")
	}
	if strings.Contains(tpl, "var label = PHASE_SHORT[ph] || ph;") {
		t.Error("the popover timeline still abbreviates -- the reason would have nowhere to appear")
	}
}
