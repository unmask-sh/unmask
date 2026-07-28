package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// renderedPhases lists the phases of the rows actually in the table -- read
// from the <tr data-phase="...">, not from the pill class, because the page's
// stylesheet mentions every ph-* class and a substring check on those matches
// whether the row exists or not.
func renderedPhases(body string) map[string]bool {
	out := map[string]bool{}
	for _, m := range regexp.MustCompile(`<tr[^>]*data-phase="([^"]+)"`).FindAllStringSubmatch(body, -1) {
		out[m[1]] = true
	}
	return out
}

// TestHuntPhaseGroupFilter: the phase filter takes a comma-separated group, so
// "show me everything that passed" is one query rather than four.  The handler
// used to validate the value as a single phase name, which turned every group
// back into "no filter" -- the page then looked like the filter was ignored.
func TestHuntPhaseGroupFilter(t *testing.T) {
	h := newTestHandler(t)
	for _, ph := range []string{"serve", "load", "bv_pow_only", "bv_captcha_only", "verify_ng", "abandon"} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,x'7f000001','UA','','',0,?,0,0,'','','{}',datetime('now'))`, ph); err != nil {
			t.Fatal(err)
		}
	}
	get := func(qs string) string {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?range=1h"+qs, nil)
		rr := httptest.NewRecorder()
		h.AdminHuntIndex(rr, r)
		if rr.Code != http.StatusOK {
			t.Fatalf("status %d", rr.Code)
		}
		return rr.Body.String()
	}

	const passed = "bv_pow_only,bv_captcha_only,bv_pow_then_captcha,bv_rebind"
	body := get("&phase=" + passed)
	got := renderedPhases(body)
	if !got["bv_pow_only"] || !got["bv_captcha_only"] {
		t.Errorf("passed group dropped its own members: %v", got)
	}
	for _, unwanted := range []string{"serve", "load", "verify_ng", "abandon"} {
		if got[unwanted] {
			t.Errorf("passed group leaked %s: %v", unwanted, got)
		}
	}
	// The picker has to come back showing the group, or the operator cannot
	// tell which filter produced the page.
	if !strings.Contains(body, `value="`+passed+`" selected`) {
		t.Error("the group option must render as selected after filtering")
	}

	// A single phase keeps working exactly as before.
	if one := renderedPhases(get("&phase=verify_ng")); len(one) != 1 || !one["verify_ng"] {
		t.Errorf("single-phase filter = %v, want only verify_ng", one)
	}
	// No filter shows everything.
	if all := renderedPhases(get("")); len(all) != 6 {
		t.Errorf("unfiltered page rendered %d phases, want 6", len(all))
	}
	// An unrecognised value must narrow to nothing, never widen to the whole log.
	if bad := renderedPhases(get("&phase=bogus")); len(bad) != 0 {
		t.Errorf("unknown phase returned %v, want no rows", bad)
	}
}
