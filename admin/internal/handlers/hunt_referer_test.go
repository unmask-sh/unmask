package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// The hunt row carries the referer as a data attribute, and the datetime
// popover renders it as a row that is ALWAYS present ("-" when the request
// sent none) -- a line that simply disappears reads as "this build does not
// record it".  The session view collapses a fire into its LAST phase, a
// beacon that never has a referer, so the collapse must promote the one from
// the serve row; without that promotion every collapsed session showed no
// referer at all, which is the state this pins.
func TestHuntRefererInDatetimePopover(t *testing.T) {
	h := newTestHandler(t)
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	// One session: the serve carries the referer, the beacons do not.
	for _, s := range []struct{ phase, payload string }{
		{"serve", `{"bt":"s1","orig_path":"/members/","referer":"https://news.example.com/thread/42"}`},
		{"load", `{"bt":"s1","url":"https://site.example/members/"}`},
		{"bv_pow_only", `{"bt":"s1","url":"https://site.example/members/"}`},
	} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('s','','https',443,?,?,'t13d','ok',0,?,0,0,'','',?,datetime('now'))`,
			[]byte{192, 0, 2, 9}, ua, s.phase, s.payload); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("hunt: %d", rr.Code)
	}
	body := rr.Body.String()

	if !strings.Contains(body, `data-referer="https://news.example.com/thread/42"`) {
		t.Error("the serve row must carry the referer as data-referer")
	}
	// The popover builder reads the attribute and always emits the row.
	if !strings.Contains(body, `tr.getAttribute('data-referer')`) {
		t.Error("the datetime popover must read data-referer")
	}
	if !strings.Contains(body, "dtpop-none") || !strings.Contains(body, "REFERER_LABEL") {
		t.Error(`the popover must render the referer row unconditionally, with a "-" (dtpop-none) when absent`)
	}
	// The session collapse promotes it onto the representative row.
	if !strings.Contains(body, `rep.setAttribute('data-referer', fv)`) {
		t.Error("the session collapse must promote the referer onto the rep row, else a collapsed session loses it")
	}
}

// Not a test: dump the hunt page (with a referer-carrying session) for browser
// measurement.  Enabled only when UNMASK_DUMP_HUNT_REF points at a file.
func TestDumpHuntRefererHTML(t *testing.T) {
	out := os.Getenv("UNMASK_DUMP_HUNT_REF")
	if out == "" {
		t.Skip("set UNMASK_DUMP_HUNT_REF=<path> to dump the hunt page")
	}
	h := newTestHandler(t)
	if _, err := h.DB.Exec(`INSERT INTO unmask_event
		(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
		VALUES ('s','','https',443,?,'UA','t13d','ok',0,'serve',0,0,'','',?,datetime('now'))`,
		[]byte{192, 0, 2, 9}, `{"bt":"s1","orig_path":"/members/","referer":"https://news.example.com/thread/42"}`); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, req)
	if err := os.WriteFile(out, rr.Body.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}
