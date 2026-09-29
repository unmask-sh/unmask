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

// A view filtered to the passes holds no serve, so the pass rows arrive with no
// referer of their own -- and must not be read as "the visitor sent none".
// Three things make that hold, and the page has to ship all of them: the state
// both popovers read, the click that loads the session as recorded, and the
// two sentences that stand in for a value until (or unless) one is found.
// The behaviour itself is exercised in a browser by e2e/ui/referer-on-click.
func TestHuntRefererSurvivesPhaseFilter(t *testing.T) {
	h := newTestHandler(t)
	for _, s := range []struct{ phase, payload string }{
		{"serve", `{"bt":"sessf.0001.aaaa","referer":"https://news.example.com/thread/42"}`},
		{"load", `{"bt":"sessf.0001.aaaa"}`},
		{"bv_pow_only", `{"bt":"sessf.0001.aaaa"}`},
		// A silent rebind is its own first request and records the referer itself.
		{"bv_rebind", `{"bt":"sessf.0002.bbbb","reason":"match","referer":"https://github.com/unmask-sh/unmask"}`},
	} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('s','','https',443,?,'UA','t13d','ok',0,?,0,0,'','',?,datetime('now'))`,
			[]byte{192, 0, 2, 11}, s.phase, s.payload); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodGet,
		"/unmask/admin/hunt/?range=1h&phase=bv_pow_only%2Cbv_captcha_only%2Cbv_pow_then_captcha%2Cbv_rebind", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("hunt: %d", rr.Code)
	}
	body := rr.Body.String()

	// The shape under test: the pass is on the page, its serve is not.
	if !strings.Contains(body, `data-bt="sessf.0001.aaaa" data-phase="bv_pow_only"`) {
		t.Fatal("the pass row is not in the filtered view")
	}
	if strings.Contains(body, `data-referer="https://news.example.com/thread/42"`) {
		t.Fatal("the serve's referer is on the page: the filter no longer excludes the serve, and this test no longer covers the filtered shape")
	}
	// The rebind row carries its own.
	if !strings.Contains(body, `data-referer="https://github.com/unmask-sh/unmask"`) {
		t.Error("the rebind row must carry the referer it recorded")
	}
	for _, want := range []string{
		`window.unmaskHuntReferer = (function(){`, // one state for both popovers
		`function loadChain(tr){`,                 // the click that reads the recorded session
		`tr.setAttribute('data-head',`,            // ...and settles the row
		`if (REF.state(rep) === 'unloaded') { loadChain(rep).then(open, open); return; }`, // a chain whose serve is off the page asks too
		`var RS = window.unmaskHuntReferer;`,                                              // the date popover reads the same state
		`未取得。phase をクリックすると読み込みます。`,                                                       // not loaded (the default locale of the test handler)
		`不明。このセッションの serve が、このノードの記録にありません。`,                                             // looked for, not on record
	} {
		if !strings.Contains(body, want) {
			t.Errorf("hunt page lost %q", want)
		}
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
		[]byte{192, 0, 2, 9}, `{"bt":"s1","orig_path":"/members/","referer":"https://news.example.com/thread/42","local_port":80}`); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, req)
	if err := os.WriteFile(out, rr.Body.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Behind a load balancer the client-facing port is inferred from the forwarded
// scheme, so the port nginx actually accepted on is carried alongside it and
// shown as a second tier -- only when the two disagree, which is exactly when
// a hop exists.  An unproxied install records nothing extra and keeps one line.
func TestHuntLocalPortSecondTier(t *testing.T) {
	h := newTestHandler(t)
	for _, s := range []struct{ phase, payload string }{
		// serve carries the accepted port (LB hop); the beacon does not.
		{"serve", `{"bt":"s2","orig_path":"/x/","local_port":80}`},
		{"bv_pow_only", `{"bt":"s2","url":"https://site.example/x/"}`},
	} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('s','','https',443,?,'UA','t13d','ok',0,?,0,0,'','',?,datetime('now'))`,
			[]byte{192, 0, 2, 10}, s.phase, s.payload); err != nil {
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
	if !strings.Contains(body, `data-local-port="80"`) {
		t.Error("the accepted port must ride the row as data-local-port")
	}
	if !strings.Contains(body, `tr.getAttribute('data-local-port')`) || !strings.Contains(body, "LOCAL_PORT_LABEL") {
		t.Error("the Port row must render the accepted port as a second tier")
	}
	if !strings.Contains(body, `rep.setAttribute('data-local-port', lv)`) {
		t.Error("the session collapse must promote the accepted port, else a collapsed session loses it")
	}
}
