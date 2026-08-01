package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The platform icon rides in FRONT of the summary, not instead of it: the
// name stays searchable and copyable, and the glyph is aria-hidden because
// the platform is already spelled out beside it.
func TestHuntUACellCarriesPlatformIcon(t *testing.T) {
	h := newTestHandler(t)
	const win = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	if _, err := h.DB.Exec(`INSERT INTO unmask_event
		(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
		 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
		VALUES ('','','https',443,x'7f000001',?,'','',0,'serve',0,0,'','','{}',datetime('now'))`, win); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?range=24h", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("hunt: %d", rr.Code)
	}
	body := rr.Body.String()

	// Order: platform glyph, browser dot, then the text.  Assert the sequence
	// rather than adjacency so adding a marker between them does not read as
	// a regression.
	osIdx := strings.Index(body, `class="ua-os" aria-hidden="true">🪟</span>`)
	txt := strings.Index(body, "Windows 10")
	if osIdx < 0 || txt < 0 {
		t.Fatalf("UA cell parts missing (os=%d text=%d)", osIdx, txt)
	}
	if osIdx > txt {
		t.Error("the platform glyph must precede the platform name")
	}
	// The browser mark sits in front of the BROWSER name, not next to the
	// platform glyph: each half of the summary carries its own marker.
	bi := strings.Index(body, `<use href="#bi-chrome"`)
	plat := strings.Index(body, "Windows 10")
	name := strings.Index(body, "Chrome 126")
	if bi < 0 {
		t.Fatal("the drawn browser mark is missing")
	}
	if !(plat < bi && bi < name) {
		t.Error("the browser mark must sit between the platform text and the browser name")
	}
	// The sprite it references is defined on the page.
	if !strings.Contains(body, `<symbol id="bi-chrome"`) {
		t.Error("the browser sprite symbol is not defined; the <use> would render nothing")
	}
	// The label survives: an icon-only cell would not be searchable.
	if !strings.Contains(body, "Chrome 126") {
		t.Error("the summary text was replaced by the icon")
	}
}

// Pinning a UA cell names the summary in the popover's TITLE bar, not in its
// body.  A pinned popover can be dragged away from its row, and the raw UA
// alone gives no clue which reading produced it -- but the copy button takes
// the body's text verbatim, so a summary line there would be pasted along
// with the UA every time.
func TestUAPopoverTitleCarriesTheSummary(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?range=24h", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, req)
	body := rr.Body.String()

	if !strings.Contains(body, "function popTitle(") {
		t.Fatal("the pin title helper is gone; the summary would be lost on a dragged popover")
	}
	// Passed as handleClick's title argument, NOT built into popHtml.
	if !strings.Contains(body, "popTitle(el, val)") {
		t.Error("the pin does not receive the cell's summary as its title")
	}
	// Hover carries the summary as a heading INSIDE the popover, because the
	// hover popover has no tools -- only the pinned clone has the copy
	// button, and that one keeps its body verbatim.
	if !strings.Contains(body, "pin.showHover(popHtml(val, url, summaryHTML(el, val), note)") {
		t.Error("hover no longer shows the summary; it would only appear after pinning")
	}
	// Hover reuses the cell's rendered markup so the icons survive; flattening
	// it to text would drop the platform glyph and the <svg> browser mark.
	if !strings.Contains(body, "function summaryHTML(") || !strings.Contains(body, "el.innerHTML") {
		t.Error("the hover heading no longer reuses the cell's markup; its icons would be lost")
	}
	// The pin title is a NODE for the same reason -- the title bar sets
	// textContent, which cannot carry an <svg>.
	if !strings.Contains(body, "createDocumentFragment()") {
		t.Error("the pin title is back to a flat string; the browser icon cannot appear there")
	}
	if !strings.Contains(body, "cellpop-summary") {
		t.Error("the hover summary heading is missing")
	}
	// The pinned call must NOT pass a summary into the body (it has the title
	// bar for that).  The row note is a separate argument and does ride the
	// body -- deliberately, since two stacked tooltips read worse than a copy
	// that includes one sentence.
	if !strings.Contains(body, "pin.handleClick(popHtml(val, url, '', el.getAttribute('data-note')") {
		t.Error("the pinned popover body no longer receives the raw value alone; copy would include the summary")
	}
	// The bot-claim reading lives in the popover, never as a native title=
	// on the badge: the cell already opens a popover on hover, and both at
	// once put two boxes in the same corner.
	if strings.Contains(body, `class="ua-bot ua-bot-listed" title=`) ||
		strings.Contains(body, `class="ua-bot ua-bot-self" title=`) {
		t.Error("the bot badge still carries a native title tooltip")
	}
	if !strings.Contains(body, "cellpop-note") {
		t.Error("the popover has no slot for the row note")
	}
	// The popover is a WHITE surface (popover-pin.css: background #fff, body
	// text #0f172a), so the note has to be a dark slate -- the first cut used
	// #cbd5e1, a value for dark backgrounds, and it rendered nearly invisible.
	if !strings.Contains(body, ".cellpop-note{") || !strings.Contains(body, "color:#475569}") {
		t.Error("the row note is not readable slate on the popover's white background")
	}
}
