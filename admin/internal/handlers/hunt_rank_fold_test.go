package handlers

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// The four rank cards share one row and the widest data decides what is left
// for the others, so an operator who does not need a card right now folds it
// and hands its width to the ones they do.  The state is resolved from the
// cookie server-side: folding in JS after paint would render the row at full
// width and then jump.
func TestRankCardFoldingComesFromTheCookie(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)

	get := func(cookie string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/", nil)
		if cookie != "" {
			req.Header.Set("Cookie", cookie)
		}
		rr := httptest.NewRecorder()
		h.AdminHuntIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("hunt: %d", rr.Code)
		}
		return rr.Body.String()
	}
	folded := func(body, key string) bool {
		i := strings.Index(body, `data-rank-card="`+key+`"`)
		if i < 0 {
			t.Fatalf("no %s card", key)
		}
		// The class list precedes the attribute on the same element.
		start := strings.LastIndex(body[:i], `<div class="`)
		return strings.Contains(body[start:i], "folded")
	}

	if body := get(""); folded(body, "ip") || folded(body, "ja4") {
		t.Error("no cookie must mean nothing folded")
	}
	body := get("unmask_rank_fold=ip%2Cja4")
	if !folded(body, "ip") || !folded(body, "ja4") {
		t.Error("the cookie's cards are not folded on the server-rendered page")
	}
	if folded(body, "ua") {
		t.Error("a card not in the cookie was folded")
	}
	// The value is operator-supplied and lands in a class name.
	if body := get("unmask_rank_fold=ip,%22%3E%3Cscript%3E"); !folded(body, "ip") {
		t.Error("a junk entry alongside a real one dropped the real one")
	} else if strings.Contains(body, "<script>\"") {
		t.Error("an unknown fold key reached the markup")
	}
	// All four folded is an empty row with no way back except the cookie.
	if body := get("unmask_rank_fold=ip,asn,ja4,ua"); folded(body, "ip") {
		t.Error("every card folded: the row would render empty with no control left to click")
	}
}

// Folding a card can hand the UA column enough width to read a raw string, and
// an operator chasing a spoofed UA wants the whole thing rather than
// "Windows 10+ · Chrome 142".  Both forms are rendered and CSS picks one, so
// the switch costs no round trip.
func TestUACardCanShowTheRawString(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	const ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	if _, err := h.DB.Exec(
		`INSERT INTO unmask_event (ip_address, host, phase, user_agent, date_created)
		 VALUES (x'7f000001', 'example.com', 'serve', ?, datetime('now'))`, ua); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/", nil)
	req.Header.Set("Cookie", "unmask_rank_ua_full=1")
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, req)
	body := rr.Body.String()
	i := strings.Index(body, `data-rank-card="ua"`)
	if i < 0 {
		t.Fatal("no UA card")
	}
	if !strings.Contains(body[strings.LastIndex(body[:i], `<div class="`):i], "ua-full") {
		t.Error("the cookie did not put the UA card into full mode")
	}
	card := body[i : i+strings.Index(body[i:], "</table>")]
	if !strings.Contains(card, `class="ua-sum"`) || !strings.Contains(card, `class="ua-raw"`) {
		t.Error("the UA cell no longer carries both forms; the switch would need a round trip")
	}

	// The popover clones this markup to a body-level element, outside the card,
	// so the raw copy has to be hidden by a rule that does not depend on the
	// card -- otherwise the popover heading reads as the raw string twice.
	tpl, err := os.ReadFile("../../assets/templates/hunt.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(tpl), "\n.ua-raw{display:none}") {
		t.Error("the raw UA is hidden by a card-scoped rule only; it will show inside the popover too")
	}
}
