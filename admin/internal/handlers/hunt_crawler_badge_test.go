package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A crawler-claiming row is marked in the hunt log.  The reason this is worth
// marking: a genuine crawler that passes on its published IP range never
// reaches the challenge flow, so a row here claiming one is a request that did
// NOT verify -- on this fleet, every Googlebot in the log was a spoof from
// outside Google's ranges.  Naming and marking it turns spoof-hunting into
// scanning rather than reading full UA strings.
func TestHuntMarksCrawlerRows(t *testing.T) {
	h := newTestHandler(t)
	const bot = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
	const human = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	for _, ua := range []string{bot, human} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
			 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','https',443,x'7f000001',?,'','',0,'serve',0,0,'','','{}',datetime('now'))`, ua); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?range=24h", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("hunt: %d", rr.Code)
	}
	body := rr.Body.String()

	if !strings.Contains(body, `<use href="#bi-bot"/></svg>Googlebot</span>`) {
		t.Error("the crawler row does not render its name in a marked badge with the bot mark")
	}
	// A LISTED crawler gets the warning colour: its vendor is known and the
	// big ones publish egress ranges, so the name appearing HERE means the
	// request did not verify.
	if !strings.Contains(body, "ua-bot ua-bot-listed") {
		t.Error("a listed crawler is not marked as listed")
	}
	// The human row is summarised as usual, not marked.
	if !strings.Contains(body, "Chrome 126") {
		t.Error("the ordinary browser row lost its summary")
	}
	// Count in the ROWS only: the column header's legend carries sample
	// badges of both kinds, which are not rows.
	rows := rowsOnly(body)
	if n := strings.Count(rows, `class="ua-bot `); n != 1 {
		t.Errorf("expected exactly one marked row, found %d", n)
	}
	// The full string stays available in the popover.
	if !strings.Contains(body, "bot.html") {
		t.Error("the raw crawler UA is no longer reachable from the row")
	}
}

// A bot that is not on the curated list but names itself gets the same mark:
// the badge says "this row is a bot", and an unlisted crawler sitting in the
// challenge log is exactly as unverified as a listed one.  Amzn-SearchBot was
// the single biggest unsummarised UA on live traffic.
func TestHuntMarksSelfDeclaredBots(t *testing.T) {
	h := newTestHandler(t)
	const bot = "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Amzn-SearchBot/0.1) Chrome/119.0.6045.214 Safari/537.36"
	if _, err := h.DB.Exec(`INSERT INTO unmask_event
		(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
		 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
		VALUES ('','','https',443,x'7f000001',?,'','',0,'serve',0,0,'','','{}',datetime('now'))`, bot); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?range=24h", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, `<use href="#bi-bot"/></svg>Amzn-SearchBot</span>`) {
		t.Error("a self-declared bot is not marked; it would read as an ordinary Chrome row")
	}
	// But NOT as a listed one: nothing was verified and nothing failed, so
	// wearing the same colour would claim a check that never happened.
	if !strings.Contains(body, "ua-bot ua-bot-self") {
		t.Error("a self-declared bot is not distinguished from a listed crawler")
	}
	// Scope to the rendered row: the stylesheet and the header legend in the
	// same document both name the classes, so a document-wide search would
	// always find "listed".
	rows := rowsOnly(body)
	if i := strings.Index(rows, `class="ua-bot `); i >= 0 {
		row := rows[i:]
		if end := strings.Index(row, "</span>"); end > 0 {
			row = row[:end]
		}
		if strings.Contains(row, "ua-bot-listed") {
			t.Error("a self-declared bot was marked as a listed crawler")
		}
	}
}

// The popover explains which KIND of bot the row is.  The badge carries the
// distinction only as a colour, and colour alone does not say what it means --
// "listed" (a known vendor, so its name here means it failed verification) vs
// "self-declared" (nothing to verify against) are different findings.
//
// The text is read off the badge's own title at render time, so the popover
// cannot drift from the row: one classification, rendered twice.
func TestUAColumnHeaderExplainsTheBotKinds(t *testing.T) {
	h := newTestHandler(t)
	for _, ua := range []string{
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
		"Mozilla/5.0 official-url-checker/1.0",
	} {
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
			 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','https',443,x'7f000001',?,'','',0,'serve',0,0,'','','{}',datetime('now'))`, ua); err != nil {
			t.Fatal(err)
		}
	}
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?range=24h", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, req)
	body := rr.Body.String()

	// Per-row, the badge still carries its own one-line explanation on hover.
	if !strings.Contains(body, "自称 bot") && !strings.Contains(body, "Self-declared bot") {
		t.Error("the self-declared badge does not say it is only a claim")
	}
	if strings.Contains(body, "hunt.ua.bot_") {
		t.Error("a raw i18n key leaked into the render")
	}
	// The column HEADER carries the legend: the badge colours are the
	// indicator, and what they mean belongs once at the top of the column
	// rather than repeated on every row's popover.
	th := body[strings.Index(body, "<th>UA "):]
	if end := strings.Index(th, "</th>"); end > 0 {
		th = th[:end]
	}
	if !strings.Contains(th, "info-tip") {
		t.Error("the UA column header has no help affordance")
	}
	for _, want := range []string{"crawler-user-agents.json", "ua-bot-listed", "ua-bot-self"} {
		if !strings.Contains(th, want) {
			t.Errorf("the UA header legend does not explain %q", want)
		}
	}
}

// rowsOnly narrows to the event table's BODY.  The page holds other tables
// and the UA column's legend (which carries sample badges of both kinds), so
// counting badges document-wide answers a different question than "how many
// rows are marked".
func rowsOnly(body string) string {
	i := strings.Index(body, `<table class="events"`)
	if i < 0 {
		return body
	}
	rest := body[i:]
	if j := strings.Index(rest, "<tbody"); j >= 0 {
		rest = rest[j:]
	}
	if k := strings.Index(rest, "</table>"); k > 0 {
		rest = rest[:k]
	}
	return rest
}
