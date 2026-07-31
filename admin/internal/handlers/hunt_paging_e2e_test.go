package handlers

import (
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"regexp"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/events"
)

var (
	nextLinkRe = regexp.MustCompile(`href="([^"]+)"[^>]*rel="next"`)
	ipCellRe   = regexp.MustCompile(`\b10\.9\.(\d+)\.(\d+)\b`)
)

// The operator's actual complaint, driven through the rendered page: open the
// hunt log, let events keep arriving, follow the "next" link, and see rows from
// the previous page again.  Nothing here reaches into the query layer -- it
// clicks what the page renders, so the freeze id has to survive templating and
// URL building for this to pass.
func TestFollowingTheNextLinkDoesNotShowTheSameRowsAgain(t *testing.T) {
	h := newTestHandler(t)
	seed := func(from, n int) {
		t.Helper()
		for i := 0; i < n; i++ {
			ip := fmt.Sprintf("10.9.%d.%d", (from+i)/250, (from+i)%250)
			if _, err := h.DB.Exec(`INSERT INTO unmask_event
				(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
				 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
				VALUES ('','','https',443,?,'UA','','',0,'serve',0,0,'','','{}',
				        datetime('now', ?))`,
				events.PackIP(ip), fmt.Sprintf("-%d seconds", 10000-(from+i))); err != nil {
				t.Fatal(err)
			}
		}
	}
	get := func(url string) string {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, url, nil)
		rr := httptest.NewRecorder()
		h.AdminHuntIndex(rr, r)
		if rr.Code != http.StatusOK {
			t.Fatalf("GET %s: %d", url, rr.Code)
		}
		return rr.Body.String()
	}
	shownIPs := func(body string) map[string]bool {
		out := map[string]bool{}
		for _, m := range ipCellRe.FindAllString(body, -1) {
			out[m] = true
		}
		return out
	}

	seed(1, 250)

	page1 := get("/unmask/admin/hunt/?range=24h")
	first := shownIPs(page1)
	if len(first) == 0 {
		t.Fatal("page 1 rendered no event rows -- the seed or the selector is wrong")
	}

	m := nextLinkRe.FindStringSubmatch(page1)
	if m == nil {
		t.Fatal(`page 1 rendered no rel="next" link, so there is nothing to follow`)
	}
	next := html.UnescapeString(m[1])

	// Traffic keeps arriving while the operator reads -- more than one page of it.
	seed(900, 150)

	page2 := shownIPs(get("/unmask/admin/hunt/" + next))
	var repeated []string
	for ip := range page2 {
		if first[ip] {
			repeated = append(repeated, ip)
		}
	}
	if len(repeated) > 0 {
		t.Errorf("following %q showed %d rows again that were already on page 1: %v",
			next, len(repeated), repeated)
	}
	if len(page2) == 0 {
		t.Error("page 2 rendered no rows at all")
	}
}

// "First" is the way back to a moving log: it must show events that arrived
// after paging started, which is exactly what the paging links hide.
func TestFirstLinkReturnsToTheNewestEvents(t *testing.T) {
	h := newTestHandler(t)
	ins := func(ip string, ageSec int) {
		t.Helper()
		if _, err := h.DB.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,
			 phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','https',443,?,'UA','','',0,'serve',0,0,'','','{}',
			        datetime('now', ?))`,
			events.PackIP(ip), fmt.Sprintf("-%d seconds", ageSec)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 150; i++ {
		ins(fmt.Sprintf("10.9.%d.%d", i/250, i%250), 500+i)
	}
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?range=24h", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, r)
	firstLink := regexp.MustCompile(`href="([^"]*)"[^>]*aria-label="[^"]*"[^>]*>«`).
		FindStringSubmatch(rr.Body.String())

	// A brand new event lands after the page was rendered.
	ins("10.9.7.7", 1)

	url := "/unmask/admin/hunt/?range=24h"
	if firstLink != nil {
		url = "/unmask/admin/hunt/" + html.UnescapeString(firstLink[1])
	}
	r2 := httptest.NewRequest(http.MethodGet, url, nil)
	rr2 := httptest.NewRecorder()
	h.AdminHuntIndex(rr2, r2)
	if rr2.Code != http.StatusOK {
		t.Fatalf("GET %s: %d", url, rr2.Code)
	}
	if !regexp.MustCompile(`\b10\.9\.7\.7\b`).MatchString(rr2.Body.String()) {
		t.Errorf("the newest event is missing from %q -- first must not stay frozen", url)
	}
}
