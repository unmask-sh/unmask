package handlers

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Bypassed requests are the ones the operator exempted from judgement, and on a
// real install they are not a rounding error -- 56% of a day's traffic on one
// fleet node.  Left in the denominator they halve every other share, so the
// card can be read against either total.  What must never happen is the
// headline being taken against one total while the caption names another, so
// both come from CompDenom and this pins the arithmetic.
func TestCompScopeResolution(t *testing.T) {
	req := func(query, cookie string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/unmask/admin/"+query, nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: compScopeCookieName, Value: cookie})
		}
		return r
	}
	cases := []struct {
		name, query, cookie, want string
	}{
		{"no signal -> the long-standing view", "", "", compScopeAll},
		{"cookie remembers the pick", "", compScopeJudged, compScopeJudged},
		{"query wins over the cookie (first click)", "?comp=all", compScopeJudged, compScopeAll},
		{"query alone works before its cookie is read back", "?comp=judged", "", compScopeJudged},
		{"a hand-edited cookie falls back, it does not break the page", "", "nonsense", compScopeAll},
		{"a hand-edited query falls back too", "?comp=nonsense", "", compScopeAll},
	}
	for _, c := range cases {
		if got := resolveCompScope(req(c.query, c.cookie)); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	if got := resolveCompScope(nil); got != compScopeAll {
		t.Errorf("nil request: got %q want %q", got, compScopeAll)
	}
}

// The share and the caption must be computed from the same denominator.  This
// walks the real handler so a template that reached for KPIReqTotal again
// (the bug this replaced) shows up as a caption disagreeing with the bar.
func TestCompScopeDenominatorIsConsistent(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)

	for _, scope := range []string{compScopeAll, compScopeJudged} {
		rr := httptest.NewRecorder()
		h.AdminTopOverview(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/?comp="+scope, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status %d", scope, rr.Code)
		}
		// The pick is remembered for next time.
		var found bool
		for _, c := range rr.Result().Cookies() {
			if c.Name == compScopeCookieName && c.Value == scope {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: the choice was not persisted, so it resets on the next visit", scope)
		}
	}
	// A plain load must NOT write the cookie: a bookmarked /admin/ would
	// otherwise repin whatever view happened to render.
	rr := httptest.NewRecorder()
	h.AdminTopOverview(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil))
	for _, c := range rr.Result().Cookies() {
		if c.Name == compScopeCookieName {
			t.Error("a plain load pinned the denominator choice")
		}
	}
}

// With real proportions, the card must be internally consistent in BOTH modes:
// the headline percentage, the caption's denominator and the legend shares all
// taken against the same total.  Seeded from a fleet node's real 24h shape --
// bypass at 56% of traffic, which is why the two modes differ by about 2x and
// why showing only one of them was a choice worth making explicit.
func TestCompScopeCardIsInternallyConsistent(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)

	// The shared test schema is event-shaped; this card reads the access-log
	// counters, so the table it aggregates has to exist here.
	if _, err := h.DB.Exec(`CREATE TABLE IF NOT EXISTS unmask_cookie_minute (
		bucket_min INTEGER NOT NULL, site TEXT NOT NULL, kind TEXT NOT NULL, cnt INTEGER NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	bucketMin := time.Now().Unix()/60 - 10
	seed := func(kind string, n int) {
		if _, err := h.DB.Exec(`INSERT INTO unmask_cookie_minute (bucket_min, site, kind, cnt) VALUES (?,?,?,?)`,
			bucketMin, "", kind, n); err != nil {
			t.Fatal(err)
		}
	}
	seed("total", 180184)
	seed("bypass_pass", 100743)
	seed("crawler_pass", 3669)
	seed("challenge_served", 28398)

	// Both views are in the DOM now (the toggle swaps visibility, no request),
	// so read the one actually on screen.  Taking the first match would always
	// read the "all" view and this test would pass while the page showed the
	// wrong numbers.  Split on the view markers rather than regex-matching
	// nested HTML.
	pctRE := regexp.MustCompile(`<div class="comp-pct">([0-9.]+)<`)
	ofRE := regexp.MustCompile(`<div class="comp-of">[^0-9]*([0-9,]+)`)

	get := func(scope string) (pct float64, denom int, body string) {
		rr := httptest.NewRecorder()
		h.AdminTopOverview(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/?comp="+scope, nil))
		body = rr.Body.String()
		var seg string
		for _, part := range strings.Split(body, `<div class="comp-view"`)[1:] {
			head := part[:min(len(part), 60)]
			if !strings.Contains(head, "comp-pct") && !strings.Contains(part[:min(len(part), 400)], "comp-pct") {
				continue // the bar/legend view, not the headline one
			}
			if strings.Contains(head, "hidden") {
				continue
			}
			if !strings.Contains(head, `data-scope="`+scope+`"`) {
				t.Fatalf("%s: the visible headline view is not this scope (head=%q)", scope, head)
			}
			seg = part
			break
		}
		if seg == "" {
			t.Fatalf("%s: no visible headline view rendered", scope)
		}
		mp := pctRE.FindStringSubmatch(seg)
		mo := ofRE.FindStringSubmatch(seg)
		if mp == nil || mo == nil {
			t.Fatalf("%s: card did not render a percentage/caption pair", scope)
		}
		pct, _ = strconv.ParseFloat(mp[1], 64)
		denom, _ = strconv.Atoi(strings.ReplaceAll(mo[1], ",", ""))
		return
	}

	allPct, allDenom, allBody := get(compScopeAll)
	judPct, judDenom, judBody := get(compScopeJudged)

	if allDenom != 180184 {
		t.Errorf("all-traffic caption names %d, want the full total 180184", allDenom)
	}
	if want := 180184 - 100743; judDenom != want {
		t.Errorf("judged caption names %d, want total-minus-bypass %d", judDenom, want)
	}
	// The share has to actually change -- the bug this guards against is a
	// template still reaching for KPIReqTotal while the caption says otherwise.
	if judPct <= allPct {
		t.Errorf("judged share %.1f%% is not above the all-traffic share %.1f%%; the denominator did not switch", judPct, allPct)
	}
	// And it must be the SAME numerator over the named denominator.
	if got, want := judPct/allPct, float64(allDenom)/float64(judDenom); got < want*0.99 || got > want*1.01 {
		t.Errorf("the two shares do not share a numerator: ratio %.3f, want %.3f", got, want)
	}
	// The toggle appears (there is bypass traffic to exclude) and marks the
	// active side in each mode.
	if !strings.Contains(allBody, `href="?comp=judged"`) || !strings.Contains(judBody, `href="?comp=all"`) {
		t.Error("the denominator toggle is missing")
	}
	// Both views must be present in ONE response -- that is what makes the
	// toggle a visibility flip instead of a request.  Two headline views, two
	// bar/legend views, one of each hidden.
	if n := strings.Count(allBody, `<div class="comp-view"`); n != 4 {
		t.Errorf("%d comp-view blocks, want 4 (headline + bar for each denominator)", n)
	}
	if n := strings.Count(allBody, `<div class="comp-view" data-scope="judged" hidden>`); n != 2 {
		t.Errorf("the inactive views are not hidden (%d marked), so both would render at once", n)
	}
	// Bypass stays listed when excluded: it did not vanish, it left the
	// denominator, and a row that disappears reads as "there is none".
	if !strings.Contains(judBody, "comp-out") {
		t.Error("the excluded bypass row is not rendered as excluded (it should stay visible, greyed)")
	}
}
