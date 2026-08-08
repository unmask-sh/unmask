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

// The two named denominators are presets over one state now: a set of enabled
// segments.  What must never happen is unchanged -- the headline percentage,
// the caption's total and every share taken against different denominators --
// and the state names must stay stable, because they live in bookmarks and a
// year-long cookie.
func TestCompSegsResolution(t *testing.T) {
	req := func(query, cookie string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/unmask/admin/"+query, nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: compSegCookieName, Value: cookie})
		}
		return r
	}
	name := func(r *http.Request) string { return compSegsParam(resolveCompSegs(r)) }
	cases := []struct {
		name, query, cookie, want string
	}{
		{"no signal -> the long-standing view", "", "", "all"},
		{"cookie remembers the pick", "", "judged", "judged"},
		{"query wins over the cookie (first click)", "?comp=all", "judged", "all"},
		{"query alone works before its cookie is read back", "?comp=judged", "", "judged"},
		{"a custom subset is a state of its own", "?comp=benign,bad", "", "benign-bad"},
		{"subset order is canonical, not what was typed", "?comp=bad-benign", "", "benign-bad"},
		{"every segment on IS the all preset", "?comp=benign-bad-bypass-human-other", "", "all"},
		{"all minus bypass IS the judged preset", "?comp=benign-bad-human-other", "", "judged"},
		{"unknown tokens are dropped, not fatal", "?comp=benign-junk", "", "benign"},
		{"a hand-edited cookie falls back, it does not break the page", "", "nonsense", "all"},
		{"a hand-edited query falls back too", "?comp=nonsense", "", "all"},
		{"a custom subset sticks in the cookie", "", "bad-human", "bad-human"},
	}
	for _, c := range cases {
		if got := name(req(c.query, c.cookie)); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	if got := name(nil); got != "all" {
		t.Errorf("nil request: got %q want %q", got, "all")
	}
}

// The pick is persisted exactly as its canonical name, and only for an
// explicit ?comp= -- a bookmarked plain /admin/ must not repin the session.
func TestCompSegsCookiePersistence(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)

	get := func(query string) []*http.Cookie {
		rr := httptest.NewRecorder()
		h.AdminTopOverview(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/"+query, nil))
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status %d", query, rr.Code)
		}
		return rr.Result().Cookies()
	}
	find := func(cs []*http.Cookie) *http.Cookie {
		for _, c := range cs {
			if c.Name == compSegCookieName {
				return c
			}
		}
		return nil
	}
	for query, want := range map[string]string{
		"?comp=judged":     "judged",
		"?comp=bad,benign": "benign-bad", // canonicalised before storing (comma tolerated on input)
	} {
		if c := find(get(query)); c == nil || c.Value != want {
			t.Errorf("%s: persisted %v, want %q", query, c, want)
		}
	}
	if c := find(get("")); c != nil {
		t.Error("a plain load pinned the segment choice")
	}
	if c := find(get("?comp=nonsense")); c != nil {
		t.Error("an unparseable choice was persisted instead of ignored")
	}
}

// With real proportions the card must be internally consistent in EVERY state:
// the headline, the caption and each share against the same denominator.  The
// expectations are recomputed from the counts the page itself advertises on
// its chips, so the test pins the arithmetic contract rather than one seed's
// numbers.
func TestCompSegsCardIsInternallyConsistent(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)

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

	pctRE := regexp.MustCompile(`<div class="comp-pct">([0-9.]+)<`)
	ofRE := regexp.MustCompile(`<div class="comp-of">[^0-9]*([0-9,]+)`)
	chipRE := regexp.MustCompile(`class="comp-chip( comp-out)?" data-key="([a-z]+)" data-count="([0-9]+)" data-nonhuman="(true|false)"`)
	totalRE := regexp.MustCompile(`data-total="([0-9]+)"`)

	type chip struct {
		out      bool
		count    int
		nonhuman bool
	}
	get := func(state string) (pct float64, denom, total int, chips map[string]chip, body string) {
		rr := httptest.NewRecorder()
		h.AdminTopOverview(rr, httptest.NewRequest(http.MethodGet, "/unmask/admin/?comp="+state, nil))
		body = rr.Body.String()
		mp := pctRE.FindStringSubmatch(body)
		mo := ofRE.FindStringSubmatch(body)
		mt := totalRE.FindStringSubmatch(body)
		if mp == nil || mo == nil || mt == nil {
			t.Fatalf("%s: card did not render pct/caption/total", state)
		}
		pct, _ = strconv.ParseFloat(mp[1], 64)
		denom, _ = strconv.Atoi(strings.ReplaceAll(mo[1], ",", ""))
		total, _ = strconv.Atoi(mt[1])
		chips = map[string]chip{}
		for _, m := range chipRE.FindAllStringSubmatch(body, -1) {
			n, _ := strconv.Atoi(m[3])
			chips[m[2]] = chip{out: m[1] != "", count: n, nonhuman: m[4] == "true"}
		}
		if len(chips) != 5 {
			t.Fatalf("%s: %d chips rendered, want all 5 segments visible in every state", state, len(chips))
		}
		return
	}

	// In every state: denom == total - sum(excluded counts), and
	// pct == enabled non-human / denom.
	check := func(state string, wantOut ...string) {
		t.Helper()
		pct, denom, total, chips, body := get(state)
		outSet := map[string]bool{}
		for _, k := range wantOut {
			outSet[k] = true
		}
		wantDenom := total
		nonhuman := 0
		for k, c := range chips {
			if c.out != outSet[k] {
				t.Errorf("%s: chip %q excluded=%v, want %v", state, k, c.out, outSet[k])
			}
			if c.out {
				wantDenom -= c.count
			} else if c.nonhuman {
				nonhuman += c.count
			}
		}
		if denom != wantDenom {
			t.Errorf("%s: caption names %d, want total-minus-excluded %d", state, denom, wantDenom)
		}
		if denom > 0 {
			want := float64(nonhuman) / float64(denom) * 100
			if pct < want-0.06 || pct > want+0.06 {
				t.Errorf("%s: headline %.1f%%, want %.1f%% (enabled non-human over the named denominator)", state, pct, want)
			}
		}
		// An excluded chip keeps its count but shows no share.
		if len(wantOut) > 0 && !strings.Contains(body, "comp-out") {
			t.Errorf("%s: no excluded chip is marked", state)
		}
	}
	check("all")
	check("judged", "bypass")
	check("benign-bad", "bypass", "human", "other")
	check("human", "benign", "bad", "bypass", "other")

	// The judged share must exceed the all share (same numerator, smaller
	// denominator) -- the historical contract of the preset pair.
	allPct, allDenom, _, _, allBody := get("all")
	judPct, judDenom, _, _, judBody := get("judged")
	if judPct <= allPct {
		t.Errorf("judged share %.1f%% is not above the all share %.1f%%", judPct, allPct)
	}
	if got, want := judPct/allPct, float64(allDenom)/float64(judDenom); got < want*0.99 || got > want*1.01 {
		t.Errorf("the two shares do not share a numerator: ratio %.3f, want %.3f", got, want)
	}
	// Presets render as links over the same state and mark the active one.
	if !strings.Contains(allBody, `href="?comp=judged"`) || !strings.Contains(judBody, `href="?comp=all"`) {
		t.Error("the preset links are missing")
	}
	if !regexp.MustCompile(`data-preset="judged"[^>]*class="on"`).MatchString(judBody) {
		t.Error("the active preset is not marked")
	}

	// Every enabled chip links to the state with itself toggled off; the LAST
	// enabled segment must not be a link at all -- a share of nothing answers
	// nothing.
	if !strings.Contains(allBody, `href="?comp=bad-bypass-human-other"`) {
		t.Error("the benign chip does not link to the state without benign")
	}
	_, _, _, _, soloBody := get("human")
	solo := regexp.MustCompile(`data-key="human"[^>]*>.{0,400}?<a class="comp-tgl comp-tgl-pinned"`)
	if !solo.MatchString(soloBody) {
		t.Error("the last enabled segment still renders as a toggle link")
	}
}
