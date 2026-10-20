package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/live"
)

// The strip's scope: the query parameter switches, the cookie keeps, and
// without either the requests tile counts the requests unmask judged.
func TestLiveScopeResolution(t *testing.T) {
	req := func(query, cookie string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/unmask/admin/live/"+query, nil)
		if cookie != "" {
			r.AddCookie(&http.Cookie{Name: liveScopeCookieName, Value: cookie})
		}
		return r
	}
	for _, c := range []struct{ name, query, cookie, want string }{
		{"no signal -> judged", "", "", liveScopeJudged},
		{"the cookie remembers all", "", "all", liveScopeAll},
		{"the query wins over the cookie", "?scope=judged", "all", liveScopeJudged},
		{"the query alone", "?scope=all", "", liveScopeAll},
		{"a hand-edited cookie falls back", "", "nonsense", liveScopeJudged},
		{"a hand-edited query falls back", "?scope=nonsense", "", liveScopeJudged},
	} {
		if got := resolveLiveScope(req(c.query, c.cookie)); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
	if got := resolveLiveScope(nil); got != liveScopeJudged {
		t.Errorf("nil request: %q", got)
	}
}

// Under the judged scope the requests tile leaves out the bypassed requests
// -- its last minute, its half hour and its rate -- and is named for it; under
// all it counts every request as before.  The other tiles do not move.
func TestLiveRequestsTileJudged(t *testing.T) {
	h := &Handler{Live: live.New()}
	now := time.Date(2026, 10, 18, 1, 2, 3, 0, time.UTC)
	for i := 0; i < 3; i++ {
		h.Live.Hit(now, "JP", live.Of(live.Requests, live.Pass))
	}
	h.Live.Hit(now, "JP", live.Of(live.Requests, live.Bypass))
	h.Live.Hit(now, "JP", live.Of(live.Requests, live.Crawler)) // a listed crawler: judged, so it stays
	h.Live.Hit(now.Add(-70*time.Second), "US", live.Of(live.Requests, live.Bypass))

	all := h.liveView(now, "", liveScopeAll)
	if r := all.Tiles[0]; r.Key != "requests" || r.Last != 5 || r.Last30 != 6 || r.LabelKey != "overview.live.requests" || r.TPS != "1.0" || r.Crawler30 != 1 {
		t.Errorf("all: %+v", r)
	}
	jud := h.liveView(now, "", liveScopeJudged)
	if jud.Scope != liveScopeJudged {
		t.Errorf("scope = %q", jud.Scope)
	}
	if r := jud.Tiles[0]; r.Last != 4 || r.Last30 != 4 || r.LabelKey != "overview.live.requests_judged" || r.TPS != "0.8" || r.Crawler30 != 1 {
		t.Errorf("judged: %+v", r)
	}
	if b := jud.Tiles[7]; b.Key != "bypass" || b.Last30 != 2 { // the last tile
		t.Errorf("the bypass tile should still count the bypassed requests: %+v", b)
	}
}

// The JSON the page polls carries the judged reading beside the others, its
// rate caption worded like tps_text.
func TestAdminNowJSONCarriesTheJudgedRequests(t *testing.T) {
	h := &Handler{Live: live.New()}
	now := time.Now()
	for i := 0; i < 3; i++ {
		h.Live.Hit(now, "JP", live.Of(live.Requests, live.Pass))
	}
	h.Live.Hit(now, "JP", live.Of(live.Requests, live.Bypass))

	rec := httptest.NewRecorder()
	h.AdminNowJSON(rec, httptest.NewRequest(http.MethodGet, "/unmask/admin/api/now", nil))
	var out struct {
		Last           map[string]uint32 `json:"last"`
		TPSText        string            `json:"tps_text"`
		RequestsJudged struct {
			Last    uint32   `json:"last"`
			Last30  uint32   `json:"last30"`
			Minutes []uint32 `json:"minutes"`
			Series  []uint32 `json:"series"`
			TPSText string   `json:"tps_text"`
		} `json:"requests_judged"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	j := out.RequestsJudged
	if out.Last["requests"] != 4 || j.Last != 3 || j.Last30 != 3 || len(j.Minutes) != live.Minutes || len(j.Series) != live.Buckets {
		t.Errorf("requests=%d judged=%+v", out.Last["requests"], j)
	}
	if j.TPSText == "" || j.TPSText == out.TPSText {
		t.Errorf("judged tps_text %q vs all %q", j.TPSText, out.TPSText)
	}
}
