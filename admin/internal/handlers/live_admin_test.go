package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/live"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func TestAdminNowJSON(t *testing.T) {
	h := &Handler{Live: live.New()}
	now := time.Now()
	for i := 0; i < 3; i++ {
		h.Live.Hit(now, "JP", live.Of(live.Requests, live.Pass))
	}
	h.Live.Hit(now.Add(-70*time.Second), "US", live.Of(live.Requests, live.Serve))
	h.Live.ObserveEvent(now, "bv_pow_only", "JP", nil)
	h.Live.ObserveEvent(now, "serve", "", map[string]any{"rl": 1})
	h.Live.ObserveEvent(now, "serve", "US", map[string]any{"deny": 1, "force_reason": "asn_deny", "deny_rule": "AS16509"})

	req := httptest.NewRequest("GET", "/unmask/admin/api/now", nil)
	rec := httptest.NewRecorder()
	h.AdminNowJSON(rec, req)
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("status %d, content-type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("a live reading must not be cached: %q", rec.Header().Get("Cache-Control"))
	}
	var out struct {
		Available bool                `json:"available"`
		Step      int                 `json:"step"`
		Window    int                 `json:"window"`
		Series    map[string][]uint32 `json:"series"`
		Last      map[string]uint32   `json:"last"`
		TPS       map[string]float64  `json:"tps"`
		Countries map[string]struct {
			N    uint32 `json:"n"`
			Pass uint32 `json:"pass"`
		} `json:"countries"`
		CountryNames map[string]string   `json:"country_names"`
		Minutes      map[string][]uint32 `json:"minutes"`
		Last30       map[string]uint32   `json:"last30"`
		Countries30  map[string]struct {
			N uint32 `json:"n"`
		} `json:"countries30"`
		FeedOff      bool                     `json:"feed_off"`
		TPSText      string                   `json:"tps_text"`
		Refused30    map[string]uint32        `json:"refused30"`
		RefusedRules map[string][]refusedRule `json:"refused_rules30"`
		RefusedNames map[string]string        `json:"refused_names"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("json: %v\n%s", err, rec.Body.String())
	}
	if !out.Available || out.Step != live.Step || out.Window != live.Window {
		t.Errorf("available=%v step=%d window=%d", out.Available, out.Step, out.Window)
	}
	if out.Last["requests"] != 3 || out.Last["pass"] != 3 || out.Last["solve"] != 1 || out.Last["rate_limit"] != 1 {
		t.Errorf("last = %v", out.Last)
	}
	if len(out.Series["requests"]) != live.Buckets {
		t.Errorf("series has %d buckets, want %d", len(out.Series["requests"]), live.Buckets)
	}
	if out.Countries["JP"].N != 3 || out.Countries["JP"].Pass != 3 {
		t.Errorf("countries = %v", out.Countries)
	}
	if _, ok := out.Countries["US"]; ok {
		t.Error("a country from the previous minute leaked into the window")
	}
	// The map's popover names the source in full, from the same reading.
	// (the names cover the thirty-minute window too, so US is named
	// although it left the last minute.)
	if out.CountryNames["JP"] != "Japan (日本)" || out.CountryNames["US"] == "" || len(out.CountryNames) < len(out.Countries) {
		t.Errorf("country_names = %v", out.CountryNames)
	}
	// The deny pages of the thirty minutes, by reason, with the busiest rules
	// and the reason worded as the dashboard words it.
	if out.Refused30["asn_deny"] != 1 {
		t.Errorf("refused30 = %v", out.Refused30)
	}
	if r := out.RefusedRules["asn_deny"]; len(r) != 1 || r[0].Rule != "AS16509" || r[0].N != 1 || r[0].Label != "AS16509" {
		t.Errorf("refused_rules30 = %v", out.RefusedRules)
	}
	if out.RefusedNames["asn_deny"] == "" || out.RefusedNames["asn_deny"] == "asn_deny" {
		t.Errorf("refused_names = %v", out.RefusedNames)
	}
	// The hit 70 s ago sits one or two minutes back, by where in the minute
	// the reading was taken.
	prevIdx := 29 - int(now.Unix()/60-(now.Unix()-70)/60)
	if out.Last30["requests"] != 4 || len(out.Minutes["requests"]) != 30 || out.Minutes["requests"][29] != 3 || out.Minutes["requests"][prevIdx] != 1 {
		t.Errorf("thirty minutes: last30=%v minutes=%v (70 s ago expected at %d)", out.Last30, out.Minutes["requests"], prevIdx)
	}
	if out.Countries30["US"].N != 1 || out.Countries30["JP"].N != 3 {
		t.Errorf("countries30 = %v", out.Countries30)
	}
	if out.TPS["now"] != 3.0/live.Step {
		t.Errorf("tps = %v", out.TPS)
	}
	// The access-log feed is not configured in this test, but lines were
	// counted, so the strip is not told the feed is off.
	if out.FeedOff {
		t.Error("feed_off with requests counted")
	}
	if out.TPSText == "" || !strings.Contains(out.TPSText, "0.6") {
		t.Errorf("tps_text = %q", out.TPSText)
	}
}

func TestAdminNowJSONWithoutCounter(t *testing.T) {
	h := &Handler{}
	rec := httptest.NewRecorder()
	h.AdminNowJSON(rec, httptest.NewRequest("GET", "/unmask/admin/api/now", nil))
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["available"] != false {
		t.Fatalf("code=%d body=%s err=%v", rec.Code, rec.Body.String(), err)
	}
}

func TestLiveViewTiles(t *testing.T) {
	h := &Handler{Live: live.New()}
	now := time.Date(2026, 10, 10, 1, 2, 3, 0, time.UTC)
	h.Live.Hit(now, "", live.Of(live.Requests, live.Deny))
	h.Live.Hit(now.Add(-65*time.Second), "", live.Of(live.Requests))
	h.Live.Hit(now.Add(-65*time.Second), "", live.Of(live.Requests))
	v := h.liveView(now, "Asia/Tokyo")
	if v.At != "10:02:03" || v.AtTS != now.Unix() {
		t.Errorf("At = %q (%d), want 10:02:03 in Tokyo", v.At, v.AtTS)
	}
	if len(v.Tiles) != len(liveKinds) {
		t.Fatalf("%d tiles", len(v.Tiles))
	}
	req := v.Tiles[0]
	if req.Key != "requests" || req.Last != 1 || req.Last30 != 3 {
		t.Errorf("requests tile = %+v", req)
	}
	if req.TPS != "0.2" || req.Points == "" || !strings.HasPrefix(req.Points, "0.0,") {
		t.Errorf("requests tile tps=%q points=%q", req.TPS, req.Points[:20])
	}
	deny := v.Tiles[5]
	if deny.Key != "deny" || deny.Last != 1 {
		t.Errorf("deny tile = %+v", deny)
	}
	// Nothing configured, nothing counted: the strip says the feed is off.
	empty := &Handler{Live: live.New()}
	if !empty.liveView(now, "").FeedOff {
		t.Error("FeedOff should be true with no feed and no lines")
	}
	// A flat series draws along the bottom edge.
	if p := liveSparkPoints(make([]uint32, 3)); p != "0.0,32.0 75.0,32.0 150.0,32.0" {
		t.Errorf("flat points = %q", p)
	}
}

// The overview renders the strip with its first reading, so a page without
// script still says real numbers; without a counter the strip is absent.
func TestLivePageRendersStrip(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	h.Live = live.New()
	h.Live.Hit(time.Now(), "JP", live.Of(live.Requests, live.Serve))
	req := httptest.NewRequest("GET", "/unmask/admin/live/", nil)
	rec := httptest.NewRecorder()
	h.AdminLive(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`id="live-grid"`, `data-k="requests"`, `data-k="rate_limit"`, `/admin/api/now`, `id="live-toggle"`, `data-f="last30"`, `data-f="bars"`, `id="geo-card"`, `id="recent-card"`, `data-src="/unmask/admin/live/?partial=recent"`} {
		if !strings.Contains(body, want) {
			t.Errorf("realtime page lacks %q", want)
		}
	}
	if strings.Count(body, `class="live" data-k=`) != len(liveKinds) {
		t.Errorf("%d tiles rendered", strings.Count(body, `class="live" data-k=`))
	}
	// A bar a minute on every tile (counted inside the grid: the shared
	// partials draw rects of their own).
	grid := body[strings.Index(body, `id="live-grid"`):strings.Index(body, `id="live-feed-off"`)]
	if n := strings.Count(grid, `<rect x="`); n != len(liveKinds)*live.Minutes {
		t.Errorf("%d bars, want %d", n, len(liveKinds)*live.Minutes)
	}
	// The dashboard has no strip, map, recent card or line of now any more:
	// the realtime tab holds the figures of now, and the tab bar points there.
	rec = httptest.NewRecorder()
	h.AdminTopOverview(rec, httptest.NewRequest("GET", "/unmask/admin/", nil))
	page := rec.Body.String()
	for _, gone := range []string{`id="live-grid"`, `id="geo-card"`, `id="recent-card"`} {
		if strings.Contains(page, gone) {
			t.Errorf("the dashboard still carries %q", gone)
		}
	}
	if strings.Contains(page, `class="now-line"`) || !strings.Contains(page, `href="/unmask/admin/live/"`) || !strings.Contains(page, `class="dash-tabs"`) {
		t.Error("the dashboard lacks the tab bar with its realtime entry, or still carries the line of now")
	}
	if !strings.Contains(body, `class="dash-tabs"`) || strings.Contains(body, `nav.live`) {
		t.Error("the realtime tab must carry the tab bar and no nav entry of its own")
	}
	rec = httptest.NewRecorder()
	h.AdminTopOverview(rec, httptest.NewRequest("GET", "/unmask/admin/?partial=day", nil))
	if strings.Contains(rec.Body.String(), `class="now-line"`) {
		t.Error("the day partial still carries the line of now")
	}
	h.Live = nil
	rec = httptest.NewRecorder()
	h.AdminLive(rec, httptest.NewRequest("GET", "/unmask/admin/live/", nil))
	if b := rec.Body.String(); strings.Contains(b, `id="live-grid"`) || !strings.Contains(b, "リアルタイム計測") {
		t.Error("without a counter the realtime page must say so and show no strip")
	}
	rec = httptest.NewRecorder()
	h.AdminTopOverview(rec, httptest.NewRequest("GET", "/unmask/admin/", nil))
	if strings.Contains(rec.Body.String(), `class="now-line"`) {
		t.Error("the line of now rendered without a counter")
	}
}

// The busiest rules first, three at most, ties by rule; a custom rule shows
// its name, or its id when it has none.
func TestTopRules(t *testing.T) {
	got := topRules("asn_deny", map[string]uint32{"AS1": 5, "AS2": 9, "AS3": 5, "AS4": 1}, 3, nil)
	if len(got) != 3 || got[0].Rule != "AS2" || got[1].Rule != "AS1" || got[2].Rule != "AS3" {
		t.Errorf("order = %+v", got)
	}
	custom := []settings.CustomRule{{ID: "cr1", Label: "scrapers"}, {ID: "cr2"}}
	got = topRules("custom_rule", map[string]uint32{"cr1": 2, "cr2": 1}, 3, custom)
	if got[0].Label != "scrapers" || got[1].Label != "cr2" {
		t.Errorf("labels = %+v", got)
	}
}
