package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/live"
)

func TestAdminNowJSON(t *testing.T) {
	h := &Handler{Live: live.New()}
	now := time.Now()
	for i := 0; i < 3; i++ {
		h.Live.Hit(now, "JP", live.Of(live.Requests, live.Pass))
	}
	h.Live.Hit(now.Add(-70*time.Second), "US", live.Of(live.Requests, live.Serve))
	h.Live.ObserveEvent(now, "bv_pow_only", "JP", false)
	h.Live.ObserveEvent(now, "serve", "", true)

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
		Prev      map[string]uint32   `json:"prev"`
		TPS       map[string]float64  `json:"tps"`
		Countries map[string]struct {
			N    uint32 `json:"n"`
			Pass uint32 `json:"pass"`
		} `json:"countries"`
		FeedOff bool   `json:"feed_off"`
		TPSText string `json:"tps_text"`
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
	if out.Prev["requests"] != 1 || out.Prev["serve"] != 1 {
		t.Errorf("prev = %v", out.Prev)
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
	if len(v.Tiles) != int(live.NumKinds) {
		t.Fatalf("%d tiles", len(v.Tiles))
	}
	req := v.Tiles[0]
	if req.Key != "requests" || req.Last != 1 || req.Delta != -1 || req.DeltaText != "-1" || req.DeltaClass != "down" {
		t.Errorf("requests tile = %+v", req)
	}
	if req.TPS != "0.2" || req.Points == "" || !strings.HasPrefix(req.Points, "0.0,") {
		t.Errorf("requests tile tps=%q points=%q", req.TPS, req.Points[:20])
	}
	deny := v.Tiles[5]
	if deny.Key != "deny" || deny.Last != 1 || deny.DeltaText != "+1" || deny.DeltaClass != "up" {
		t.Errorf("deny tile = %+v", deny)
	}
	if v.Tiles[1].DeltaText != "±0" || v.Tiles[1].DeltaClass != "" {
		t.Errorf("pass tile delta = %q/%q", v.Tiles[1].DeltaText, v.Tiles[1].DeltaClass)
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
func TestOverviewRendersLiveStrip(t *testing.T) {
	h := newTestHandler(t)
	h.Live = live.New()
	h.Live.Hit(time.Now(), "JP", live.Of(live.Requests, live.Serve))
	req := httptest.NewRequest("GET", "/unmask/admin/", nil)
	rec := httptest.NewRecorder()
	h.AdminTopOverview(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{`id="live-grid"`, `data-k="requests"`, `data-k="rate_limit"`, `/admin/api/now`, `id="live-toggle"`} {
		if !strings.Contains(body, want) {
			t.Errorf("overview lacks %q", want)
		}
	}
	if strings.Count(body, `class="live" data-k=`) != int(live.NumKinds) {
		t.Errorf("%d tiles rendered", strings.Count(body, `class="live" data-k=`))
	}
	h.Live = nil
	rec = httptest.NewRecorder()
	h.AdminTopOverview(rec, httptest.NewRequest("GET", "/unmask/admin/", nil))
	if strings.Contains(rec.Body.String(), `id="live-grid"`) {
		t.Error("the strip rendered without a counter")
	}
}
