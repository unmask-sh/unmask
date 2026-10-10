package handlers

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/live"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func TestServeWorldMap(t *testing.T) {
	h := &Handler{}
	rec := httptest.NewRecorder()
	h.ServeWorldMap(rec, httptest.NewRequest("GET", "/unmask/static/world-110m.json", nil))
	if rec.Code != 200 || !strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		t.Fatalf("status %d type %q", rec.Code, rec.Header().Get("Content-Type"))
	}
	if !strings.Contains(rec.Header().Get("Cache-Control"), "max-age=86400") {
		t.Errorf("cache-control %q", rec.Header().Get("Cache-Control"))
	}
	var m struct {
		Paths     []string
		Centroids map[string][2]float64
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil || len(m.Paths) == 0 || m.Centroids["JP"][0] == 0 {
		t.Errorf("body is not the map: %v (%d paths)", err, len(m.Paths))
	}
}

// Saving the server's position: a valid point is kept with its label, an
// empty point clears it, and a point off the globe or a label past the
// limit is refused in the operator's language without touching the setting.
func TestAdminMapLocationSave(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()
	h.ConfigPath = filepath.Join(dir, "config.yml")
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	if err := os.WriteFile(h.ConfigPath, []byte("server:\n  base_path: /unmask\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	post := func(form url.Values) (int, map[string]any) {
		req := httptest.NewRequest("POST", "/unmask/admin/api/map-location", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Cookie", "unmask_lang=ja")
		rec := httptest.NewRecorder()
		h.AdminMapLocationSave(rec, req)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}
	code, out := post(url.Values{"lat": {"35.68"}, "lon": {"139.76"}, "label": {"東京"}})
	if code != 200 || out["ok"] != true || out["set"] != true || out["label"] != "東京" {
		t.Fatalf("save: %d %v", code, out)
	}
	if m := h.cfg().Server.MapLocation; m == nil || m.Lat != 35.68 || m.Lon != 139.76 || m.Label != "東京" {
		t.Errorf("setting after save: %+v", m)
	}
	if v := h.mapLocation(); !v.Set || v.Label != "東京" {
		t.Errorf("view: %+v", v)
	}
	// Off the globe: refused, the setting stays.
	code, out = post(url.Values{"lat": {"95"}, "lon": {"10"}})
	if code != 400 || out["ok"] != false || !strings.Contains(out["error"].(string), "90") {
		t.Errorf("lat 95: %d %v", code, out)
	}
	code, _ = post(url.Values{"lat": {"abc"}, "lon": {"10"}})
	if code != 400 {
		t.Errorf("non-numeric: %d", code)
	}
	code, out = post(url.Values{"lat": {"1"}, "lon": {"2"}, "label": {strings.Repeat("あ", mapLabelMax+1)}})
	if code != 400 || !strings.Contains(out["error"].(string), "80") {
		t.Errorf("long label: %d %v", code, out)
	}
	if m := h.cfg().Server.MapLocation; m == nil || m.Lat != 35.68 {
		t.Errorf("a refused save changed the setting: %+v", m)
	}
	// Empty: cleared.
	code, out = post(url.Values{"lat": {""}, "lon": {""}, "label": {""}})
	if code != 200 || out["set"] != false || h.cfg().Server.MapLocation != nil {
		t.Errorf("clear: %d %v %+v", code, out, h.cfg().Server.MapLocation)
	}
}

// The map card rides with the live strip: drawn with the server's position
// when one is set, saying so when none is, and offering the setting only to
// an admin.
func TestOverviewMapCard(t *testing.T) {
	h := newTestHandler(t)
	h.Live = live.New()
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)
	get := func(role string) string {
		req := httptest.NewRequest("GET", "/unmask/admin/", nil)
		if role != "" {
			req = req.WithContext(context.WithValue(req.Context(), sessionCtxKey{}, &SessionPayload{UserID: 1, Role: role, Exp: time.Now().Add(time.Hour).Unix()}))
		}
		rec := httptest.NewRecorder()
		h.AdminTopOverview(rec, req)
		return rec.Body.String()
	}
	body := get("admin")
	for _, want := range []string{`id="geo-card"`, `data-set="0"`, `/static/world-110m.json?v=`, `id="geo-set"`, `id="geo-unset"`, `data-save="/unmask/admin/api/map-location"`} {
		if !strings.Contains(body, want) {
			t.Errorf("admin page lacks %q", want)
		}
	}
	if strings.Contains(body, `id="geo-unset" style="margin:.4rem 0 0" hidden`) {
		t.Error("the unset note is hidden although no position is set")
	}
	if strings.Contains(get("viewer"), `id="geo-set"`) {
		t.Error("a viewer is offered the setting")
	}
	s = h.snapshotSettings()
	s.Server.MapLocation = &settings.MapLocation{Lat: 35.68, Lon: 139.76, Label: "Tokyo"}
	h.SetSettings(s)
	body = get("admin")
	if !strings.Contains(body, `data-set="1"`) || !strings.Contains(body, `data-label="Tokyo"`) || !strings.Contains(body, `id="geo-unset" style="margin:.4rem 0 0" hidden`) {
		t.Error("a set position is not handed to the card")
	}
	// No counter: no strip, and no map either.
	h.Live = nil
	if strings.Contains(get("admin"), `id="geo-card"`) {
		t.Error("the map card rendered without the live counter")
	}
}
