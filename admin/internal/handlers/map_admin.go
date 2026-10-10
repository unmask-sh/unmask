package handlers

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/unmask-sh/unmask/admin/assets"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The dashboard's map of inbound traffic: the outline it draws, and the one
// setting it needs -- where this server is, so the streams have somewhere to
// go.  The streams themselves come from /admin/api/now's countries.

// ServeWorldMap: GET {base}/static/world-110m.json -- the outline, embedded
// in the binary (see static/world-110m.md for its source).  Cached for a
// day; the page adds ?v=<build> so a new binary is never read from cache.
func (h *Handler) ServeWorldMap(w http.ResponseWriter, r *http.Request) {
	b, err := assets.Static.ReadFile("static/world-110m.json")
	if err != nil {
		http.Error(w, "world map unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	_, _ = w.Write(b)
}

// mapLocView is what the map card renders of the setting.
type mapLocView struct {
	Set      bool
	Lat, Lon float64
	Label    string
}

func (h *Handler) mapLocation() mapLocView {
	m := h.cfg().Server.MapLocation
	if m == nil || !m.Valid() {
		return mapLocView{}
	}
	return mapLocView{Set: true, Lat: m.Lat, Lon: m.Lon, Label: m.Label}
}

// mapLabelMax bounds the label; the dialog says so as the text runs past it.
const mapLabelMax = 80

// AdminMapLocationSave: POST {base}/admin/api/map-location (admin role),
// form fields lat, lon, label.  Empty lat and lon clear the setting.  Answers
// JSON: {"ok":true,"set":bool,"lat":..,"lon":..,"label":".."} or 400 with
// {"error":"..."} in the operator's language.
func (h *Handler) AdminMapLocationSave(w http.ResponseWriter, r *http.Request) {
	lang := i18n.Lang(i18n.Resolve(r))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	fail := func(msg string) {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": msg})
	}
	if err := r.ParseForm(); err != nil {
		fail(i18n.T(lang, "overview.map.err_point"))
		return
	}
	latS, lonS := strings.TrimSpace(r.FormValue("lat")), strings.TrimSpace(r.FormValue("lon"))
	label := strings.TrimSpace(r.FormValue("label"))
	if utf8.RuneCountInString(label) > mapLabelMax {
		fail(i18n.Tf(lang, "err.value_long", mapLabelMax))
		return
	}
	var loc *settings.MapLocation
	if latS != "" || lonS != "" {
		lat, err1 := strconv.ParseFloat(latS, 64)
		lon, err2 := strconv.ParseFloat(lonS, 64)
		if err1 != nil || err2 != nil {
			fail(i18n.T(lang, "overview.map.err_point"))
			return
		}
		loc = &settings.MapLocation{Lat: lat, Lon: lon, Label: label}
		if !loc.Valid() {
			fail(i18n.T(lang, "overview.map.err_point"))
			return
		}
	}
	if err := h.UpdateSettings(func(s *settings.Settings) { s.Server.MapLocation = loc }); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": err.Error()})
		return
	}
	v := h.mapLocation()
	_ = json.NewEncoder(w).Encode(map[string]any{"ok": true, "set": v.Set, "lat": v.Lat, "lon": v.Lon, "label": v.Label})
}
