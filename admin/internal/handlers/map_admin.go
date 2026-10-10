package handlers

import (
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/unmask-sh/unmask/admin/assets"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
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

// mapLocView is what the map card renders: the operator's setting, or,
// without one, the position worked out from the server's own address.
type mapLocView struct {
	Set      bool
	Lat, Lon float64
	Label    string
	Auto     bool   // worked out, not set: the card says so and from what
	Source   string // "interface" / "echo" when Auto
	Approx   bool   // Auto from a country alone: the country's centre
	IP       string // the address the automatic position came from
	At       int64  // when the address check answered (echo only), unix
}

func (h *Handler) mapLocation() mapLocView {
	m := h.cfg().Server.MapLocation
	if m != nil && m.Valid() {
		return mapLocView{Set: true, Lat: m.Lat, Lon: m.Lon, Label: m.Label}
	}
	return h.autoMapLocation()
}

// The server's own position, worked out without asking a third party.  Two
// sources: a global address on one of the host's own interfaces (a bare-metal
// server, most VPSes), else the address the community-bans hub saw this
// install come from (echoed on the hourly feed pull; the hub is ours).  The
// address is then placed by the install's own geo database: coordinates from
// a City database, the country's centre from a Country one.  Cached for an
// hour; a manual setting always wins.
const mapAutoTTL = time.Hour

// interfaceAddrs is net.InterfaceAddrs, replaceable in tests.
var interfaceAddrs = net.InterfaceAddrs

func (h *Handler) autoMapLocation() mapLocView {
	h.mapAutoMu.Lock()
	defer h.mapAutoMu.Unlock()
	if time.Since(h.mapAutoAt) < mapAutoTTL {
		return h.mapAuto
	}
	h.mapAutoAt = time.Now()
	h.mapAuto = mapLocView{}
	ip, source := "", ""
	var at int64
	if addrs, err := interfaceAddrs(); err == nil {
		if v := pickGlobalIP(addrs); v != "" {
			ip, source = v, "interface"
		}
	}
	if ip == "" {
		// Behind NAT or a load balancer: the address the server shows the
		// outside, as the operator last asked unmask.sh's address check
		// for it (public_ip.go); nothing until they have.
		if v, t := h.publicIP(); v != "" {
			ip, source, at = v, "echo", t.Unix()
		}
	}
	if ip == "" || h.IPGeo == nil {
		return h.mapAuto
	}
	info := h.IPGeo.LookupInfo(ip)
	// The country's name from the record, or from the built-in table when
	// the record carries only the code.
	country := info.CountryName
	if country == "" || country == info.Country {
		country = ipgeo.CountryName(info.Country)
	}
	switch {
	case info.HasCoords:
		label := info.City
		if label == "" {
			label = country
		}
		h.mapAuto = mapLocView{Set: true, Lat: info.Lat, Lon: info.Lon, Label: label, Auto: true, Source: source, IP: ip, At: at}
	case info.Country != "":
		if lon, lat, ok := assets.WorldCentroid(info.Country); ok {
			h.mapAuto = mapLocView{Set: true, Lat: lat, Lon: lon, Label: country, Auto: true, Source: source, Approx: true, IP: ip, At: at}
		}
	}
	return h.mapAuto
}

// pickGlobalIP returns the first global unicast address among addrs, IPv4
// before IPv6; "" when the host has none (NAT, or loopback only).
func pickGlobalIP(addrs []net.Addr) string {
	var v6 string
	for _, a := range addrs {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || isCGNAT(ip) {
			continue
		}
		if ip.To4() != nil {
			return ip.String()
		}
		if v6 == "" {
			v6 = ip.String()
		}
	}
	return v6
}

// isCGNAT: 100.64.0.0/10, the carrier-grade range IsPrivate does not cover.
func isCGNAT(ip net.IP) bool {
	v4 := ip.To4()
	return v4 != nil && v4[0] == 100 && v4[1]&0xc0 == 64
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
	// The effective position after the save: the setting, or, cleared, the
	// worked-out one (with what the card says about it).
	_ = json.NewEncoder(w).Encode(h.mapLocationAnswer(lang))
}

// mapLocationAnswer is the effective position as the page's script reads
// it after a save or a probe: the point, the label as shown, and the note
// the card carries when it is worked out; plus the worked-out candidate on
// its own (auto_*), for the dialog.
func (h *Handler) mapLocationAnswer(lang i18n.Lang) map[string]any {
	v := h.mapLocation()
	shown := v.Label
	if v.Approx {
		shown += " " + i18n.T(lang, "overview.map.approx")
	}
	out := map[string]any{"ok": true, "set": v.Set, "lat": v.Lat, "lon": v.Lon, "label": shown, "auto": v.Auto, "approx": v.Approx}
	if v.Auto {
		out["source"] = v.Source
		out["note"] = i18n.Tf(lang, "overview.map.auto_note", i18n.T(lang, "overview.map.src_"+v.Source))
		if v.Approx {
			out["note"] = out["note"].(string) + " " + i18n.T(lang, "overview.map.approx_note")
		}
	}
	a := h.autoMapLocation()
	al := a.Label
	if a.Approx {
		al += " " + i18n.T(lang, "overview.map.approx")
	}
	out["auto_set"], out["auto_lat"], out["auto_lon"], out["auto_label"], out["auto_source"], out["auto_ip"], out["auto_at"] = a.Set, a.Lat, a.Lon, al, a.Source, a.IP, a.At
	return out
}

// AdminMapLocationProbe: POST {base}/admin/api/map-location/probe (admin
// role).  Asks unmask.sh's address check for the server's outward address
// now -- the one call home the map makes, and only on this button -- keeps
// the answer, and returns the position worked out from it.
func (h *Handler) AdminMapLocationProbe(w http.ResponseWriter, r *http.Request) {
	lang := i18n.Lang(i18n.Resolve(r))
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	ip, err := h.ProbePublicIP(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		_ = json.NewEncoder(w).Encode(map[string]any{"ok": false, "error": i18n.Tf(lang, "overview.map.dlg_probe_err", err.Error())})
		return
	}
	h.mapAutoMu.Lock()
	h.mapAutoAt = time.Time{} // worked out afresh from the new address
	h.mapAutoMu.Unlock()
	out := h.mapLocationAnswer(lang)
	out["ip"] = ip
	_ = json.NewEncoder(w).Encode(out)
}
