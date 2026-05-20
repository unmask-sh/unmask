// ipgeo_install_admin.go — web-UI handler for 1-click DB-IP Lite install
// (= shared by the network tab's Country + ASN install buttons).
//
// Pairs with `unmask-admin install-ipgeo` CLI: both call the same
// ipgeo.InstallDBIPLite library so behavior matches exactly.  The web-UI
// path additionally reloads the in-process ipgeo Reader so the geo axis
// picks up the new file immediately (= no SIGHUP / restart needed).
package handlers

import (
	"net/http"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
)

// AdminIPGeoInstall: POST /admin/api/ipgeo/install?kind=country|asn.
//
// Downloads the requested DB-IP Lite snapshot into the configured path (or
// the library default when unset), atomically replaces the file, and reloads
// the in-process IP-geo Reader so the geo axis acts on the new data.
//
// Returns JSON: {"ok":1, "kind":"country", "path":"...", "month":"...", "bytes":N, "fallback":bool}
// On failure: {"ok":0, "error":"..."}
func (h *Handler) AdminIPGeoInstall(w http.ResponseWriter, r *http.Request) {
	kindArg := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("kind")))
	if kindArg == "" {
		kindArg = r.FormValue("kind")
	}
	kind := ipgeo.InstallKind(strings.ToLower(strings.TrimSpace(kindArg)))
	switch kind {
	case "":
		kind = ipgeo.InstallKindCountry
	case ipgeo.InstallKindCountry, ipgeo.InstallKindASN:
		// ok
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"ok":    0,
			"error": "kind must be country or asn (got " + kindArg + ")",
		})
		return
	}

	cfg := h.snapshotSettings()
	var path string
	if kind == ipgeo.InstallKindASN {
		path = strings.TrimSpace(cfg.IPGeo.MMDBASNPath)
	} else {
		path = strings.TrimSpace(cfg.IPGeo.MMDBPath)
	}
	if path == "" {
		path = ipgeo.DefaultPathForKind(kind)
	}

	res, err := ipgeo.InstallDBIPLite(ipgeo.InstallOptions{
		Kind: kind,
		Path: path,
	})
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]any{
			"ok":    0,
			"kind":  string(kind),
			"error": err.Error(),
		})
		return
	}
	// In-process reload so the geo axis sees the new file on the very next
	// /api/check request (= no SIGHUP / restart).  Reload short-circuits
	// when the path is unchanged, so clear-then-reload forces a refresh.
	if h.IPGeo != nil {
		h.IPGeo.Reload("", "")
		h.IPGeo.Reload(cfg.IPGeo.MMDBPath, cfg.IPGeo.MMDBASNPath)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       1,
		"kind":     string(kind),
		"path":     res.Path,
		"source":   res.Source,
		"month":    res.Month,
		"bytes":    res.Bytes,
		"fallback": res.Fallback,
	})
}
