// ipgeo_install_admin.go — web-UI handler for 1-click DB-IP Lite install
// (= shared by the network tab's Country + ASN install buttons).
//
// Pairs with `unmask install-ipgeo` CLI: both call the same
// ipgeo.InstallDBIPLite library so behavior matches exactly.  The web-UI
// path additionally reloads the in-process ipgeo Reader so the geo axis
// picks up the new file immediately (= no SIGHUP / restart needed), and
// renders nginx's configuration, which carries CIDR lists read from the
// file (the country and ASN rules).
package handlers

import (
	"net/http"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// AdminIPGeoInstall: POST /admin/api/ipgeo/install?kind=country|asn.
//
// Downloads the requested DB-IP Lite snapshot into the configured path (or
// the library default when unset), atomically replaces the file, and reloads
// the in-process IP-geo Reader so the geo axis acts on the new data.
//
// Returns JSON: {"ok":1, "kind":"country", "path":"...", "month":"...", "bytes":N, "fallback":bool,
// "reload":bool, "render_error":"..."}
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
	// nginx's configuration carries the CIDRs of the country and ASN rules,
	// read from these files at render time: render, as the daily update
	// does, so the new file reaches nginx with its next reload.  Without
	// it the first install left the country / ASN rules empty in nginx
	// until some other save rendered.  "reload" tells the page whether the
	// configuration changed.
	reload, renderErr := h.renderAfterIPGeoInstall(h.snapshotSettings())
	out := map[string]any{
		"ok":       1,
		"kind":     string(kind),
		"path":     res.Path,
		"source":   res.Source,
		"month":    res.Month,
		"bytes":    res.Bytes,
		"fallback": res.Fallback,
		"reload":   reload,
	}
	if renderErr != nil {
		out["render_error"] = renderErr.Error()
	}
	writeJSON(w, http.StatusOK, out)
}

// renderAfterIPGeoInstall renders nginx's configuration after an mmdb was
// installed and says whether it changed (the render id on disk moved).
func (h *Handler) renderAfterIPGeoInstall(cur settings.Settings) (bool, error) {
	out := strings.TrimSpace(cur.Nginx.OutputDir)
	if out == "" {
		out = "/var/lib/unmask/nginx"
	}
	before, _ := nginxconf.RenderIDOnDisk(out)
	if err := nginxconf.RenderFor(cur, out, h.Version, nginxconf.RenderCause{Kind: nginxconf.RenderByGeoIP}); err != nil {
		return false, err
	}
	after, _ := nginxconf.RenderIDOnDisk(out)
	return after != before, nil
}
