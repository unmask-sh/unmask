package handlers

// Ghost-site report (multi-site phase 4b).
//
// When settings.Sites is in "defined" mode, any site observed in unmask_event
// whose normalized Host is not in Sites.Defined is a "ghost" — surfaced in the
// dashboard's ghost report so the operator can promote a legitimate vhost into
// Defined with one click, or simply ignore a spoofed Host.  In "auto" mode
// nothing is a ghost and the report is hidden.

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// GhostSite: one observed-but-undefined site row for the dashboard ghost report.
type GhostSite struct {
	Site       string
	Events     int
	LastSeen   string
	LastSeenTS int64 // unix sec UTC; template renders via <time class="js-datetime">
}

// ghostSites returns the sites that are ghosts under the current acceptance
// config, observed within the last `hours` hours.  Returns nil in "auto" mode
// (no ghost concept) or on query error.  Not scoped by the site picker — the
// ghost report is a global, cross-site management view.
func (h *Handler) ghostSites(ctx context.Context, hours int) []GhostSite {
	sa := h.Settings.Sites
	if sa.ResolvedMode() != settings.SiteModeDefined {
		return nil
	}
	if h.DB == nil {
		return nil
	}
	sites, err := dashboard.Sites(ctx, h.DB, hours)
	if err != nil {
		log.Printf("ghostSites: %v", err)
		return nil
	}
	out := []GhostSite{}
	for _, s := range sites {
		// A ghost is by definition an observed site; dashboard.Sites synthesizes
		// a zero-event "default" row, which is not a real observation.
		if s.Events == 0 || !sa.IsGhost(s.Site) {
			continue
		}
		out = append(out, GhostSite{
			Site:       s.Site,
			Events:     s.Events,
			LastSeen:   s.LastSeen,
			LastSeenTS: s.LastSeenTS,
		})
	}
	return out
}

// AdminSitePromote: POST {base}/admin/api/sites/promote — one-click promotion
// of a ghost site into settings.Sites.Defined.  Admin role.  Form field: site.
//
// No nginx re-render is needed: Sites is an admin-side classification only and
// does not affect the rendered nginx conf.  On success the row simply vanishes
// from the ghost report on the next render (its own confirmation).
func (h *Handler) AdminSitePromote(w http.ResponseWriter, r *http.Request) {
	base := h.Settings.Server.BasePath
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	site := normalizeSite(r.FormValue("site"))
	if site == "" || site == "default" {
		http.Error(w, "invalid site", http.StatusBadRequest)
		return
	}

	if err := h.UpdateSettings(func(s *settings.Settings) {
		// Promotion implies "defined" mode; if the config is still on the
		// default ("" -> auto) keep it explicit so the new entry has an effect.
		if s.Sites.Mode == "" {
			s.Sites.Mode = settings.SiteModeDefined
		}
		for _, d := range s.Sites.Defined {
			if d == site {
				return // already defined — idempotent
			}
		}
		s.Sites.Defined = append(s.Sites.Defined, site)
	}); err != nil {
		http.Error(w, "save: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// audit trail: who promoted which site.
	if pay := SessionFromContext(r); pay != nil && h.UserRepo != nil {
		username := ""
		if u, err := h.UserRepo.GetByID(r.Context(), pay.UserID); err == nil {
			username = u.Username
		}
		h.UserRepo.Record(r.Context(), pay.UserID, username, "site_promote",
			site, fmt.Sprintf(`{"mode":%q}`, h.Settings.Sites.ResolvedMode()))
	}

	// Back to wherever the operator clicked from (the dashboard ghost report).
	dst := r.Header.Get("Referer")
	if dst == "" {
		dst = base + "/admin/"
	}
	http.Redirect(w, r, dst, http.StatusSeeOther)
}
