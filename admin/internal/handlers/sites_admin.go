package handlers

// Site-acceptance management (multi-site phase 4).
//
// When settings.Sites is in "defined" mode, any site observed in unmask_event
// whose normalized Host is not in Sites.Defined is a "ghost" — surfaced in the
// settings "sites" tab's ghost report so the operator can promote a legitimate
// vhost into Defined with one click, or simply ignore a spoofed Host.  In
// "auto" mode nothing is a ghost.

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// GhostSite: one observed-but-undefined site row for the ghost report.
type GhostSite struct {
	Site       string
	Events     int
	LastSeen   string
	LastSeenTS int64 // unix sec UTC; template renders via <time class="js-datetime">
}

// ghostSites returns the sites that are ghosts under the current acceptance
// config, observed within the last `hours` hours.  Returns nil in "auto" mode
// (no ghost concept) or on query error.  Not scoped by any picker — the ghost
// report is a global, cross-site management view.
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

// applySitesForm applies the settings "sites" tab: the acceptance mode and the
// defined-site list (a newline-separated textarea).  Each line is normalized
// (lowercased, :port stripped) and de-duplicated; blank lines are dropped.
func applySitesForm(c *settings.SiteAcceptanceConfig, r *http.Request) {
	if strings.TrimSpace(r.FormValue("site_mode")) == settings.SiteModeDefined {
		c.Mode = settings.SiteModeDefined
	} else {
		c.Mode = settings.SiteModeAuto
	}
	seen := map[string]bool{}
	defined := []string{}
	for _, line := range strings.Split(r.FormValue("site_defined"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		s := normalizeSite(line)
		if seen[s] {
			continue
		}
		seen[s] = true
		defined = append(defined, s)
	}
	c.Defined = defined
}

// AdminSitePromote: POST {base}/admin/api/sites/promote — one-click promotion
// of a ghost site into settings.Sites.Defined.  Admin role.  Form field: site.
//
// No nginx re-render is needed: Sites is an admin-side classification only and
// does not affect the rendered nginx conf.  On success the row simply vanishes
// from the ghost report on the next render (its own confirmation).
func (h *Handler) AdminSitePromote(w http.ResponseWriter, r *http.Request) {
	base := h.Settings.Server.BasePath
	redir := func(msg string) {
		dst := base + "/admin/settings/?tab=sites"
		if msg == "" {
			dst += "&saved=1"
		} else {
			setFlash(w, base, "err", msg)
		}
		http.Redirect(w, r, dst, http.StatusSeeOther)
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	site := normalizeSite(r.FormValue("site"))
	if site == "" || site == "default" {
		redir("invalid site")
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
		redir("save: " + err.Error())
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

	redir("")
}
