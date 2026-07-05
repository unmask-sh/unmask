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
	"regexp"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// hostIDRE: charset guard for a host id submitted to AdminHostToggle.  Matches
// the dashboard.hostValRE charset so a junk id never reaches settings / SQL.
var hostIDRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

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
	sa := h.cfg().Sites
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
	// site_defined is now a value-rule-list (one host per row) rather than a
	// newline textarea, so read the repeated field.
	for _, line := range r.Form["site_defined"] {
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
	base := h.cfg().Server.BasePath
	redir := func(msg string) {
		dst := base + "/admin/settings/?tab=sites"
		if msg == "" {
			dst += "&saved=1"
		} else {
			setFlash(w, r, base, "err", msg)
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
			site, fmt.Sprintf(`{"mode":%q}`, h.cfg().Sites.ResolvedMode()))
	}

	redir("")
}

// AdminHostToggle: POST {base}/admin/api/hosts/toggle — disable / enable a host
// in the inventory.  Admin role.  Form: host, op (disable | enable).
//
// A disabled host drops out of the host picker and out of every dashboard
// aggregation (hostCond excludes it); its events stay in the DB.  Reversible.
func (h *Handler) AdminHostToggle(w http.ResponseWriter, r *http.Request) {
	base := h.cfg().Server.BasePath
	redir := func(msg string) {
		dst := base + "/admin/settings/?tab=sites"
		if msg == "" {
			dst += "&saved=1"
		} else {
			setFlash(w, r, base, "err", msg)
		}
		http.Redirect(w, r, dst, http.StatusSeeOther)
	}
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	host := strings.TrimSpace(r.FormValue("host"))
	if host == "" || !hostIDRE.MatchString(host) {
		redir("invalid host")
		return
	}
	disable := r.FormValue("op") != "enable"

	if err := h.UpdateSettings(func(s *settings.Settings) {
		// Rebuild the list without the target, then append it iff disabling.
		// Idempotent for both ops (disabling an already-disabled host is a
		// no-op; the op field is authoritative, not a toggle).
		out := []string{}
		for _, d := range s.Hosts.Disabled {
			if d != host {
				out = append(out, d)
			}
		}
		if disable {
			out = append(out, host)
		}
		s.Hosts.Disabled = out
	}); err != nil {
		redir("save: " + err.Error())
		return
	}

	// hot-swap the aggregation exclusion (= applied from the next query).
	dashboard.SetDisabledHosts(h.cfg().Hosts.Disabled)

	// audit trail: who disabled / enabled which host.
	if pay := SessionFromContext(r); pay != nil && h.UserRepo != nil {
		username := ""
		if u, err := h.UserRepo.GetByID(r.Context(), pay.UserID); err == nil {
			username = u.Username
		}
		op := "host_enable"
		if disable {
			op = "host_disable"
		}
		h.UserRepo.Record(r.Context(), pay.UserID, username, op, host, "")
	}

	redir("")
}
