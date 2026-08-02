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
	"strconv"
	"strings"
	"time"

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
		// "auto" IS the resolve default (ResolvedMode) — store the
		// non-deviation as unset so a no-op save leaves the config untouched.
		c.Mode = ""
	}
	seen := map[string]bool{}
	defined := []string{}
	titles := []string{}
	disabled := []bool{}
	anyOff := false
	anyTitle := false
	// site_defined is a value-rule-list: one host per row, with parallel
	// _title / _enabled fields riding the same index.
	vals := r.Form["site_defined"]
	notes := r.Form["site_defined_title"]
	ens := r.Form["site_defined_enabled"]
	crs := r.Form["site_defined_created_at"]
	ups := r.Form["site_defined_updated_at"]
	now := time.Now().Unix()
	var createdAt, updatedAt []int64
	anyUpdated := false
	for i, line := range vals {
		if strings.TrimSpace(line) == "" {
			continue
		}
		s := normalizeSite(line)
		if seen[s] {
			continue
		}
		seen[s] = true
		defined = append(defined, s)
		title := ""
		if i < len(notes) {
			title = strings.TrimSpace(notes[i])
		}
		titles = append(titles, title)
		anyTitle = anyTitle || title != ""
		off := i < len(ens) && ens[i] == "0"
		disabled = append(disabled, off)
		anyOff = anyOff || off
		var cr, up int64
		if i < len(crs) {
			cr, _ = strconv.ParseInt(strings.TrimSpace(crs[i]), 10, 64)
		}
		if i < len(ups) {
			up, _ = strconv.ParseInt(strings.TrimSpace(ups[i]), 10, 64)
		}
		if cr <= 0 {
			cr = now
		}
		up = clampUpdatedAt(up, cr, now)
		createdAt = append(createdAt, cr)
		updatedAt = append(updatedAt, up)
		anyUpdated = anyUpdated || up > 0
	}
	c.DefinedCreatedAt = createdAt
	c.DefinedUpdatedAt = nil
	if anyUpdated {
		c.DefinedUpdatedAt = updatedAt
	}
	c.Defined = defined
	// Store the parallel slices only when they carry information, so a config
	// that never used notes / toggles keeps its old shape.
	c.DefinedTitle = nil
	if anyTitle {
		c.DefinedTitle = titles
	}
	c.DefinedDisabled = nil
	if anyOff {
		c.DefinedDisabled = disabled
	}
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
		for i, d := range s.Sites.Defined {
			if d != site {
				continue
			}
			// Already on the list: promoting a site whose row was switched
			// off means "define it again", so clear the flag instead of
			// appending a duplicate row.
			if i < len(s.Sites.DefinedDisabled) {
				s.Sites.DefinedDisabled[i] = false
			}
			return
		}
		s.Sites.Defined = append(s.Sites.Defined, site)
		if len(s.Sites.DefinedDisabled) > 0 {
			// Keep the parallel slices aligned once they exist.
			for len(s.Sites.DefinedDisabled) < len(s.Sites.Defined)-1 {
				s.Sites.DefinedDisabled = append(s.Sites.DefinedDisabled, false)
			}
			s.Sites.DefinedDisabled = append(s.Sites.DefinedDisabled, false)
		}
		if len(s.Sites.DefinedTitle) > 0 {
			for len(s.Sites.DefinedTitle) < len(s.Sites.Defined) {
				s.Sites.DefinedTitle = append(s.Sites.DefinedTitle, "")
			}
		}
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
