package handlers

import (
	"sort"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// upstreamView is what the UA-filter tab's crawler card renders: one entry per
// crawler-user-agents.json group, each with its crawlers, plus the crawlers
// set one by one whose pattern the catalog no longer has.
type upstreamView struct {
	Groups []upstreamGroupView
	// Total / Passing: every crawler in the catalog, and the ones resolving
	// to white right now (group-wide or on their own) -- the card's summary.
	Total   int
	Passing int
	// Orphans: crawlers set one by one whose pattern is gone from the
	// catalog (a newer list renamed or dropped it).  Nothing resolves them,
	// so they act on nothing; the card names them so the operator can set
	// the crawler again under its new pattern, and keeps them until the
	// operator removes them.
	Orphans []upstreamOrphanView
}

type upstreamGroupView struct {
	Cat string
	// Mode: the group's own mode (classify.ResolveGroupMode).
	Mode string
	// Action: the group's chain for its stopped crawlers, "" = inherit.
	Action string
	Rows   []upstreamRowView
	// Own: how many of Rows the operator set one by one.  OwnBlack: whether
	// one of those is set to black -- the action picker matters then even
	// while the group itself is not stopped.
	Own      int
	OwnBlack bool
	// HasRV: some crawler here has a published vendor range (= the legend
	// that explains the 🛡 badge is shown).
	HasRV bool
}

type upstreamRowView struct {
	Pattern     string
	Description string
	Since       string
	// Own: the mode set for this crawler on its own, "" = follows the group.
	Own string
	// RangeBacked: the vendor publishes egress ranges for it; RangeActive:
	// those ranges are enabled on the Bypass IPs tab right now (= the badge
	// is green).
	RangeBacked bool
	RangeActive bool
	// Name: the crawler's display name (classify.CrawlerNameFromPattern), the
	// key the hourly aggregates use.  NamedDay / NamedIPs: requests the last
	// 24 hours let through on this crawler's name alone, and roughly how many
	// addresses they came from (fillNamedRescue); 0 when none.
	Name     string
	NamedDay int
	NamedIPs int
}

type upstreamOrphanView struct {
	Pattern string
	Mode    string
}

func buildUpstreamView(n settings.Nginx) upstreamView {
	sb := n.SearchBots
	rescue := classify.UpstreamRescueList()
	rvActive := nginxconf.UpstreamRangeActive(n)
	cats := make([]string, 0, len(rescue))
	for cat := range rescue {
		cats = append(cats, cat)
	}
	sort.Strings(cats)

	var v upstreamView
	known := map[string]bool{}
	for _, cat := range cats {
		g := upstreamGroupView{
			Cat:    cat,
			Mode:   classify.ResolveGroupMode(cat, sb.UpstreamGroupMode),
			Action: strings.TrimSpace(sb.UpstreamGroupAction[cat]),
		}
		for _, e := range rescue[cat] {
			known[e.Pattern] = true
			own := validUpstreamMode(sb.UpstreamPatternMode[e.Pattern])
			backed := nginxconf.RangeVerifiedPresetIDs(e.Pattern) != nil
			g.Rows = append(g.Rows, upstreamRowView{
				Pattern:     e.Pattern,
				Description: e.Description,
				Since:       e.AdditionDate,
				Own:         own,
				RangeBacked: backed,
				RangeActive: backed && rvActive[e.Pattern],
				Name:        classify.CrawlerNameFromPattern(e.Pattern),
			})
			if own != "" {
				g.Own++
				if own == classify.GroupModeBlack {
					g.OwnBlack = true
				}
			}
			if backed {
				g.HasRV = true
			}
			v.Total++
			if classify.ResolvePatternMode(cat, e.Pattern, sb.UpstreamGroupMode, sb.UpstreamPatternMode) == classify.GroupModeWhite {
				v.Passing++
			}
		}
		v.Groups = append(v.Groups, g)
	}
	for pat, mode := range sb.UpstreamPatternMode {
		if mode = validUpstreamMode(mode); mode != "" && !known[pat] {
			v.Orphans = append(v.Orphans, upstreamOrphanView{Pattern: pat, Mode: mode})
		}
	}
	sort.Slice(v.Orphans, func(i, j int) bool { return v.Orphans[i].Pattern < v.Orphans[j].Pattern })
	return v
}

// validUpstreamMode: mode when it is one a crawler can be set to, else "".
func validUpstreamMode(mode string) string {
	switch mode {
	case classify.GroupModeWhite, classify.GroupModeNone, classify.GroupModeBlack:
		return mode
	}
	return ""
}

// parseUpstreamPatternModes reads the crawlers set one by one from the
// UA-filter form: each `upstream_pattern_mode` value is "<mode>:<pattern>"
// (the mode never holds a colon, so the first one splits them; the pattern
// may hold more), and each `upstream_pattern_drop` value names a pattern the
// operator removed.  The page posts one value per crawler that does not
// follow its group, so an absent crawler is one that does.
func parseUpstreamPatternModes(modes, drops []string) map[string]string {
	drop := map[string]bool{}
	for _, p := range drops {
		drop[strings.TrimSpace(p)] = true
	}
	out := map[string]string{}
	for _, v := range modes {
		mode, pat, ok := strings.Cut(v, ":")
		if !ok {
			continue
		}
		pat = strings.TrimSpace(pat)
		if mode = validUpstreamMode(strings.TrimSpace(mode)); mode == "" || pat == "" || drop[pat] {
			continue
		}
		out[pat] = mode
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
