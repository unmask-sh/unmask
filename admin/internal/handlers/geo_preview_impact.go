package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// What a country rule would stop among the link-preview fetchers, from the
// last day's name-only traffic -- shown on the country tab as the rules are
// edited, before they are saved.
//
// A country rule challenges a named crawler like anyone, and the social
// networks' link-preview fetchers are named crawlers calling from abroad.  An
// operator writing the rule against the world's scrapers could not see that
// it would stop them; the first sign was a day of posts without their cards.
// The access-log reader keeps the name-only passes by crawler and country
// (unmask_crawler_named_hourly), so the tab's proposed rules can be run over
// the last 24 hours of the social-preview crawlers and the answer shown next
// to the rules themselves.
//
// A fetcher the name-and-network pair verifies (previewverify.go) never meets
// the axis, so it is left out of the count and named as verified instead --
// when an ASN mmdb is configured to verify it by; without one it is counted
// like the rest, which is what will happen.

// previewImpactWindowHours is how far back the estimate reads.
const previewImpactWindowHours = 24

type previewImpactRow struct {
	Crawler  string `json:"crawler"`
	Requests int64  `json:"requests"`
}

type previewImpact struct {
	WindowHours int                `json:"window_hours"`
	Rows        []previewImpactRow `json:"rows"`     // fetchers the rules would stop, most first
	Verified    []string           `json:"verified"` // fetchers the pair clears, left out of Rows
	ASNMMDB     bool               `json:"asn_mmdb"` // an ASN mmdb is configured to verify by
}

// AdminGeoPreviewImpact: GET /admin/settings/geo/preview-impact
//
//	?default=<action>        action for a country without a rule (the tab's ①)
//	&rule_default=<action>   action for a rule row left blank (the tab's ②)
//	&rules=JP:skip,CN:deny   the enabled rows, a blank action inheriting ②
//
// Answers the JSON above.  Admin role, like the tab.
func (h *Handler) AdminGeoPreviewImpact(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	def := geoActionOrSkip(q.Get("default"))
	ruleDef := q.Get("rule_default")
	if strings.TrimSpace(ruleDef) == "" {
		// A blank ② is a challenge, as GeoConfig.ResolvedDefaultRuleAction:
		// registering a country means acting on it.
		ruleDef = settings.RateChallengePoWThenCaptcha
	}
	ruleDef = geoActionOrSkip(ruleDef)
	rules := map[string]string{}
	for _, item := range strings.Split(q.Get("rules"), ",") {
		cc, act, _ := strings.Cut(item, ":")
		cc = strings.ToUpper(strings.TrimSpace(cc))
		if len(cc) != 2 {
			continue
		}
		if act = strings.TrimSpace(act); act == "" {
			act = ruleDef
		}
		rules[cc] = geoActionOrSkip(act)
	}
	out := h.previewImpact(r.Context(), h.snapshotSettings(), def, rules)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

// geoActionOrSkip: a valid country action, else skip -- an unknown value
// stops nothing rather than everything.
func geoActionOrSkip(act string) string {
	act = strings.TrimSpace(act)
	if act == "" || !settings.IsValidGeoAction(act) {
		return settings.GeoActionSkip
	}
	return act
}

// previewImpact runs the proposed rules over the window's name-only passes
// of the social-preview crawlers.
func (h *Handler) previewImpact(ctx context.Context, s settings.Settings, def string, rules map[string]string) previewImpact {
	out := previewImpact{WindowHours: previewImpactWindowHours, Rows: []previewImpactRow{}, Verified: []string{}}
	out.ASNMMDB = strings.TrimSpace(s.IPGeo.MMDBASNPath) != ""
	social := map[string]bool{}
	for _, e := range classify.UpstreamRescueList()["social-preview"] {
		if name := classify.CrawlerNameFromPattern(e.Pattern); name != "" {
			social[name] = true
		}
	}
	verified := map[string]bool{}
	if out.ASNMMDB {
		for p := range nginxconf.PreviewVerifiedPatterns(s.Nginx) {
			if name := classify.CrawlerNameFromPattern(p); name != "" {
				verified[name] = true
				out.Verified = append(out.Verified, name)
			}
		}
		sort.Strings(out.Verified)
	}
	if h == nil || h.DB == nil {
		return out
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	since := time.Now().Unix()/3600 - previewImpactWindowHours
	rows, err := h.DB.QueryContext(ctx,
		`SELECT crawler, country, SUM(cnt) FROM unmask_crawler_named_hourly WHERE bucket_hour >= ? GROUP BY crawler, country`, since)
	if err != nil {
		log.Printf("country tab: preview impact: %v", err)
		return out
	}
	defer rows.Close()
	hit := map[string]int64{}
	for rows.Next() {
		var crawler, cc string
		var n int64
		if err := rows.Scan(&crawler, &cc, &n); err != nil {
			continue
		}
		if !social[crawler] || verified[crawler] {
			continue
		}
		// What nginx does: an address the geo block does not list -- a
		// country without a rule, or one the mmdb could not place -- gets
		// the default action.
		act := def
		if a, ok := rules[strings.ToUpper(cc)]; ok {
			act = a
		}
		if act == settings.GeoActionSkip {
			continue
		}
		hit[crawler] += n
	}
	for name, n := range hit {
		out.Rows = append(out.Rows, previewImpactRow{Crawler: name, Requests: n})
	}
	sort.Slice(out.Rows, func(i, j int) bool {
		if out.Rows[i].Requests != out.Rows[j].Requests {
			return out.Rows[i].Requests > out.Rows[j].Requests
		}
		return out.Rows[i].Crawler < out.Rows[j].Crawler
	})
	return out
}
