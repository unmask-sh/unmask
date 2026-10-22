// previewverify.go: link-preview fetchers verified by the network they call
// from.
//
// A social network's link-preview fetcher (X, Facebook, LINE) publishes no
// address list, so unmask passes it on its name alone -- and a country or ASN
// rule the operator writes against the world's scrapers takes the fetcher down
// with them, since it calls from abroad.  Nothing on the page shows that; the
// first sign is a day of posts without their cards.  The vendor does run its
// fetchers from its own autonomous system, which nobody else can send from,
// so the name and the calling network together are the check an address list
// would have been: the UA map names the fetcher, the ASN mmdb (walked at
// render time, like the ASN rules) names the network, and the pair clears the
// country and ASN axes only -- challenge, deny and the CAPTCHA grade -- the
// way an axis-exempt path does.  A custom rule, a protected path, a trap, a
// deny from another axis and every rate limit apply to it as to any named
// crawler.
//
// Meta's AI crawlers call from the same system and are not listed: the pair
// is per pattern, so meta-externalagent stays a named crawler.
package nginxconf

import (
	"sort"
	"strconv"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// PreviewFetcher: one upstream crawler-user-agents.json pattern and the
// autonomous systems its vendor fetches from.
type PreviewFetcher struct {
	Pattern string // the upstream `pattern`, byte for byte (previewverify_test.go pins it against the snapshot)
	Token   string // the UA map's value: the pattern's id in the verified map's keys
	ASNs    []uint // the vendor's own networks
	Vendor  string // for the settings page
}

// PreviewFetchers: the fetchers the pair verifies, in UA-map order.
// facebookexternalhit is first on purpose: Facebook's fetcher sends that name
// alone, while iMessage's "facebookexternalhit/1.1 Facebot Twitterbot/1.0"
// calls from its users' devices and matches no network whichever name is
// read -- as intended, it stays a named crawler.
var PreviewFetchers = []PreviewFetcher{
	// LINE's fetcher sends "facebookexternalhit/1.1;line-poker/1.0" from LY
	// Corporation's network, so the one pattern carries both vendors.
	{Pattern: `facebookexternalhit`, Token: "fbexthit", ASNs: []uint{32934, 38631}, Vendor: "Facebook, LINE"},
	{Pattern: `Facebot`, Token: "facebot", ASNs: []uint{32934}, Vendor: "Facebook"},
	{Pattern: `Twitterbot`, Token: "twitterbot", ASNs: []uint{13414}, Vendor: "X"},
}

// PreviewVerifyRender: the three maps http.inc draws when the check is live.
type PreviewVerifyRender struct {
	CIDRs string            // geo block body: the vendors' networks -> "AS<n>"
	UAs   []PreviewUARender // map $http_user_agent -> token, in PreviewFetchers order
	Pairs []string          // "<token>:AS<n>" keys the verified map lists
}

// PreviewUARender: one entry of the UA map.
type PreviewUARender struct {
	Pattern string
	Token   string
}

// previewWalk is the ASN walk; a test substitutes a canned one.
var previewWalk = ipgeo.CIDRsForASNTargets

// netAxisCanFire reports whether a country or ASN rule on this install can
// resolve to anything but skip.  When none can, the pair has nothing to clear
// and the walk is not paid for.
func netAxisCanFire(d *renderData) bool {
	if d.GeoDefaultAction != settings.GeoActionSkip || d.AsnDefaultAction != settings.GeoActionSkip {
		return true
	}
	for _, r := range d.GeoRules {
		if r.Action != settings.GeoActionSkip {
			return true
		}
	}
	for _, r := range d.AsnRules {
		if r.Action != settings.GeoActionSkip {
			return true
		}
	}
	return false
}

// previewVerify builds the render for the fetchers whose name is on the UA
// whitelist (d.SearchBotPatterns: the operator's UA filter has them white),
// or nil when the check is inert: no such name, no ASN mmdb to walk, no axis
// that can fire, or a walk that found none of the networks.  A fetcher the
// operator set to normal checks or stopped is not verified -- the pair clears
// an axis for a crawler the operator passes, never one they judge.
func previewVerify(s settings.Settings, d *renderData) *PreviewVerifyRender {
	if s.IPGeo.MMDBASNPath == "" || !netAxisCanFire(d) {
		return nil
	}
	white := make(map[string]bool, len(d.SearchBotPatterns))
	for _, p := range d.SearchBotPatterns {
		white[p] = true
	}
	var pv PreviewVerifyRender
	asns := map[uint]bool{}
	for _, f := range PreviewFetchers {
		if !white[f.Pattern] {
			continue
		}
		pv.UAs = append(pv.UAs, PreviewUARender{Pattern: f.Pattern, Token: f.Token})
		for _, n := range f.ASNs {
			asns[n] = true
			pv.Pairs = append(pv.Pairs, f.Token+":AS"+strconv.FormatUint(uint64(n), 10))
		}
	}
	if len(pv.UAs) == 0 {
		return nil
	}
	targets := make([]ipgeo.ASNTarget, 0, len(asns))
	for n := range asns {
		targets = append(targets, ipgeo.ASNTarget{ASN: n, Value: "AS" + strconv.FormatUint(uint64(n), 10)})
	}
	// Deterministic: the walk's matcher is a map, the render diff is not.
	sort.Slice(targets, func(i, j int) bool { return targets[i].ASN < targets[j].ASN })
	cidrs, err := previewWalk(s.IPGeo.MMDBASNPath, targets)
	if err != nil || cidrs == "" {
		// A broken or missing db: the fetchers stay named crawlers; doctor's
		// mmdb check names the db.
		return nil
	}
	pv.CIDRs = cidrs
	return &pv
}

// PreviewVerifiedPatterns: the patterns the pair would verify on this
// install, for the settings page -- the fetchers on the whitelist, whether or
// not the ASN mmdb is there to back them (the page says which).
func PreviewVerifiedPatterns(n settings.Nginx) map[string]PreviewFetcher {
	white, _, _, _ := collectUpstreamPatternsByMode(n.SearchBots, RangeVerifiedUA(n))
	set := make(map[string]bool, len(white))
	for _, p := range white {
		set[p] = true
	}
	out := map[string]PreviewFetcher{}
	for _, f := range PreviewFetchers {
		if set[f.Pattern] {
			out[f.Pattern] = f
		}
	}
	return out
}

// PreviewFetcherFor: the fetcher the pair knows pattern as, or nil.
func PreviewFetcherFor(pattern string) *PreviewFetcher {
	for i := range PreviewFetchers {
		if PreviewFetchers[i].Pattern == pattern {
			return &PreviewFetchers[i]
		}
	}
	return nil
}

// ASNList: the fetcher's networks for display, "AS32934, AS38631".
func (f PreviewFetcher) ASNList() string {
	parts := make([]string, 0, len(f.ASNs))
	for _, n := range f.ASNs {
		parts = append(parts, "AS"+strconv.FormatUint(uint64(n), 10))
	}
	return strings.Join(parts, ", ")
}

// NetAxisConfigured: whether a country or ASN rule is set on this install
// (the doctor's and the settings page's question; the render asks the
// resolved rules instead, netAxisCanFire).
func NetAxisConfigured(n settings.Nginx) bool {
	if n.Geo.ResolvedDefaultAction() != settings.GeoActionSkip || n.Asn.ResolvedDefaultAction() != settings.GeoActionSkip {
		return true
	}
	for _, r := range n.Geo.Rules {
		if !r.Enabled {
			continue
		}
		if act := strings.TrimSpace(r.Action); act == "" || act == settings.GeoActionSkip {
			if act == "" && n.Geo.ResolvedDefaultRuleAction() != settings.GeoActionSkip {
				return true
			}
			continue
		}
		return true
	}
	return n.Asn.HasEnabled()
}
