// /admin/ — top dashboard (= summary page).
//
// Layout:
//   - 4 KPI boxes: events / serves / verify_ok / currently-BANNED, all over the last 24h
//   - 10 most recent detections (= latest unmask_event rows)
//   - shortcuts to each tab (= stats / bot hunt / persistent BAN / settings / docs)
//
// Data source is only the existing events package.  Lightweight.
package handlers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/hll"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
)

// decodeCookieValue percent-decodes a cookie value.  The pickers write cookies
// with the browser's encodeURIComponent (so a comma-joined host list becomes
// "a%2Cb", an IPv6 site keeps its %3A), but net/http hands back the raw value
// undecoded — without this the host filter would split "a%2Cb" into one junk
// entry.  Falls back to the raw value on a malformed escape.
func decodeCookieValue(v string) string {
	if d, err := url.PathUnescape(v); err == nil {
		return d
	}
	return v
}

// AdminTopOverview: GET /admin/  — top dashboard.
func (h *Handler) AdminTopOverview(w http.ResponseWriter, r *http.Request) {
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	// host filter (= global scope of the shared host_picker.  Sourced from cookie / ?host=).
	hosts := resolveHostFilter(r)
	// site filter (= shared site_picker, single-select.  cookie / ?site=).
	site := resolveSiteFilter(r)

	// Last-24h KPIs, traffic uniqueness, the recent-detections list, and the AI
	// crawler funnel are all independent read queries.  Issue them concurrently so
	// a cold cache pays the slowest one, not their sum -- the landing page's
	// biggest win (they were previously run back-to-back).
	var (
		kpiServes, kpiPoWPass, kpiCaptchaPass int
		kpiLoaded                             int
		powLoaded, powAbandon                 int
		comp                                  dashboard.TrafficComposition
		uBlocked                              int
		uKnown                                bool
		recentRaw                             []events.Row
		recentErr                             error
		aiRows                                []AITrafficRow
		aiDetail                              map[string][]AICrawlerRow
		aiServed                              []dashboard.AITrafficRow
		overBlock                             OverBlockHealth
	)
	var wg sync.WaitGroup
	launch := func(f func()) {
		wg.Add(1)
		go func() { defer wg.Done(); f() }()
	}
	launch(func() { kpiServes = countEvents(ctx, h, 1440, "serve", site, hosts) })
	// Passed counts split by how the visitor cleared the challenge.  PoW-only is
	// transparent (mostly real browsers); the CAPTCHA paths mean a human solved
	// one.  The old "verify" phase does not exist in native mode.
	launch(func() { kpiPoWPass = countEvents(ctx, h, 1440, "bv_pow_only", site, hosts) })
	// Challenge pages that actually ran their JS.  `load` rather than `serve`
	// because a scraper that never executes JS is served a page and emits no
	// load, so counting serves would fold every bot into a number meant to
	// describe real visitors.  Used by the funnel below.
	launch(func() { kpiLoaded = countEvents(ctx, h, 1440, "load", site, hosts) })
	// ...and the abandon rate's own pair, narrowed to ordinary visitors facing
	// the transparent proof-of-work.  See countUnruledPoW: counting every
	// abandon made the tile a readout of how much targeted traffic the rules
	// were turning away, which is the configuration working rather than
	// visitors lost.
	launch(func() { powLoaded = countUnruledPoW(ctx, h, 1440, "load", site, hosts) })
	launch(func() { powAbandon = countUnruledPoW(ctx, h, 1440, "abandon", site, hosts) })
	launch(func() {
		kpiCaptchaPass = countEventsPhases(ctx, h, 1440,
			[]string{"bv_captcha_only", "bv_pow_then_captcha"}, site, hosts)
	})
	// Non-human %: request counts from unmask_cookie_minute.  "—" when the
	// access-log feed is off (no counters at all).
	launch(func() {
		var err error
		comp, err = dashboard.TrafficRequests(ctx, h.DB, 1440, site)
		if err != nil {
			log.Printf("trafficRequests: %v", err)
		}
	})
	// Distinct clients, for the hero's "from an estimated N addresses" line --
	// the one figure on this page where a distinct count is what is being
	// asked for rather than a proxy for volume.
	launch(func() { _, uBlocked, uKnown = trafficUnique(ctx, h, 1440, site) })
	// 10 most recent detections: fetch 40 raw rows so the client-side session
	// collapse (group by beacon_token) still shows ~10 sessions.
	launch(func() {
		recentRaw, recentErr = events.FetchPaged(ctx, h.DB, "", "", "", "", "", "", site, hosts, 0, 40, 0)
	})
	// AI traffic funnel: "all" reads unmask_crawler_minute (sees rescued/bypassed
	// traffic too), "served" reads the hkAITag aggregate (phase=serve only).
	launch(func() { aiRows = aiTrafficSummary(ctx, h, 1440) })
	launch(func() { aiDetail = aiTrafficDrilldown(ctx, h, 1440) })
	launch(func() { aiServed, _ = dashboard.AITrafficBreakdown(ctx, h.DB, "", nil, 24) })
	// Over-block circuit-breaker health -- a global signal, so it lives on the
	// landing rather than the per-site stats dashboard.
	launch(func() { overBlock, _ = h.OverBlockHealth(ctx) })
	wg.Wait()

	if recentErr != nil {
		log.Printf("overview recent: %v", recentErr)
	}
	// "Blocked" for the hero: challenges fired that produced no pass, minus the
	// visitors who loaded the challenge and left.  Someone who walked away was
	// not stopped -- and the abandons are recorded, so they can be taken out
	// rather than disclosed in a footnote on every figure that uses this.  What
	// remains is still an estimate at the edges (a serve in the last seconds
	// has not had time to pass, and an abandon that never sent its beacon
	// cannot be told from a bot that fetched the page and left).
	// Challenges fired comes from the access log, not the event log: a deny
	// serves no challenge page, so it writes no serve event while the log still
	// records it.  On a site that denies bots outright the event log saw 493 of
	// 6,329 -- a 12x undercount of the headline claim.  kpiServes stays for the
	// funnel below, where it means "challenge pages served", which is what the
	// pass counts beside it are a fraction of.
	kpiFired := comp.Challenged
	if kpiFired < kpiServes {
		// No log feed (or it is behind): fall back to what the events know.
		kpiFired = kpiServes
	}
	// The abandon figure: ordinary visitors who ran the transparent
	// proof-of-work and left without finishing it.
	//
	// Both halves are narrowed the same way, because the question is whether
	// the challenge costs real visitors -- not how much targeted traffic the
	// rules are turning away.  Deriving it from every load instead (load minus
	// passes) read 99.2% on a node where a residential browser farm was being
	// sent to a CAPTCHA it never solves; ordinary visitors there abandoned 32
	// times.  Using the `abandon` beacon but counting all of it still read
	// 83.6%, because that farm sends the beacon faithfully.
	abandon := powAbandon
	abandonPct := 0.0
	if powLoaded > 0 {
		abandonPct = float64(abandon) / float64(powLoaded) * 100
	}
	// Blocked subtracts only the visitors who walked away, not everything that
	// loaded and did not pass: a targeted client shown a CAPTCHA it never
	// solves WAS stopped, and crediting it as "walked away" hands the malicious
	// side back to the traffic the rules exist to catch.  On the farm node that
	// is 65,634 of 65,676 abandons.
	kpiBlocked := kpiFired - kpiPoWPass - kpiCaptchaPass - abandon
	if kpiBlocked < 0 {
		kpiBlocked = 0
	}
	// Observe mode fires no challenge, so the arithmetic above is structurally
	// zero -- and the card then reported "no attacks" on installs that were
	// being scanned continuously.  The judgement is still recorded, so when the
	// mode is on the headline switches to what unmask WOULD have stopped, and
	// says which question it is answering.
	// Passthrough suppresses the challenge too, so it lands the card in the same
	// structural zero.  Both states must stop the card claiming quiet.
	observeOnly := h.cfg().Challenge.Resolve(site).IsObserveOnly() || h.cfg().Global.Passthrough
	kpiWouldBlock := 0
	if observeOnly {
		if n, err := dashboard.ObserveOnlyWouldBlock(ctx, h.DB, site, hosts, 24); err == nil {
			kpiWouldBlock = n
		} else {
			log.Printf("overview observe-mode count: %v", err)
		}
	}
	// Abandon rate: of the visitors whose browser LOADED the challenge, how
	// many never finished it.  This is the one number that says whether the
	// challenge is too heavy for real people -- it excludes bots by
	// construction (they do not run the JS, so they never reach `load`), which
	// is what separates it from the blocked count above.  Measured at 6.55%
	// across the fleet when the proof-of-work still ran on the UI thread.
	// (Computed with the blocked figure above, which subtracts the same count.)
	//
	// If the shared 5s deadline expired during the COUNT(*) queries above, the
	// kpi* values are partial zeros rather than real measurements.  Flag it so
	// the template renders "—" and suppresses the reassuring "😴 quiet / 0
	// blocked" hero -- a DB-busy landing must not masquerade as a calm one.
	kpiKnown := ctx.Err() == nil
	nonHumanPct := 0.0
	// Non-human = requests from bots we deliberately passed PLUS requests we
	// answered with a challenge nobody cleared.  Each request is counted once
	// on one side or the other, so the sum cannot exceed the total.
	// Blocked = the challenges the data plane actually fired, minus the ones
	// that were cleared or walked away from.  The fires come from the access
	// log rather than the event log: a deny serves no challenge page, so it
	// writes no serve event while the log still records it -- on a site that
	// denies bots outright the event log saw 493 of 6,329.  The solves and the
	// abandons stay events, because each is one row per occurrence, which is
	// exactly what this table's 'pow' / 'captcha' are not (they count every
	// request from a client that already holds a cookie).
	//
	// The event terms are site-scoped only: the log totals carry no host
	// dimension, so mixing a host-filtered numerator with an unfiltered
	// denominator would understate the ratio on a narrowed page.
	tileBlocked := kpiBlocked
	rNonHuman := comp.Benign + tileBlocked
	if rNonHuman > comp.Total {
		rNonHuman = comp.Total
	}
	// BAN has no host axis (= keyed on the IP+JA4 pair, global).  Same number for every host.
	currentBans := 0
	if h.BanMgr != nil {
		currentBans = len(h.BanMgr.Snapshot())
	}

	// IP rendering is unified as "flag + IP + popover" (= same as bans / hunt / dashboard).
	// Tag each row with the IP-geo-looked-up country code + the ban state for the IP.
	// Banned is required by the shared partial_events_table.html partial -- without
	// it the {{ if .Banned }} branch fails template execution and the page truncates
	// at the first row of the recent table.  Same shape as huntEventRow.
	type recentRow struct {
		events.Row
		CountryCode string
		Banned      bool
	}
	geoOK := h.IPGeo != nil && h.IPGeo.Loaded()
	banOK := h.BanMgr != nil
	ccCache := map[string]string{}
	banCache := map[string]bool{}
	recent := make([]recentRow, 0, len(recentRaw))
	for _, r0 := range recentRaw {
		cc := ""
		if geoOK && r0.IP != "" {
			if v, ok := ccCache[r0.IP]; ok {
				cc = v
			} else {
				cc = h.IPGeo.LookupInfo(r0.IP).Country
				ccCache[r0.IP] = cc
			}
		}
		banned := false
		if banOK && r0.IP != "" {
			if v, ok := banCache[r0.IP]; ok {
				banned = v
			} else {
				banned = h.BanMgr.IsBanned(ctx, r0.IP, "")
				banCache[r0.IP] = banned
			}
		}
		recent = append(recent, recentRow{Row: r0, CountryCode: cc, Banned: banned})
	}

	// Hosts / HostSelected / SelfHostID (= for the shared host_picker) are
	// injected by addMeToData, which is shared across every admin page.
	recentUAList := make([]string, len(recent))
	for i := range recent {
		recentUAList[i] = recent[i].UA
	}
	// Human is COUNTED, not left over: requests that arrived already holding a
	// pass cookie, plus the ones that cleared a challenge inside the window
	// (those arrived without a cookie, so the counters filed them under
	// challenge_served and the blocked figure above has already given them
	// back).  As a remainder it silently absorbed everything the other three
	// segments could not explain -- including the people who loaded the
	// challenge and left, who are not human traffic that got through and were
	// being reported on the abandon tile as a problem at the same moment this
	// card was counting them as fine.
	rHuman := comp.Passed + kpiPoWPass + kpiCaptchaPass
	// Requests that arrived on a credential re-bound onto this address after a
	// solve somewhere else.  Kept OUT of the human share -- "solved once, then
	// roamed" is the shape a distributed crawler has and a person rarely does,
	// and folding it in there is what hid one for months -- but not given a
	// segment of its own either: measured across the fleet it is 3.3% of a
	// day on the busiest node and 0.0% on three others, and a bar segment
	// that is invisible everywhere teaches the eye to skip the card.  It
	// lands in the residue with a line of its own in the breakdown, so the
	// number is still one hover away and still not claimed as people.
	//
	// The signal itself lives in hunt's lineage table, which answers the
	// question this share cannot: not how many such requests there were, but
	// how many addresses ONE solve reached.
	rRebound := comp.Rebound
	// ...which leaves a residue, and it gets its own segment rather than being
	// hidden in a neighbour.  Two things are in it, both real and neither
	// belonging to a named share:
	//
	//   - the abandons, per above.
	//   - requests judged and let through with no challenge at all (an
	//     Operating-mode bucket set to pass).  Not "bypassed" -- that means
	//     exempted from judgement -- and not blocked.  Zero on a default
	//     install, which is why this went unnoticed.
	//
	// Both are non-negative, so under exclusive counters this cannot go below
	// zero.  When it does, the exclusivity has broken again, and "other" is
	// where that is visible instead of a named segment quietly absorbing it --
	// so the unknown case lives HERE now, and the human share always renders a
	// real measurement.
	rOther := comp.Total - comp.Benign - tileBlocked - comp.Bypassed - rHuman
	rOtherKnown := rOther >= 0
	if !rOtherKnown {
		rOther = 0
	}
	// Named components for the segment's popover, so "other" is a description
	// rather than a shrug.  The balance is what the two measured terms do not
	// account for: window edges (a solve counted whose serve fell before the
	// cutoff) and the clamps above.  Always rendered, including at zero and
	// including when negative -- "0" is the statement that the parts explain the
	// whole, which is worth more than the line's absence, and a skew worth
	// noticing is exactly what an operator should see rather than a tidied
	// number.
	rOtherSkew := rOther - abandon - comp.Unchallenged - comp.Passthrough - rRebound

	// Which denominator the share is taken against.  Bypassed requests are the
	// ones the operator exempted from judgement -- package managers, monitors,
	// a feed -- and on a real install they are not a rounding error: 56% of a
	// day's traffic on one fleet node.  Left in the denominator they dilute
	// every other share, so the headline answers "what is this server
	// serving?" when the question an operator usually has is "of what unmask
	// actually judged, how much was not a person?".  Both are legitimate, and
	// they differ by about 2x here, so the card names the denominator it used
	// and lets the operator switch rather than picking one silently.
	//
	// BOTH denominators are computed here and BOTH are rendered; the toggle
	// only changes which one is on screen.  That keeps the arithmetic in one
	// place -- recomputing it in JS on click would put the same formula in two
	// languages, the drift this codebase keeps paying for -- while costing
	// nothing: the two views come from counts already in hand, so switching
	// needs no request at all, let alone a navigation.
	// The two named denominators generalised: every legend segment is a
	// toggle, and the denominator is whatever remains switched on.  "All" and
	// "judged" survive as presets over the same state -- one rule instead of
	// two mechanisms, and the operator can also ask the questions the presets
	// could not ("of the bot traffic alone, how much is malicious?").
	//
	// The selected view is still rendered SERVER-side from the cookie/query,
	// so the page is truthful without JS and never flashes a default; the
	// script below mirrors the arithmetic only for the in-place toggle.
	enabledSegs := resolveCompSegs(r)
	segCounts := []compSegDef{
		{compSegBenign, comp.Benign, true},
		{compSegBad, tileBlocked, true},
		{compSegBypass, comp.Bypassed, false},
		{compSegHuman, rHuman, false},
		{compSegOther, rOther, false},
	}
	// Denominator by subtraction, not by summing the enabled parts: with every
	// segment on it must equal comp.Total even while the residue is "unknown"
	// (parts that do not sum), exactly as the old all-view did.
	selDenom := comp.Total
	for _, sg := range segCounts {
		if !enabledSegs[sg.key] {
			selDenom -= sg.count
		}
	}
	if selDenom < 0 {
		selDenom = 0
	}
	if comp.OK && selDenom > 0 {
		num := 0
		for _, sg := range segCounts {
			if sg.nonHuman && enabledSegs[sg.key] {
				num += sg.count
			}
		}
		nonHumanPct = float64(num) / float64(selDenom) * 100
	}
	compSegs := make([]map[string]any, 0, len(segCounts))
	for _, sg := range segCounts {
		toggled := make(map[string]bool, len(enabledSegs))
		for k, v := range enabledSegs {
			toggled[k] = v
		}
		toggled[sg.key] = !toggled[sg.key]
		target := compSegsParam(toggled)
		// The last enabled segment cannot be switched off (a share of nothing
		// answers nothing), and an unknown residue cannot leave the
		// denominator (its count is not a number that can be subtracted).
		if target == "" || (sg.key == compSegOther && !rOtherKnown) {
			target = ""
		}
		compSegs = append(compSegs, map[string]any{
			"Key": sg.key, "Count": sg.count, "NonHuman": sg.nonHuman,
			"On": enabledSegs[sg.key], "ToggleParam": target,
		})
	}
	compState := compSegsParam(enabledSegs)
	data := map[string]any{
		"Lang":           i18n.Resolve(r),
		"TZ":             resolveTZ(r),
		"KPIServes":      kpiFired,
		"KPIPoWPass":     kpiPoWPass,
		"KPICaptchaPass": kpiCaptchaPass,
		// The pass cards' quiet second line: requests admitted on a cookie of
		// that kind.  The headline counts solves; one solve then admits every
		// request its cookie covers, so the two figures answer different
		// questions and the card names both to keep them apart.  From the same
		// counters as the non-human card, so "no feed" renders the same dash.
		"KPIPoWCookie":     comp.PowPass,
		"KPICaptchaCookie": comp.CaptchaPass,
		"KPICookieKnown":   comp.OK,
		"KPIBlocked":       kpiBlocked,
		"ObserveOnly":      observeOnly,
		"KPIWouldBlock":    kpiWouldBlock,
		"KPILoaded":        kpiLoaded,
		// The abandon tile's own denominator: ordinary visitors who ran the
		// transparent PoW.  Deliberately NOT kpiLoaded -- showing "N / <every
		// load>" beside a rate computed over a narrower population is two
		// figures that cannot be divided into each other.
		"KPIPoWLoaded":   powLoaded,
		"KPIAbandon":     abandon,
		"KPIAbandonPct":  abandonPct,
		"KPIKnown":       kpiKnown,
		"KPIReqTotal":    comp.Total,
		"KPIReqBenign":   comp.Benign,
		"KPIReqNonHuman": rNonHuman,
		// Requests holding a pass cookie plus the challenges cleared inside the
		// window: a count, not a remainder, so the label means what it says.
		"KPIReqHuman":    rHuman,
		"KPIReqRebound":  rRebound,
		"KPIReqBypassed": comp.Bypassed,
		// The residue, with the two things in it named for the popover.
		"KPIReqOther":        rOther,
		"KPIReqPassthrough":  comp.Passthrough,
		"KPIReqOtherKnown":   rOtherKnown,
		"KPIReqOtherAbandon": abandon,
		"KPIReqOtherUnchall": comp.Unchallenged,
		"KPIReqOtherSkew":    rOtherSkew,
		// CompState is the canonical name of the enabled-segment set; CompSegs
		// the denominator its own headline, bar and legend shares are taken
		// against -- so a card can never show a percentage of one total beside
		// a caption naming another.
		"CompState":        compState,
		"CompSegs":         compSegs,
		"CompDenom":        selDenom,
		"CompPct":          nonHumanPct,
		"KPIReqBlocked":    tileBlocked,
		"KPIUniqueBlocked": uBlocked,
		"KPIUniqueKnown":   uKnown,
		"KPINonHumanPct":   nonHumanPct,
		"KPINonHumanKnown": comp.OK && comp.Total > 0,
		"KPICurrentBans":   currentBans,
		"Recent":           recent,
		// partial_events_table reads .Rows / .EventsCap / .Range so we expose the
		// same recent slice under those keys.  EventsCap=10 caps the client-side
		// visible-session count after the session-collapse pass so the card
		// honours its "10 most recent" heading even though we pre-fetched 40 raw rows.
		// UABotNote: see hunt_admin.go -- same key the shared events partial
		// reads to caption a listed-crawler badge.
		"UABotNote": uaBotNoteByUA(recentUAList, h.snapshotSettings().Nginx),
		"Rows":      recent,
		"EventsCap": 10,
		"Range":     "",
		// Drop the per-row BAN action column on the overview card so the URL /
		// UA columns get the recovered ~4rem of horizontal room.  The hunt page
		// (= the actual deep-dive destination) keeps the action column on.
		"HideActions":     true,
		"AITraffic":       aiRows,
		"AITrafficDetail": aiDetail,
		"AITrafficServed": aiServed,
		"OverBlock":       overBlock,
	}
	// Persist the denominator choice when it arrived as a link click, so the
	// next visit opens on the view the operator picked.  Written only for an
	// explicit ?comp= (never on a plain load) so a bookmarked URL cannot
	// silently repin someone else's session, and Lax/HttpOnly-free because the
	// value is a view preference the template reads back, not a credential.
	if v := r.URL.Query().Get("comp"); v != "" {
		if on, ok := parseCompSegs(v); ok {
			http.SetCookie(w, &http.Cookie{
				Name: compSegCookieName, Value: compSegsParam(on), Path: h.basePath(),
				MaxAge: 365 * 24 * 3600, SameSite: http.SameSiteLaxMode,
			})
		}
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	h.addMeToData(r, data)
	if err := tmpl.ExecuteTemplate(w, "overview.html", data); err != nil {
		log.Printf("overview render: %v", err)
	}
}

// AITrafficRow: per-tag aggregation for the overview's crawler funnel.
// Total = every request of that crawler tag; Served = the subset that was
// challenged (= did not pass straight through); Passed = Total - Served.
// Category names follow classify.CrawlerTagOrder (12 tags) so the overview
// + stats cards share one taxonomy.
type AITrafficRow struct {
	Category string // one of classify.CrawlerTagOrder
	Total    int
	Served   int
	Passed   int
}

// aiTrafficSummary reads the last `minutes` of the unmask_crawler_minute
// aggregate (fed by the nginx access-log pipeline / auth_request BumpCrawler).
// This is the only source that sees rescued crawlers — they are passed
// straight through and never recorded in unmask_event.  Global (not scoped by
// the host / site picker; the aggregate has no host dimension).  Best-effort.
func aiTrafficSummary(ctx context.Context, h *Handler, minutes int) []AITrafficRow {
	// Order matches the stats card so the operator's eye doesn't have to
	// re-anchor when switching between views.  Zero-row tags stay visible
	// per the feedback_zero_row_policy.
	byCat := map[string]*AITrafficRow{}
	for _, k := range classify.CrawlerTagOrder {
		byCat[k] = &AITrafficRow{Category: k}
	}
	if h.DB != nil {
		sinceMin := time.Now().Unix()/60 - int64(minutes)
		rows, err := h.DB.QueryContext(ctx,
			`SELECT category, SUM(total), SUM(served) FROM unmask_crawler_minute
			 WHERE bucket_min > ? GROUP BY category`, sinceMin)
		if err != nil {
			log.Printf("aiTrafficSummary: %v", err)
		} else {
			defer rows.Close()
			for rows.Next() {
				var cat string
				var total, served int
				if err := rows.Scan(&cat, &total, &served); err != nil {
					continue
				}
				if r := byCat[cat]; r != nil {
					r.Total = total
					r.Served = served
					r.Passed = total - served
				}
			}
		}
	}
	out := make([]AITrafficRow, 0, len(classify.CrawlerTagOrder))
	for _, k := range classify.CrawlerTagOrder {
		out = append(out, *byCat[k])
	}
	// Sort by Total DESC; ties keep classify.CrawlerTagOrder via stable sort.
	// Zero-row tags fall to the bottom but stay visible (feedback_zero_row_policy).
	sort.SliceStable(out, func(i, j int) bool { return out[i].Total > out[j].Total })
	return out
}

// AICrawlerRow: one individual crawler's traffic within a category, for the
// drill-down popover on the AI/crawler card's "all" tab.  Total = every
// request from that crawler; Served = the subset that was challenged; Passed =
// Total - Served.  Spark is the polyline "points" of a tiny trend sparkline
// (total volume over the window, downsampled), "" when there's nothing to draw.
type AICrawlerRow struct {
	Crawler string
	Total   int
	Served  int
	Passed  int
	Spark   string
	// RangeVerified is true when this crawler's UA-only rescue has been
	// replaced by IP-range verification (its vendor publishes ranges AND every
	// backing preset is enabled + past the NEW gate).  For such a crawler the
	// genuine bot arrives from a published range and is bypassed before it can
	// be served, so Served counts only requests from OUTSIDE the range -- i.e.
	// spoofed traffic carrying the crawler's UA.  The card reads it that way.
	RangeVerified bool
}

// aiTrafficDrilldown reads the per-crawler breakdown that backs the card's
// "all"-tab popover, keyed by category (= classify.CrawlerTagOrder).  Source
// is unmask_crawler_detail_hourly -- the same access-log pipeline as
// aiTrafficSummary, resolved one level finer (category -> individual crawler).
//
// It pulls the per-hour rows (not a pre-summed total) so it can also build a
// trend sparkline per crawler: the window's hours are downsampled into ~32
// equal chunks and the per-chunk volume becomes the sparkline.  The chunks are
// label-less (a shape, not dated axes), so they need no operator TZ -- an hour
// is an hour regardless of zone.  Total/Served are the series sums, so the
// popover numbers and the sparkline come from one query.  The lower bound snaps
// down to the containing hour, so the totals never under-count vs the category
// row above.  Only crawlers actually seen produce rows.  Best-effort.
func aiTrafficDrilldown(ctx context.Context, h *Handler, minutes int) map[string][]AICrawlerRow {
	if h.DB == nil {
		return nil
	}
	// Resolve which drill-down crawler names are IP-range verified under the
	// live settings: take the range-verified UA PATTERNS and fold each to the
	// same display name the aggregation keys on.  A crawler in this set has its
	// genuine bots bypassed by range, so its Served figure is spoofed traffic.
	rangeVerifiedNames := map[string]bool{}
	for pat := range nginxconf.UARangePresets {
		if !nginxconf.RangePresetsActive(h.cfg().Nginx, pat) {
			continue
		}
		if name := classify.CrawlerNameFromPattern(pat); name != "" && name != "other" {
			rangeVerifiedNames[name] = true
		}
	}
	nowHour := time.Now().Unix() / 3600
	sinceHour := (time.Now().Unix() - int64(minutes)*60) / 3600
	// Downsample the window's hours into ~32 chunks for the sparkline.
	const sparkTarget = 32
	spanHours := nowHour - sinceHour + 1
	if spanHours < 1 {
		spanHours = 1
	}
	chunkHours := (spanHours + sparkTarget - 1) / sparkTarget // ceil
	if chunkHours < 1 {
		chunkHours = 1
	}
	nBuckets := int((spanHours + chunkHours - 1) / chunkHours) // ceil

	rows, err := h.DB.QueryContext(ctx,
		`SELECT category, crawler, bucket_hour, total, served FROM unmask_crawler_detail_hourly
		 WHERE bucket_hour >= ?`, sinceHour)
	if err != nil {
		log.Printf("aiTrafficDrilldown: %v", err)
		return nil
	}
	defer rows.Close()

	type agg struct {
		total, served int
		series        []int
	}
	byKey := map[[2]string]*agg{} // {category, crawler} -> agg
	for rows.Next() {
		var cat, crawler string
		var bucketHour int64
		var total, served int
		if err := rows.Scan(&cat, &crawler, &bucketHour, &total, &served); err != nil {
			continue
		}
		if total <= 0 {
			continue
		}
		k := [2]string{cat, crawler}
		a := byKey[k]
		if a == nil {
			a = &agg{series: make([]int, nBuckets)}
			byKey[k] = a
		}
		a.total += total
		a.served += served
		if bi := int((bucketHour - sinceHour) / chunkHours); bi >= 0 && bi < nBuckets {
			a.series[bi] += total
		}
	}

	byCat := map[string][]AICrawlerRow{}
	for k, a := range byKey {
		byCat[k[0]] = append(byCat[k[0]], AICrawlerRow{
			Crawler: k[1], Total: a.total, Served: a.served, Passed: a.total - a.served,
			Spark:         sparkPoints(a.series),
			RangeVerified: rangeVerifiedNames[k[1]],
		})
	}
	// Per-category: Total DESC, then crawler name ASC for a stable, readable
	// order (map-scan order is otherwise non-deterministic).
	for cat := range byCat {
		list := byCat[cat]
		sort.Slice(list, func(i, j int) bool {
			if list[i].Total != list[j].Total {
				return list[i].Total > list[j].Total
			}
			return list[i].Crawler < list[j].Crawler
		})
	}
	return byCat
}

// sparkPoints renders a series of per-chunk counts as the "points" attribute of
// an SVG <polyline> in a 64x16 box (1px inset so the stroke stays inside).  The
// y-axis is anchored at 0 and scaled to the series max, so a crawler that ramped
// from nothing reads as a clear rise.  Returns "" when there's nothing to draw
// (fewer than 2 points, or all-zero).
func sparkPoints(series []int) string {
	n := len(series)
	if n < 2 {
		return ""
	}
	max := 0
	for _, v := range series {
		if v > max {
			max = v
		}
	}
	if max <= 0 {
		return ""
	}
	const w, h, pad = 64.0, 16.0, 1.0
	uw, uh := w-2*pad, h-2*pad
	var b strings.Builder
	for i, v := range series {
		x := pad + float64(i)/float64(n-1)*uw
		y := pad + (1-float64(v)/float64(max))*uh
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.1f,%.1f", x, y)
	}
	return b.String()
}

// countEvents: count of unmask_event rows in the last `minutes`.  Empty phase
// means all rows.  Non-empty hosts narrows via IN (...) for multi-host filtering.
// Best-effort (= on error, return 0 and just log).
// countUnruledPoW: events of one phase that reached an ORDINARY visitor -- the
// transparent proof-of-work, fired by nothing in particular.
//
// The abandon rate answers "is the challenge too heavy for real people", and
// counting every abandon answers a different question badly.  A client the
// operator deliberately targeted -- a UA rule, a JA4 bot verdict, a header
// mismatch -- being shown a CAPTCHA and walking away is the configuration
// working, not a visitor lost.  Measured on one node over a day: 65,634 of
// 65,676 abandons carried force_reason=ua_target at captcha_only, so the tile
// read 99.2% while ordinary visitors abandoned 32 times.  Red, and about
// nothing the operator would want to act on.
//
// Switching to the `abandon` beacon alone does not fix it: the residential
// browser farm sends the beacon faithfully, so that reading was still 83.6%.
// The split that works is the reason the challenge fired, which both the load
// and abandon payloads already carry.
//
// force_reason is absent or "none" for a challenge no rule forced, and the
// chain has to be pow_only -- a CAPTCHA is only ever shown to a client
// something already found suspicious, so an abandon there is not evidence
// about ordinary visitors either.
func countUnruledPoW(ctx context.Context, h *Handler, minutes int, phase, site string, hosts []string) int {
	// The hourly rollup answers this in ~24 rows.  It declines when a site or
	// host filter is on (the rollup is install-wide) or when the aggregator
	// has not finished its first pass, and the scan below then runs -- that
	// scan is the definition of the number, this is only where it is read.
	if n, ok := dashboard.UnruledPoWCount(ctx, h.DB, phase, site, hosts, minutes/60); ok {
		return n
	}
	reasonExpr := `json_extract(payload_json, '$.force_reason')`
	modeExpr := `json_extract(payload_json, '$.chmode')`
	if h.DB.Driver != "sqlite" {
		reasonExpr = `JSON_UNQUOTE(JSON_EXTRACT(payload_json, '$.force_reason'))`
		modeExpr = `JSON_UNQUOTE(JSON_EXTRACT(payload_json, '$.chmode'))`
	}
	stmt := `SELECT COUNT(*) FROM unmask_event WHERE date_created > ` + h.DB.NowMinusMinutes(minutes) +
		` AND phase = ?` +
		` AND (` + reasonExpr + ` IS NULL OR ` + reasonExpr + ` IN ('', 'none'))` +
		` AND ` + modeExpr + ` = 'pow_only'`
	args := []any{phase}
	if site != "" {
		stmt += " AND site = ?"
		args = append(args, site)
	}
	if len(hosts) > 0 {
		placeholders := strings.Repeat("?,", len(hosts))
		stmt += " AND host IN (" + placeholders[:len(placeholders)-1] + ")"
		for _, hh := range hosts {
			args = append(args, hh)
		}
	}
	var n int
	if err := h.DB.QueryRowContext(ctx, stmt, args...).Scan(&n); err != nil {
		log.Printf("countUnruledPoW (phase=%q): %v", phase, err)
		return 0
	}
	return n
}

func countEvents(ctx context.Context, h *Handler, minutes int, phase, site string, hosts []string) int {
	if phase != "" {
		if n, ok := dashboard.PhaseCount(ctx, h.DB, []string{phase}, site, hosts, minutes/60); ok {
			return n
		}
	}
	stmt := `SELECT COUNT(*) FROM unmask_event WHERE date_created > ` + h.DB.NowMinusMinutes(minutes)
	args := []any{}
	if phase != "" {
		stmt += " AND phase = ?"
		args = append(args, phase)
	}
	if site != "" {
		stmt += " AND site = ?"
		args = append(args, site)
	}
	if len(hosts) > 0 {
		placeholders := strings.Repeat("?,", len(hosts))
		placeholders = placeholders[:len(placeholders)-1]
		stmt += " AND host IN (" + placeholders + ")"
		for _, hh := range hosts {
			args = append(args, hh)
		}
	}
	row := h.DB.QueryRowContext(ctx, stmt, args...)
	var n int
	if err := row.Scan(&n); err != nil {
		log.Printf("countEvents (phase=%q): %v", phase, err)
		return 0
	}
	return n
}

// countEventsPhases: like countEvents but matches any of several phases
// (phase IN (...)).  Used for the "passed" KPIs, which span multiple terminal
// bv_* phases.  Best-effort (= on error, return 0 and just log).
func countEventsPhases(ctx context.Context, h *Handler, minutes int, phases []string, site string, hosts []string) int {
	if n, ok := dashboard.PhaseCount(ctx, h.DB, phases, site, hosts, minutes/60); ok {
		return n
	}
	stmt := `SELECT COUNT(*) FROM unmask_event WHERE date_created > ` + h.DB.NowMinusMinutes(minutes)
	args := []any{}
	if len(phases) > 0 {
		ph := strings.Repeat("?,", len(phases))
		stmt += " AND phase IN (" + ph[:len(ph)-1] + ")"
		for _, p := range phases {
			args = append(args, p)
		}
	}
	if site != "" {
		stmt += " AND site = ?"
		args = append(args, site)
	}
	if len(hosts) > 0 {
		ph := strings.Repeat("?,", len(hosts))
		stmt += " AND host IN (" + ph[:len(ph)-1] + ")"
		for _, hh := range hosts {
			args = append(args, hh)
		}
	}
	row := h.DB.QueryRowContext(ctx, stmt, args...)
	var n int
	if err := row.Scan(&n); err != nil {
		log.Printf("countEventsPhases (%v): %v", phases, err)
		return 0
	}
	return n
}

// parseHostFilter: normalize the URL "host" query values as a multi-select.
// Accepts both "host=a&host=b" and "host=a,b".  TrimSpace + drop empties.
func parseHostFilter(raws []string) []string {
	var out []string
	for _, raw := range raws {
		for _, part := range strings.Split(raw, ",") {
			if v := strings.TrimSpace(part); v != "" {
				out = append(out, v)
			}
		}
	}
	return out
}

// resolveHostFilter: resolve the global scope of the host filter.  Precedence:
//  1. unmask_hosts cookie (= written by the shared host_picker.  comma-separated.  empty = all hosts)
//  2. ?host= query param (= deep link.  Only when the cookie is unset)
//
// The host picker uses a cookie like the TZ / language pickers, so the
// selection is preserved across navigation (= one view scope shared by every admin page).
func resolveHostFilter(r *http.Request) []string {
	if c, err := r.Cookie("unmask_hosts"); err == nil {
		if v := decodeCookieValue(c.Value); strings.TrimSpace(v) != "" {
			return parseHostFilter([]string{v})
		}
	}
	return parseHostFilter(r.URL.Query()["host"])
}

// siteFilterRE: a site filter value is a hostname-ish token.  Validate at the
// source (defense in depth) so a hostile unmask_site cookie / ?site= can never
// reach a SQL sink even if one forgets siteCond (= the 2026-06 SQLi via three
// dashboard queries that hand-rolled `site = '<raw>'`).
var siteFilterRE = regexp.MustCompile(`^[a-z0-9.:_-]+$`)

func sanitizeSiteFilter(v string) string {
	v = strings.TrimSpace(v)
	if v == "" || !siteFilterRE.MatchString(v) {
		return ""
	}
	return v
}

// resolveSiteFilter: resolve the single-select site filter shared by every
// admin page.  Precedence mirrors resolveHostFilter: the unmask_site cookie
// (written by the site_picker), then the ?site= query param.  "" = all sites.
func resolveSiteFilter(r *http.Request) string {
	if c, err := r.Cookie("unmask_site"); err == nil {
		if v := sanitizeSiteFilter(decodeCookieValue(c.Value)); v != "" {
			return v
		}
	}
	return sanitizeSiteFilter(r.URL.Query().Get("site"))
}

// trafficUnique: unique-client figures over the last <minutes>, merged from
// the unmask_traffic_hll HLL sketches written by the nginx-log pipeline.
//
//	total   = distinct client IPs across all traffic
//	blocked = distinct IPs that were challenged but never seen carrying a
//	          pass cookie  (= est(ipc ∪ ipp) − est(ipp))
//
// The overview's non-human tile counts requests (dashboard.TrafficRequests);
// this stays for the hero's "from an estimated N distinct clients", which is
// the one place a distinct count is the thing being asked for.
//
//	known   = false when there is no sketch data at all (= the access-log
//	          feed is off, or the feature was just deployed) → caller shows "—"
//
// Best-effort: on a query error returns known=false.
func trafficUnique(ctx context.Context, h *Handler, minutes int, site string) (total, blocked int, known bool) {
	// Default (all-sites) view: read the install-wide rollups instead of scanning
	// every site's per-minute sketches (the ~8-12k-sketch fan-out).  A site-scoped
	// view has no fan-out, so it reads the per-minute table directly below.
	if site == "" {
		t, b, ok, err := dashboard.TrafficUniqueAgg(ctx, h.DB, minutes)
		if err != nil {
			log.Printf("trafficUnique agg: %v", err)
			return 0, 0, false
		}
		return t, b, ok
	}
	cutoff := time.Now().Unix()/60 - int64(minutes)
	stmt := `SELECT kind, sketch FROM unmask_traffic_hll WHERE bucket_min >= ?`
	args := []any{cutoff}
	if site != "" {
		stmt += " AND site = ?"
		args = append(args, site)
	}
	rows, err := h.DB.QueryContext(ctx, stmt, args...)
	if err != nil {
		log.Printf("trafficUnique: %v", err)
		return 0, 0, false
	}
	defer rows.Close()
	merged := map[string]*hll.Sketch{} // kind -> window-merged sketch
	for rows.Next() {
		var kind string
		var blob []byte
		if err := rows.Scan(&kind, &blob); err != nil {
			log.Printf("trafficUnique scan: %v", err)
			return 0, 0, false
		}
		s := merged[kind]
		if s == nil {
			s = &hll.Sketch{}
			merged[kind] = s
		}
		s.Merge(hll.Load(blob))
	}
	if err := rows.Err(); err != nil {
		log.Printf("trafficUnique rows: %v", err)
		return 0, 0, false
	}
	ipAll := merged["ip"]
	if ipAll == nil {
		return 0, 0, false // no sketch data
	}
	total = ipAll.Estimate()
	if ipChal := merged["ipc"]; ipChal != nil {
		// blocked = challenged minus those that ever passed.  HLL has no
		// subtraction, so est(ipc \ ipp) = est(ipc ∪ ipp) − est(ipp).
		union := &hll.Sketch{}
		union.Merge(ipChal)
		passEst := 0
		if ipPass := merged["ipp"]; ipPass != nil {
			union.Merge(ipPass)
			passEst = ipPass.Estimate()
		}
		blocked = union.Estimate() - passEst
		if blocked < 0 {
			blocked = 0
		}
	}
	return total, blocked, true
}

// Traffic-composition denominator, persisted per operator.
//
//	compScopeAll    — every request the access log saw (the default: it is the
//	                  figure the card has always shown, and changing what a
//	                  daily number means without being asked is its own bug)
//	compScopeJudged — minus the requests a bypass rule exempted, i.e. the
//	                  traffic unmask actually evaluated
const (
	compScopeAll      = "all"
	compScopeJudged   = "judged"
	compSegCookieName = "unmask_comp_seg"
	compSegBenign     = "benign"
	compSegBad        = "bad"
	compSegBypass     = "bypass"
	compSegHuman      = "human"
	compSegOther      = "other"
)

// compSegDef: one legend segment as the state model sees it -- its canonical
// key, its request count, and whether it sits on the non-human side of the
// headline figure.
type compSegDef struct {
	key      string
	count    int
	nonHuman bool
}

// compSegOrder is the canonical rendering and serialisation order.
var compSegOrder = []string{compSegBenign, compSegBad, compSegBypass, compSegHuman, compSegOther}

// compSegsParam names an enabled-set: the two presets keep their historical
// names ("all", "judged") so bookmarks and the preset links stay readable, and
// anything else serialises as the enabled keys in canonical order.  Empty set
// -> "" (the caller treats that as "not a state").
func compSegsParam(on map[string]bool) string {
	n := 0
	for _, k := range compSegOrder {
		if on[k] {
			n++
		}
	}
	if n == 0 {
		return ""
	}
	if n == len(compSegOrder) {
		return compScopeAll
	}
	if n == len(compSegOrder)-1 && !on[compSegBypass] {
		return compScopeJudged
	}
	// Joined with "-": unreserved in URLs, so the ?comp= link and the cookie
	// carry the state name literally instead of as %2c soup.
	out := ""
	for _, k := range compSegOrder {
		if on[k] {
			if out != "" {
				out += "-"
			}
			out += k
		}
	}
	return out
}

// parseCompSegs reads a state name back.  Unknown tokens are dropped rather
// than erroring -- this selects a view, and a malformed value is not worth a
// broken page; a value with nothing recognisable in it reports !ok so the
// caller can fall back to the default.
func parseCompSegs(v string) (map[string]bool, bool) {
	on := make(map[string]bool, len(compSegOrder))
	switch v {
	case compScopeAll:
		for _, k := range compSegOrder {
			on[k] = true
		}
		return on, true
	case compScopeJudged:
		for _, k := range compSegOrder {
			on[k] = k != compSegBypass
		}
		return on, true
	}
	valid := map[string]bool{}
	for _, k := range compSegOrder {
		valid[k] = true
	}
	any := false
	for _, tok := range strings.FieldsFunc(v, func(r rune) bool { return r == '-' || r == ',' }) {
		tok = strings.TrimSpace(tok)
		if valid[tok] {
			on[tok] = true
			any = true
		}
	}
	return on, any
}

// resolveCompSegs reads the operator's saved segment selection.  The query
// parameter is how the toggle links switch; the cookie is what makes the
// choice stick.  Query wins so a link works on the first click, before the
// cookie it sets has been read back.
func resolveCompSegs(r *http.Request) map[string]bool {
	if r != nil {
		if on, ok := parseCompSegs(r.URL.Query().Get("comp")); ok {
			return on
		}
		if c, err := r.Cookie(compSegCookieName); err == nil && c != nil {
			if on, ok := parseCompSegs(decodeCookieValue(c.Value)); ok {
				return on
			}
		}
	}
	on, _ := parseCompSegs(compScopeAll)
	return on
}
