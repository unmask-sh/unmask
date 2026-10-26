package handlers

import (
	"time"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/events"
)

// statsCards is what the stats page's cards return (renderStats).  Each
// card runs on its own goroutine and hands its result to run, which writes
// it here under the cards' lock; the page renders from a copy taken under
// that lock once the wait is over.  The wait may be cut short by the
// overall deadline with cards still running, and a card that returns after
// it then writes here, to a struct nobody reads any more -- not into a
// slice the template is walking.
type statsCards struct {
	funnel                  []dashboard.FunnelRow
	funnelErr               error
	cookieRows              []dashboard.CookieStatusRow
	rlSummary               dashboard.RLSummary
	rlIPs                   []dashboard.RLIPRow
	rlPaths                 []dashboard.RLPathRow
	rlPathQueries           map[string][]dashboard.RLQueryCount
	flagsRows               []dashboard.FlagsRow
	verdictDist             []dashboard.VerdictCount
	hitRows                 []dashboard.CaptchaForceRow
	hitRules                []dashboard.CaptchaForceRuleRow
	loopRows                []dashboard.ReloadLoopRow
	verifyNG                []dashboard.VerifyNGRow
	cookieFails             []dashboard.CookieFailRow
	stealth                 []dashboard.StealthRow
	jsErrs                  []dashboard.JSErrorRow
	jsForeign               []dashboard.JSErrorRow
	jsForeignCount          int
	cpVerdictCounts         map[string]int
	cpForceReasonCounts     map[string]int
	cpFailForceReasonCounts map[string]int
	cpTopIPs                []dashboard.CaptchaPassIPRow
	cpRecent                []dashboard.CaptchaPassRow
	cpReuse                 []dashboard.CookieReuseRow
	powReuse                []dashboard.CookieReuseRow
	rebindReuse             []dashboard.CookieReuseRow
	rebindLineages          []events.RebindLineageRow
	aiTraffic               []dashboard.AITrafficRow
	aiTrafficAll            []AITrafficRow
	aiTrafficDetail         map[string][]AICrawlerRow
	dailyKind               []dashboard.DailyKindBucket
	dailyTotal              []dashboard.DailyTotal
	dailyServeKind          []dashboard.DailyKindBucket
	dailyServeTotal         []dashboard.DailyTotal
	dailyBlocked            []dashboard.DailyBlockedDay
	countries               []dashboard.CountryRow
	dailyCountry            []dashboard.DailyCountryBucket
	dailyUniq               []dashboard.DailyUniq
}

// statsOverallTimeout bounds the stats page's wait for its cards.  A card
// past it is left to finish on its own and the page renders without it.  A
// variable so a test can shorten it.
var statsOverallTimeout = 30 * time.Second

// statsCardHook, when set, is called with a card's name before its query
// runs: a test's way of making one card slow.  nil in the daemon.
var statsCardHook func(name string)
