// Package advisor extracts BAN candidates from the recent event window.
//
// Phase 1 of doc (private) DESIGN-ai-advisor.md: a DETERMINISTIC engine — no
// LLM anywhere — that codifies the checks an operator (or their assistant)
// runs by hand over the hunt log: who hammers challenges without ever running
// the JavaScript, who rakes scanner paths, which fingerprint fans out over
// many addresses, and whether the source is a hosting network wearing a
// browser User-Agent.
//
// Everything here is advisory.  The engine proposes; a human applies a ban
// through the ordinary /admin/bans/save path (or dismisses the row).  Nothing
// in this package writes.
package advisor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Signal is one reason a target became a candidate.  IDs are stable
// machine-readable names (the UI translates them; a future LLM layer and the
// MCP surface can reference them verbatim).
type Signal struct {
	ID     string `json:"id"`
	Detail string `json:"detail"` // English, for the model bundle and the digest
	Weight int    `json:"weight"`
	// A, B, C, S: the detail's parameters, so the page can render it in the
	// operator's language (advisor.sig.<id> in i18n).
	A int    `json:"a,omitempty"`
	B int    `json:"b,omitempty"`
	C int    `json:"c,omitempty"`
	S string `json:"s,omitempty"`
}

// Candidate is one proposed ban target with the evidence that produced it.
type Candidate struct {
	Type         string   `json:"type"`   // "ip" | "ja4"
	Target       string   `json:"target"` // the address or the fingerprint
	Scope        string   `json:"scope"`  // suggested ban scope (ip_only / ja4_only)
	JA4          string   `json:"ja4,omitempty"`
	UA           string   `json:"ua,omitempty"`
	Signals      []Signal `json:"signals"`
	Score        int      `json:"score"`
	Requests     int      `json:"requests"`
	Serves       int      `json:"serves"`                 // challenge pages served
	Loads        int      `json:"js_loaded"`              // the challenge JavaScript ran
	PowPassed    int      `json:"pow_passed"`             // proof-of-work solved (multi-step chain)
	CaptchaShown int      `json:"captcha_shown"`          // behavioural CAPTCHA reached
	Passes       int      `json:"passes"`                 // completed: a pass cookie was issued
	PassPow      int      `json:"pass_pow,omitempty"`     // ... by solving the proof-of-work alone (bv_pow_only)
	PassCaptcha  int      `json:"pass_captcha,omitempty"` // ... by the CAPTCHA alone (bv_captcha_only)
	PassBoth     int      `json:"pass_both,omitempty"`    // ... proof-of-work then CAPTCHA (bv_pow_then_captcha)
	// How often each chain was presented -- the load beacon's chmode, the
	// chain the challenge JavaScript ran with.  A pass is a chain completed
	// (PassPow / PassCaptcha / PassBoth); presented minus passed is the
	// chain holding.
	ShownPow     int      `json:"shown_pow_only,omitempty"`
	ShownCaptcha int      `json:"shown_captcha_only,omitempty"`
	ShownBoth    int      `json:"shown_pow_then_captcha,omitempty"`
	ScannerHits  int      `json:"scanner_hits,omitempty"`
	DistinctIPs  int      `json:"distinct_ips,omitempty"`
	FirstSeen    string   `json:"first_seen"` // "2006-01-02 15:04" UTC (trimmed for the model and as the no-JS fallback)
	LastSeen     string   `json:"last_seen"`
	FirstTs      int64    `json:"first_ts,omitempty"` // unix seconds; the page formats them in the operator's tz
	LastTs       int64    `json:"last_ts,omitempty"`
	ASN          uint     `json:"asn,omitempty"`
	ASNOrg       string   `json:"asn_org,omitempty"`
	Country      string   `json:"country,omitempty"`
	RDNS         string   `json:"rdns,omitempty"`
	SamplePaths  []string `json:"sample_paths,omitempty"`
	// Contained: the client never completed a challenge.  The challenge is
	// already doing its job; a ban buys the daemon fewer round trips and the
	// log less noise, not more protection.  What deserves attention is the
	// opposite -- an actor that passes.
	Contained bool `json:"contained"`
	Dismissed bool `json:"dismissed,omitempty"` // shown only under the "show dismissed" filter
	// For fingerprint candidates, filled in before the model sees them: the
	// collateral of a ban (see JA4Collateral).
	PassIPs7d int    `json:"pass_ips_7d,omitempty"`
	Verdict   string `json:"ja4_verdict,omitempty"`
	// Nominated: proposed by the model from the wider pool rather than by a
	// signal (page only; the scheduled pass never asks the model).
	Nominated bool `json:"nominated,omitempty"`
}

// AttentionScore is the score from which a candidate is shown by default and
// sent to the model.  Below it sits one lone signal -- a three-hit scanner
// probe, a thirty-serve hammerer -- real, rarely worth a ban, and hidden
// behind the page's "show all" until its volume or a second signal lifts it;
// and, whatever its signals, a contained client short of the cost floor
// (settleScore).
const AttentionScore = 5

// Volume thresholds for the high_volume signal: from here the traffic itself
// is a cost, whatever the client is.  For a contained client -- one the
// challenge already answers, for the price of a small page per request --
// the signal fires ten times later, at the thousands of requests a window
// where the handling alone is a cost.  Operator's calibration (2026-09-09):
// "0 passes is effectively blocked; short of thousands of requests the load
// is nothing to notice".
const (
	VolumeServes            = 300
	VolumeRequests          = 1000
	ContainedVolumeServes   = VolumeServes * 10
	ContainedVolumeRequests = VolumeRequests * 10
)

// SortByAttention orders rows the way the page reads them: passing before
// contained -- the one distinction that decides whether a ban buys
// protection or merely quiet -- then the score, then volume.  The page
// applies it again after merging the model's picks in, so a pick sits where
// its score puts it rather than at the end.
func SortByAttention(out []Candidate) {
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Contained != b.Contained {
			return !a.Contained
		}
		if a.Score != b.Score {
			return a.Score > b.Score
		}
		return a.Serves+a.Requests > b.Serves+b.Requests
	})
}

// candidateFloor is the score from which a shape is listed at all (under
// "show all"): one weighty signal.  A hosting-network address that neither
// hammers nor scans is just a server, not a candidate on its own.
//
// containedCostScore is what a contained client scores once its volume is
// past the cost floor: two signals' worth -- the shape and the volume -- so
// it clears the default view and the default digest floor alike.
const (
	candidateFloor     = 3
	containedCostScore = 6
)

// Attention: shown by default and sent to the model -- scored at or above
// AttentionScore, or nominated by the model itself.
func (c Candidate) Attention() bool {
	return c.Nominated || c.Score >= AttentionScore
}

// Fingerprint names the evidence a review is written for: the window's
// counts, the signals, the score, the first / last seen.  While it holds, a
// stored review is still about what the operator is looking at and a rerun
// keeps it; any change (new events, an aged-out window, a signal gained or
// lost) sends the candidate again.
func (c Candidate) Fingerprint() string {
	ids := make([]string, 0, len(c.Signals))
	for _, s := range c.Signals {
		ids = append(ids, s.ID)
	}
	return fmt.Sprintf("%s|%s|s%d|%s|%d/%d/%d/%d/%d/%d|%d/%d/%d|%d|%s..%s",
		c.Type, c.Target, c.Score, strings.Join(ids, ","),
		c.Requests, c.Serves, c.Loads, c.PowPassed, c.CaptchaShown, c.Passes,
		c.ShownPow, c.ShownCaptcha, c.ShownBoth, c.ScannerHits,
		c.FirstSeen, c.LastSeen)
}

// HeldAtCaptcha: the client got past the proof-of-work (or reached the
// CAPTCHA directly) and never completed it.  Contained, and worth saying so:
// the second gate is what stopped it.
func (c Candidate) HeldAtCaptcha() bool {
	return c.Passes == 0 && (c.PowPassed > 0 || c.CaptchaShown > 0)
}

// The traffic cell reads the challenge by chain -- the unit the operator
// configures -- each as presented → passed · not completed, so every line
// closes (presented = passed + not completed) and the chains' passes add up
// to the row's pass count (operator's design, 2026-09-13: "pow or captcha
// 提示数と通過、不突破を表示", per chain, the two gates of pow_then_captcha
// each).  Presented is the load beacon's chmode: how often the challenge
// JavaScript ran with that chain.  A client that never ran the JavaScript
// is in JSNotRun only.  Every figure is an event count, and every
// difference is floored at zero: on a load-balanced fleet the page and its
// beacons can land on different nodes.

// JSNotRun: challenge pages served whose JavaScript never ran -- a client
// that fetched the page and left (no JS, cookies refused, HEAD, a scraper).
// Operator (2026-09-13): "JS は何も実行出来ず去った人が算出出来る".
func (c Candidate) JSNotRun() int { return floor0(c.Serves - c.Loads) }

// PowOnlyHeld: pow_only presented and not completed.
func (c Candidate) PowOnlyHeld() int { return floor0(c.ShownPow - c.PassPow) }

// CaptchaOnlyHeld: captcha_only presented and not completed.
func (c Candidate) CaptchaOnlyHeld() int { return floor0(c.ShownCaptcha - c.PassCaptcha) }

// ChainPowPassed: the pow_then_captcha chain's first gate cleared -- its
// pow_pass events.  PowPassed counts every solve (pow_pass + bv_pow_only)
// and PassPow the pow_only passes, so the difference is the chain's own.
func (c Candidate) ChainPowPassed() int { return floor0(c.PowPassed - c.PassPow) }

// ChainPowHeld: pow_then_captcha presented and stopped at the proof-of-work.
func (c Candidate) ChainPowHeld() int { return floor0(c.ShownBoth - c.ChainPowPassed()) }

// ChainCaptchaHeld: got past the chain's proof-of-work and stopped at its
// CAPTCHA -- each pow_pass shows the CAPTCHA, PassBoth completed it.
func (c Candidate) ChainCaptchaHeld() int { return floor0(c.ChainPowPassed() - c.PassBoth) }

// HasPowOnly / HasCaptchaOnly / HasChain: the chain was presented or
// completed in the window, so its line is on the row.  (Completed without
// a presentation is the load-balanced fleet: another node served the
// page.)
func (c Candidate) HasPowOnly() bool     { return c.ShownPow > 0 || c.PassPow > 0 }
func (c Candidate) HasCaptchaOnly() bool { return c.ShownCaptcha > 0 || c.PassCaptcha > 0 }
func (c Candidate) HasChain() bool {
	return c.ShownBoth > 0 || c.PassBoth > 0 || c.ChainPowPassed() > 0
}

func floor0(n int) int {
	if n > 0 {
		return n
	}
	return 0
}

// volumeIsCost: the traffic itself is worth acting on.  A passing client at
// a few hundred challenges a window; a contained one at ten times that.
func (c Candidate) volumeIsCost() bool {
	serves, requests := VolumeServes, VolumeRequests
	if c.Contained {
		serves, requests = ContainedVolumeServes, ContainedVolumeRequests
	}
	return c.Serves >= serves || c.Requests >= requests
}

// ContainedBelowCost: never passed, and short of the volume at which the
// handling alone is a cost.  The challenge already answers such a client;
// the engine lists it at candidateFloor, under every passing row and out of
// the default view (settleScore), and a nomination from the pool may not
// lift it back in (mergeResult, Merge, the advisor page) -- the pool is
// ranked by volume, so a herd that is served the page a thousand times and
// never passes is exactly what stands out there.  Operator's ask
// (2026-09-10): "AI picks keep surfacing zero-pass actors; few passes means
// not important".
func ContainedBelowCost(passes, serves, requests int) bool {
	return passes == 0 && serves < ContainedVolumeServes && requests < ContainedVolumeRequests
}

// ContainedBelowCost on a row: the same test on the row's own counts.
func (c Candidate) ContainedBelowCost() bool {
	return ContainedBelowCost(c.Passes, c.Serves, c.Requests)
}

// settleScore turns the signals into the score.  A passing client scores the
// sum of its evidence.  A contained one -- never passed, the challenge
// already stopping it -- scores what a ban would buy instead: its shape
// signals (hammering, scanner paths, a hosting network) keep it on the list
// and go no further than candidateFloor however many there are, and only
// volume past the cost floor lifts it, to containedCostScore.  So a contained
// row scores 3 or 6 once listed, sorts under every passing row, and stays out
// of the default view, the model's bundle and the digest until it is
// thousands of requests a window.  Operator's ask (2026-09-09): "0 passes is
// effectively blocked -- lower its priority".
func (c *Candidate) settleScore() {
	sum := 0
	for _, s := range c.Signals {
		sum += s.Weight
	}
	switch {
	case !c.Contained:
		c.Score = sum
	case c.volumeIsCost():
		c.Score = containedCostScore
	case sum > candidateFloor:
		c.Score = candidateFloor
	default:
		c.Score = sum
	}
}

// Options tunes the extraction.  Zero values resolve to the defaults below —
// deliberately conservative: a candidate list that cries wolf gets ignored,
// and the operator can always widen the window.
type Options struct {
	WindowMinutes int // default 24h
	MinServes     int // default 30: challenge serves before an IP is "hammering"
	MinScanner    int // default 3: distinct-ish scanner-path hits
	MinPasses     int // default 5: passes before a hosting-network client is "getting through"
	HerdMinIPs    int // default 10: distinct IPs behind one JA4
	Limit         int // default 20 candidates
}

func (o Options) resolved() Options {
	if o.WindowMinutes <= 0 {
		o.WindowMinutes = 24 * 60
	}
	if o.MinServes <= 0 {
		o.MinServes = 30
	}
	if o.MinScanner <= 0 {
		o.MinScanner = 3
	}
	if o.MinPasses <= 0 {
		o.MinPasses = 5
	}
	if o.HerdMinIPs <= 0 {
		o.HerdMinIPs = 10
	}
	if o.Limit <= 0 {
		o.Limit = 20
	}
	return o
}

// Phase groups.  A challenge flow runs serve -> load -> (pow_pass ->)
// (captcha ->) bv_*.  Counting every JS-side phase as a "pass" made one visit
// look like three and hid the case that matters: proof-of-work solved, CAPTCHA
// not.  Only a bv_* row means the client got through.
const (
	// loadPhaseList: the challenge JavaScript ran at all.
	loadPhaseList = "('load')"
	// powPhaseList: the proof-of-work solved.  pow_pass is the intermediate
	// step of a multi-step chain; in a proof-of-work-only chain the solve IS
	// the pass (bv_pow_only), and counts here too -- or a client that clears
	// pow_only five times would read as "PoW 0".
	powPhaseList = "('pow_pass','bv_pow_only')"
	// captchaPhaseList: the behavioural CAPTCHA was shown.
	captchaPhaseList = "('captcha')"
	// cookiePhaseList: the challenge completed and a pass cookie issued -- the
	// only phases that mean the client got through.
	cookiePhaseList = "('bv_pow_only','bv_captcha_only','bv_pow_then_captcha')"
)

// scannerLikes match request paths inside payload_json.  LIKE over the JSON
// text is deliberate: it is portable across sqlite/mariadb and a false
// positive merely surfaces a row for a human to glance at.
var scannerLikes = []string{
	"%.env%", "%wp-config%", "%wp-login%", "%xmlrpc.php%", "%.git/%",
	"%.aws/%", "%cgi-bin%", "%/etc/passwd%", "%phpmyadmin%", "%.php.save%",
	"%/actuator%", "%/.ssh/%",
}

// Exclusions carries the targets the engine must never propose: already
// banned, operator-dismissed, or infrastructure the install itself trusts.
type Exclusions struct {
	BannedIPs    map[string]bool
	BannedJA4s   map[string]bool
	DismissedIP  map[string]bool
	DismissedJA4 map[string]bool
	ExcludeIPs   map[string]bool // stats_exclude_ips: own monitoring etc.
}

// scannerCond matches a challenged request for a scanner-signature path.
// Only serve rows: the requested path rides along on the JS-side phases too
// (load, bv_*), which double-counted one probe, and the LIKE chain is the
// expensive part of the pass -- on serve rows it runs over a third of the
// window instead of all of it.
func scannerCond() string {
	parts := make([]string, len(scannerLikes))
	for i, l := range scannerLikes {
		parts[i] = "payload_json LIKE '" + l + "'"
	}
	return "(phase='serve' AND (" + strings.Join(parts, " OR ") + "))"
}

// Candidates runs the extraction.  gip may be nil (origin columns stay empty).
func Candidates(ctx context.Context, conn *db.DB, gip *ipgeo.Reader, excl Exclusions, opt Options) ([]Candidate, error) {
	opt = opt.resolved()
	var out []Candidate

	// The two passes read the same window independently; run them side by
	// side (SQLite in WAL mode serves concurrent readers) so the page waits
	// for the slower one, not the sum.
	var ipCands, ja4Cands []Candidate
	var ipErr, ja4Err error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		ipCands, ipErr = ipCandidates(ctx, conn, gip, excl, opt)
	}()
	go func() {
		defer wg.Done()
		ja4Cands, ja4Err = ja4Candidates(ctx, conn, excl, opt)
	}()
	wg.Wait()
	if ipErr != nil {
		return nil, fmt.Errorf("ip pass: %w", ipErr)
	}
	if ja4Err != nil {
		return nil, fmt.Errorf("ja4 pass: %w", ja4Err)
	}
	out = append(out, ipCands...)
	out = append(out, ja4Cands...)

	SortByAttention(out)
	if len(out) > opt.Limit {
		out = out[:opt.Limit]
	}
	if err := fillSamplePaths(ctx, conn, out, opt); err != nil {
		// Samples are garnish; the candidates stand without them.
		return out, nil
	}
	return out, nil
}

func ipCandidates(ctx context.Context, conn *db.DB, gip *ipgeo.Reader, excl Exclusions, opt Options) ([]Candidate, error) {
	// ja4 / user_agent / payload_json are nullable (a forward-auth check writes
	// no user agent, an old row no payload); MAX over an all-NULL group is NULL
	// and Scan into a string rejects it -- seen live on 2026-09-04.  COALESCE
	// keeps the scan simple and is portable across both drivers.
	// HAVING repeats the aggregate expressions instead of the aliases: sqlite
	// accepts aliases there, MariaDB in some modes does not.
	q := `SELECT ip_address,
	        COUNT(*) AS total,
	        SUM(CASE WHEN phase='serve' THEN 1 ELSE 0 END) AS serves,
	        SUM(CASE WHEN phase IN ` + loadPhaseList + ` THEN 1 ELSE 0 END) AS loads,
	        SUM(CASE WHEN phase IN ` + powPhaseList + ` THEN 1 ELSE 0 END) AS pow_passed,
	        SUM(CASE WHEN phase IN ` + captchaPhaseList + ` THEN 1 ELSE 0 END) AS captcha_shown,
	        SUM(CASE WHEN phase IN ` + cookiePhaseList + ` THEN 1 ELSE 0 END) AS passes,
	        SUM(CASE WHEN phase='bv_pow_only' THEN 1 ELSE 0 END) AS pass_pow,
	        SUM(CASE WHEN phase='bv_captcha_only' THEN 1 ELSE 0 END) AS pass_captcha,
	        SUM(CASE WHEN phase='bv_pow_then_captcha' THEN 1 ELSE 0 END) AS pass_both,
	        ` + poolChainShownSums(conn) + `
	        SUM(CASE WHEN ` + scannerCond() + ` THEN 1 ELSE 0 END) AS scanner_hits,
	        MIN(date_created), MAX(date_created),
	        COALESCE(MAX(ja4), ''), COALESCE(MAX(user_agent), '')
	      FROM unmask_event` + conn.EventDateIndexHint("w") + `
	      WHERE date_created > ` + conn.NowMinusMinutes(opt.WindowMinutes) + `
	      GROUP BY ip_address
	      HAVING SUM(CASE WHEN phase='serve' THEN 1 ELSE 0 END) >= ?
	          OR SUM(CASE WHEN ` + scannerCond() + ` THEN 1 ELSE 0 END) >= ?
	          OR SUM(CASE WHEN phase IN ` + cookiePhaseList + ` THEN 1 ELSE 0 END) >= ?
	      ORDER BY serves DESC
	      LIMIT 200`
	rows, err := conn.QueryContext(ctx, q, opt.MinServes, opt.MinScanner, opt.MinPasses)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Candidate
	for rows.Next() {
		var c Candidate
		var ipBytes []byte
		var first, last, ja4, ua string
		if err := rows.Scan(&ipBytes, &c.Requests, &c.Serves, &c.Loads, &c.PowPassed, &c.CaptchaShown, &c.Passes, &c.PassPow, &c.PassCaptcha, &c.PassBoth,
			&c.ShownPow, &c.ShownCaptcha, &c.ShownBoth, &c.ScannerHits, &first, &last, &ja4, &ua); err != nil {
			return nil, err
		}
		ip := unpackIP(ipBytes)
		if skipIP(ip, excl) {
			continue
		}
		c.Type, c.Target, c.Scope = "ip", ip, "ip_only"
		c.JA4, c.UA = ja4, ua
		c.FirstSeen, c.FirstTs = dbTime(first)
		c.LastSeen, c.LastTs = dbTime(last)
		c.Contained = c.Passes == 0
		if gip != nil {
			info := gip.LookupInfo(ip)
			c.ASN, c.ASNOrg, c.Country = info.ASN, info.ASNOrg, info.Country
		}
		c.addressSignals(opt)
		c.settleScore()
		if c.Score >= candidateFloor {
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

// addressSignals appends the engine's signals for an address to what the row
// carries.  The same rules score an engine candidate and a model nomination
// (buildPick), so a pick's score means what a candidate's does.
func (c *Candidate) addressSignals(opt Options) {
	if c.Serves >= opt.MinServes && c.Loads+c.PowPassed+c.CaptchaShown+c.Passes == 0 {
		c.Signals = append(c.Signals, Signal{
			ID: "challenge_hammering", Weight: 3, A: c.Serves,
			Detail: fmt.Sprintf("%d challenges served, JS never executed", c.Serves),
		})
	}
	// Got past the proof-of-work (or straight to the CAPTCHA) and never
	// completed it: automation good enough for the first gate, stopped at
	// the second.  Informational (weight 1) -- the defence is working, and
	// the row says so.
	if c.HeldAtCaptcha() {
		c.Signals = append(c.Signals, Signal{
			ID: "captcha_held", Weight: 1, A: c.PowPassed, B: c.CaptchaShown,
			Detail: fmt.Sprintf("solved the proof-of-work %d times and reached the CAPTCHA %d times, never completed it", c.PowPassed, c.CaptchaShown),
		})
	}
	if c.ScannerHits >= opt.MinScanner {
		c.Signals = append(c.Signals, Signal{
			ID: "scanner_paths", Weight: 3, A: c.ScannerHits,
			Detail: fmt.Sprintf("%d requests for scanner-signature paths", c.ScannerHits),
		})
	}
	// Volume: what separates the hammerer worth a ban from the one that
	// is merely there.  A few dozen serves are not worth the operator's
	// click; a few hundred are load on their own -- a few thousand, for
	// a client the challenge already contains (volumeIsCost).
	if c.volumeIsCost() {
		c.Signals = append(c.Signals, Signal{
			ID: "high_volume", Weight: 2, A: c.Requests, B: c.Serves,
			Detail: fmt.Sprintf("%d requests, %d challenges served -- the volume itself is a cost", c.Requests, c.Serves),
		})
	}
	if hp := hostingMatch(c.ASNOrg); hp != "" {
		w := 1
		detail := "address in a hosting network (" + hp + ")"
		id := "hosting_network"
		if strings.HasPrefix(c.UA, "Mozilla/") {
			w = 2
			detail += " wearing a browser User-Agent"
			id = "hosting_network_browser"
		}
		c.Signals = append(c.Signals, Signal{ID: id, Weight: w, S: hp, Detail: detail})
		// The shape that gets THROUGH: a server farm running a real
		// browser engine completes the challenge like a person would.
		// This is the one signal about an actor the challenge is not
		// stopping, so it outweighs every "contained" signal.
		if c.Passes >= opt.MinPasses && strings.HasPrefix(c.UA, "Mozilla/") {
			c.Signals = append(c.Signals, Signal{
				ID: "passing_hosting", Weight: 4, A: c.Passes, S: hp,
				Detail: fmt.Sprintf("%d challenges passed from a hosting network (%s) with a browser User-Agent", c.Passes, hp),
			})
		}
	}
}

// fingerprintSignals appends the engine's signals for a fingerprint: the
// herd (one fingerprint across many addresses that essentially never
// passes) and the volume.  Same rules for a candidate and a nomination.
func (c *Candidate) fingerprintSignals(opt Options) {
	if c.DistinctIPs >= opt.HerdMinIPs && c.Serves >= opt.MinServes && c.Passes*20 <= c.Serves {
		c.Signals = append(c.Signals, Signal{
			ID: "ja4_herd", Weight: 3, A: c.DistinctIPs, B: c.Serves, C: c.Passes,
			Detail: fmt.Sprintf("one fingerprint across %d addresses, %d serves, %d passes", c.DistinctIPs, c.Serves, c.Passes),
		})
	}
	if c.volumeIsCost() {
		c.Signals = append(c.Signals, Signal{
			ID: "high_volume", Weight: 2, A: c.Requests, B: c.Serves,
			Detail: fmt.Sprintf("%d requests, %d challenges served -- the volume itself is a cost", c.Requests, c.Serves),
		})
	}
}

func ja4Candidates(ctx context.Context, conn *db.DB, excl Exclusions, opt Options) ([]Candidate, error) {
	// The stages and the pass kinds too (poolStageSums / poolPassKindSums):
	// a fingerprint row read "JS 0 · PoW 0 · CAPTCHA 0" under a real pass
	// count until 2026-09-13, because only the address query carried them.
	q := `SELECT ja4,
	        COUNT(DISTINCT ip_address) AS ips,
	        COUNT(*) AS total,
	        SUM(CASE WHEN phase='serve' THEN 1 ELSE 0 END) AS serves,
	        ` + poolStageSums + `
	        ` + poolPassKindSums + `
	        ` + poolChainShownSums(conn) + `
	        MIN(date_created), MAX(date_created), COALESCE(MAX(user_agent), '')
	      FROM unmask_event` + conn.EventDateIndexHint("w") + `
	      WHERE date_created > ` + conn.NowMinusMinutes(opt.WindowMinutes) + `
	        AND ja4 <> ''
	      GROUP BY ja4
	      HAVING COUNT(DISTINCT ip_address) >= ?
	      ORDER BY ips DESC
	      LIMIT 50`
	rows, err := conn.QueryContext(ctx, q, opt.HerdMinIPs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Candidate
	for rows.Next() {
		var c Candidate
		var ja4, first, last, ua string
		if err := rows.Scan(&ja4, &c.DistinctIPs, &c.Requests, &c.Serves, &c.Loads, &c.PowPassed, &c.CaptchaShown, &c.Passes,
			&c.PassPow, &c.PassCaptcha, &c.PassBoth, &c.ShownPow, &c.ShownCaptcha, &c.ShownBoth, &first, &last, &ua); err != nil {
			return nil, err
		}
		if excl.BannedJA4s[ja4] || excl.DismissedJA4[ja4] {
			continue
		}
		// Fingerprints are SHARED by every client on the same TLS stack: a
		// popular browser JA4 fans out over thousands of addresses and passes
		// constantly.  Only a herd that essentially never passes is a
		// candidate — and even then the suggested action goes through a human
		// (the noalpn/SWG false positive taught that a strange fingerprint
		// plus a browser UA can be a corporate proxy full of real people).
		if c.Passes*20 > c.Serves || c.Serves < opt.MinServes {
			continue
		}
		c.Type, c.Target, c.Scope = "ja4", ja4, "ja4_only"
		c.UA = ua
		c.FirstSeen, c.FirstTs = dbTime(first)
		c.LastSeen, c.LastTs = dbTime(last)
		c.Contained = c.Passes == 0
		c.fingerprintSignals(opt)
		c.settleScore()
		out = append(out, c)
	}
	return out, rows.Err()
}

// fillSamplePaths decorates the top candidates with a few concrete request
// paths pulled out of payload_json — the reviewer's "what were they after".
func fillSamplePaths(ctx context.Context, conn *db.DB, cands []Candidate, opt Options) error {
	var ips []string
	for _, c := range cands {
		if c.Type == "ip" {
			ips = append(ips, c.Target)
		}
	}
	if len(ips) == 0 {
		return nil
	}
	var args []any
	for _, ip := range ips {
		if p := events.PackIP(ip); p != nil {
			args = append(args, p)
		}
	}
	if len(args) == 0 {
		return nil
	}
	ph := strings.TrimRight(strings.Repeat("?,", len(args)), ",")
	q := `SELECT ip_address, COALESCE(payload_json, '') FROM unmask_event` + conn.EventDateIndexHint("w") + `
	      WHERE date_created > ` + conn.NowMinusMinutes(opt.WindowMinutes) + `
	        AND ip_address IN (` + ph + `)
	      ORDER BY id DESC LIMIT 400`
	rows, err := conn.QueryContext(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	paths := map[string][]string{}
	for rows.Next() {
		var ipBytes []byte
		var payload string
		if err := rows.Scan(&ipBytes, &payload); err != nil {
			return err
		}
		ip := unpackIP(ipBytes)
		var p struct {
			// The module writes the requested path as orig_path (the serve
			// payload's "what was asked for"); path is the older / test shape.
			OrigPath string `json:"orig_path"`
			Path     string `json:"path"`
		}
		if json.Unmarshal([]byte(payload), &p) != nil {
			continue
		}
		if p.Path == "" {
			p.Path = p.OrigPath
		}
		if p.Path == "" {
			continue
		}
		if len(paths[ip]) >= 3 || contains(paths[ip], p.Path) {
			continue
		}
		paths[ip] = append(paths[ip], p.Path)
	}
	for i := range cands {
		if cands[i].Type == "ip" {
			cands[i].SamplePaths = paths[cands[i].Target]
		}
	}
	return rows.Err()
}

func skipIP(ip string, excl Exclusions) bool {
	if excl.BannedIPs[ip] || excl.DismissedIP[ip] || excl.ExcludeIPs[ip] {
		return true
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true
	}
	return parsed.IsPrivate() || parsed.IsLoopback() || parsed.IsLinkLocalUnicast()
}

// hostingMatch returns the catalog label when the ASN organisation belongs to
// a known hosting / cloud provider (the only axis that held against the
// CAPTCHA-solving JS crawlers).
func hostingMatch(asnOrg string) string {
	if asnOrg == "" {
		return ""
	}
	for _, hp := range settings.HostingProviders {
		if settings.OrgMatchesAny(asnOrg, hp.OrgPatterns) {
			return hp.Label
		}
	}
	return ""
}

// unpackIP renders the packed binary ip_address column (4 or 16 bytes) the
// way the events package does.
func unpackIP(b []byte) string {
	ip := net.IP(b)
	if ip == nil {
		return ""
	}
	if v4 := ip.To4(); v4 != nil {
		return v4.String()
	}
	if len(b) == 16 {
		return ip.To16().String()
	}
	return ""
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// dbTime turns a date_created value as the driver hands it back (SQLite text
// with or without fractional seconds, MariaDB DATETIME as text) into the
// trimmed "2006-01-02 15:04" UTC string the page falls back to and the unix
// seconds the page formats in the operator's timezone.  Unparseable input is
// passed through with ts 0 (the page then shows the raw value).
func dbTime(raw string) (string, int64) {
	raw = strings.TrimSpace(raw)
	for _, layout := range []string{
		"2006-01-02 15:04:05.999999999", "2006-01-02 15:04:05", "2006-01-02T15:04:05.999999999Z07:00",
		"2006-01-02T15:04:05Z07:00", "2006-01-02 15:04:05.999999999Z07:00", "2006-01-02 15:04:05Z07:00",
	} {
		if t, err := time.Parse(layout, raw); err == nil {
			t = t.UTC()
			return t.Format("2006-01-02 15:04"), t.Unix()
		}
	}
	return raw, 0
}
