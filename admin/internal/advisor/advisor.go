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
	Detail string `json:"detail"`
	Weight int    `json:"weight"`
}

// Candidate is one proposed ban target with the evidence that produced it.
type Candidate struct {
	Type        string   `json:"type"`   // "ip" | "ja4"
	Target      string   `json:"target"` // the address or the fingerprint
	Scope       string   `json:"scope"`  // suggested ban scope (ip_only / ja4_only)
	JA4         string   `json:"ja4,omitempty"`
	UA          string   `json:"ua,omitempty"`
	Signals     []Signal `json:"signals"`
	Score       int      `json:"score"`
	Requests    int      `json:"requests"`
	Serves      int      `json:"serves"`
	Passes      int      `json:"passes"`
	ScannerHits int      `json:"scanner_hits,omitempty"`
	DistinctIPs int      `json:"distinct_ips,omitempty"`
	FirstSeen   string   `json:"first_seen"`
	LastSeen    string   `json:"last_seen"`
	ASN         uint     `json:"asn,omitempty"`
	ASNOrg      string   `json:"asn_org,omitempty"`
	Country     string   `json:"country,omitempty"`
	SamplePaths []string `json:"sample_paths,omitempty"`
}

// Options tunes the extraction.  Zero values resolve to the defaults below —
// deliberately conservative: a candidate list that cries wolf gets ignored,
// and the operator can always widen the window.
type Options struct {
	WindowMinutes int // default 24h
	MinServes     int // default 30: challenge serves before an IP is "hammering"
	MinScanner    int // default 3: distinct-ish scanner-path hits
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
	if o.HerdMinIPs <= 0 {
		o.HerdMinIPs = 10
	}
	if o.Limit <= 0 {
		o.Limit = 20
	}
	return o
}

// passPhases are the phases that prove the client executed the challenge
// JavaScript at all: `load` fires from the page's own JS, the bv_* family
// records an issued pass cookie, pow_pass the solved intermediate step, and
// bv_rebind a roaming holder of a valid cookie.  A client with serves but
// none of these fetched challenge HTML over and over and never ran a line of
// it — the crispest "not a browser" signature the event log carries.
const passPhaseList = "('load','pow_pass','bv_pow_only','bv_captcha_only','bv_pow_then_captcha','bv_rebind')"

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

func scannerCond() string {
	parts := make([]string, len(scannerLikes))
	for i, l := range scannerLikes {
		parts[i] = "payload_json LIKE '" + l + "'"
	}
	return "(" + strings.Join(parts, " OR ") + ")"
}

// Candidates runs the extraction.  gip may be nil (origin columns stay empty).
func Candidates(ctx context.Context, conn *db.DB, gip *ipgeo.Reader, excl Exclusions, opt Options) ([]Candidate, error) {
	opt = opt.resolved()
	var out []Candidate

	ipCands, err := ipCandidates(ctx, conn, gip, excl, opt)
	if err != nil {
		return nil, fmt.Errorf("ip pass: %w", err)
	}
	out = append(out, ipCands...)

	ja4Cands, err := ja4Candidates(ctx, conn, excl, opt)
	if err != nil {
		return nil, fmt.Errorf("ja4 pass: %w", err)
	}
	out = append(out, ja4Cands...)

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Score != out[j].Score {
			return out[i].Score > out[j].Score
		}
		return out[i].Serves+out[i].Requests > out[j].Serves+out[j].Requests
	})
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
	// HAVING repeats the aggregate expressions instead of the aliases: sqlite
	// accepts aliases there, MariaDB in some modes does not.
	q := `SELECT ip_address,
	        COUNT(*) AS total,
	        SUM(CASE WHEN phase='serve' THEN 1 ELSE 0 END) AS serves,
	        SUM(CASE WHEN phase IN ` + passPhaseList + ` THEN 1 ELSE 0 END) AS passes,
	        SUM(CASE WHEN ` + scannerCond() + ` THEN 1 ELSE 0 END) AS scanner_hits,
	        MIN(date_created), MAX(date_created), MAX(ja4), MAX(user_agent)
	      FROM unmask_event` + conn.EventDateIndexHint("w") + `
	      WHERE date_created > ` + conn.NowMinusMinutes(opt.WindowMinutes) + `
	      GROUP BY ip_address
	      HAVING SUM(CASE WHEN phase='serve' THEN 1 ELSE 0 END) >= ?
	          OR SUM(CASE WHEN ` + scannerCond() + ` THEN 1 ELSE 0 END) >= ?
	      ORDER BY serves DESC
	      LIMIT 200`
	rows, err := conn.QueryContext(ctx, q, opt.MinServes, opt.MinScanner)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Candidate
	for rows.Next() {
		var c Candidate
		var ipBytes []byte
		var first, last, ja4, ua string
		if err := rows.Scan(&ipBytes, &c.Requests, &c.Serves, &c.Passes, &c.ScannerHits, &first, &last, &ja4, &ua); err != nil {
			return nil, err
		}
		ip := unpackIP(ipBytes)
		if skipIP(ip, excl) {
			continue
		}
		c.Type, c.Target, c.Scope = "ip", ip, "ip_only"
		c.JA4, c.UA, c.FirstSeen, c.LastSeen = ja4, ua, first, last

		if c.Serves >= opt.MinServes && c.Passes == 0 {
			c.Signals = append(c.Signals, Signal{
				ID: "challenge_hammering", Weight: 3,
				Detail: fmt.Sprintf("%d challenges served, JS never executed", c.Serves),
			})
		}
		if c.ScannerHits >= opt.MinScanner {
			c.Signals = append(c.Signals, Signal{
				ID: "scanner_paths", Weight: 3,
				Detail: fmt.Sprintf("%d requests for scanner-signature paths", c.ScannerHits),
			})
		}
		if gip != nil {
			info := gip.LookupInfo(ip)
			c.ASN, c.ASNOrg, c.Country = info.ASN, info.ASNOrg, info.Country
			if hp := hostingMatch(info.ASNOrg); hp != "" {
				w := 1
				detail := "address in a hosting network (" + hp + ")"
				if strings.HasPrefix(ua, "Mozilla/") {
					w = 2
					detail += " wearing a browser User-Agent"
				}
				c.Signals = append(c.Signals, Signal{ID: "hosting_network", Weight: w, Detail: detail})
			}
		}
		for _, s := range c.Signals {
			c.Score += s.Weight
		}
		// A hosting-network address that neither hammers nor scans is just a
		// server: not a candidate on its own.
		if c.Score >= 3 {
			out = append(out, c)
		}
	}
	return out, rows.Err()
}

func ja4Candidates(ctx context.Context, conn *db.DB, excl Exclusions, opt Options) ([]Candidate, error) {
	q := `SELECT ja4,
	        COUNT(DISTINCT ip_address) AS ips,
	        COUNT(*) AS total,
	        SUM(CASE WHEN phase='serve' THEN 1 ELSE 0 END) AS serves,
	        SUM(CASE WHEN phase IN ` + passPhaseList + ` THEN 1 ELSE 0 END) AS passes,
	        MIN(date_created), MAX(date_created), MAX(user_agent)
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
		if err := rows.Scan(&ja4, &c.DistinctIPs, &c.Requests, &c.Serves, &c.Passes, &first, &last, &ua); err != nil {
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
		c.UA, c.FirstSeen, c.LastSeen = ua, first, last
		c.Signals = append(c.Signals, Signal{
			ID: "ja4_herd", Weight: 3,
			Detail: fmt.Sprintf("one fingerprint across %d addresses, %d serves, %d passes", c.DistinctIPs, c.Serves, c.Passes),
		})
		c.Score = 3
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
	q := `SELECT ip_address, payload_json FROM unmask_event` + conn.EventDateIndexHint("w") + `
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
			Path string `json:"path"`
		}
		if json.Unmarshal([]byte(payload), &p) != nil || p.Path == "" {
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
