package advisor

import (
	"context"
	"sort"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
)

// ReasonCount: challenge pages served to a client by the rule that
// escalated it -- payload_json.force_reason on the serve event (header /
// stale / asn / geo / rate_limit / honeypot / banned / protected / ja4_bot /
// community_bans; a *_deny value is a refusal, not a challenge).  Reason ""
// is the ordinary path: no rule, the default challenge.  The traffic cell
// splits the served figure by it (operator, 2026-09-13: "昇格理由とその数も").
type ReasonCount struct {
	Reason string `json:"reason"`
	Serves int    `json:"serves"`
}

// None: the ordinary path, no rule.
func (r ReasonCount) None() bool { return r.Reason == "" }

// sortReasons: the rules by serves, the ordinary path last.
func sortReasons(rs []ReasonCount) {
	sort.SliceStable(rs, func(i, j int) bool {
		a, b := rs[i], rs[j]
		if a.None() != b.None() {
			return !a.None()
		}
		if a.Serves != b.Serves {
			return a.Serves > b.Serves
		}
		return a.Reason < b.Reason
	})
}

// MoreUAs: the user agents the row does not list (DistinctUAs beyond the
// ones shown).
func (c Candidate) MoreUAs() int { return floor0(c.DistinctUAs - len(c.TopUAs)) }

// Escalated: a rule served at least one of this client's challenges, so
// the row carries the reasons line.  A client on the ordinary path alone
// has no line: nothing escalated it.
func (c Candidate) Escalated() bool {
	for _, r := range c.Reasons {
		if !r.None() {
			return true
		}
	}
	return false
}

// UACount: one user agent a client used and how many of its requests
// carried it.  The row lists the most frequent ones (topUAs) and says how
// many more there were: one address rotating user agents, or a
// fingerprint herd's spread of browsers, is a shape one arbitrary user
// agent hid (operator, 2026-09-13: "UA 一個だけしか表示されてないけど
// TOP5 を出すとかの方がいいかも").
type UACount struct {
	UA       string `json:"ua"`
	Requests int    `json:"requests"`
}

// topUAs: how many user agents a row lists.
const topUAs = 5

// facets: what one grouped pass over a key's events yields -- the serves by
// escalation reason, the requests by user agent.
type facets struct {
	Reasons     []ReasonCount
	TopUAs      []UACount
	DistinctUAs int
}

// keyFacets reads the events of the given keys -- packed addresses for
// ip_address, fingerprints for ja4 -- grouped by user agent and, on the
// serve rows, by force_reason, in one query per key column; the JSON path
// is read on the serve rows only.  "none" and a missing reason are the
// ordinary path (""); a missing user agent is not a user agent.
func keyFacets(ctx context.Context, conn *db.DB, col string, keys []any, windowMinutes int) (map[string]facets, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	ph := strings.TrimRight(strings.Repeat("?,", len(keys)), ",")
	reason := "CASE WHEN phase='serve' THEN COALESCE(" + conn.JSONExtract("payload_json", "$.force_reason") + ", '') ELSE '-' END"
	q := `SELECT ` + col + `, COALESCE(user_agent, ''), ` + reason + `, COUNT(*) FROM unmask_event` + keyIndexHint(conn, col) + `
	      WHERE date_created > ` + conn.NowMinusMinutes(windowMinutes) + `
	        AND ` + col + ` IN (` + ph + `)
	      GROUP BY 1, 2, 3`
	rows, err := conn.QueryContext(ctx, q, keys...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	reasons := map[string]map[string]int{}
	uas := map[string]map[string]int{}
	for rows.Next() {
		var key []byte
		var ua, r string
		var n int
		if err := rows.Scan(&key, &ua, &r, &n); err != nil {
			return nil, err
		}
		k := string(key)
		if col == "ip_address" {
			k = unpackIP(key)
		}
		if r != "-" { // a serve row
			if r == "none" {
				r = ""
			}
			if reasons[k] == nil {
				reasons[k] = map[string]int{}
			}
			reasons[k][r] += n
		}
		if ua != "" {
			if uas[k] == nil {
				uas[k] = map[string]int{}
			}
			uas[k][ua] += n
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := map[string]facets{}
	for k, rs := range reasons {
		f := out[k]
		for r, n := range rs {
			f.Reasons = append(f.Reasons, ReasonCount{Reason: r, Serves: n})
		}
		sortReasons(f.Reasons)
		out[k] = f
	}
	for k, us := range uas {
		f := out[k]
		for ua, n := range us {
			f.TopUAs = append(f.TopUAs, UACount{UA: ua, Requests: n})
		}
		sort.SliceStable(f.TopUAs, func(i, j int) bool {
			if f.TopUAs[i].Requests != f.TopUAs[j].Requests {
				return f.TopUAs[i].Requests > f.TopUAs[j].Requests
			}
			return f.TopUAs[i].UA < f.TopUAs[j].UA
		})
		f.DistinctUAs = len(f.TopUAs)
		if len(f.TopUAs) > topUAs {
			f.TopUAs = f.TopUAs[:topUAs]
		}
		out[k] = f
	}
	return out, nil
}

// keyIndexHint: the address index for an address IN list (a few seeks), the
// date index for fingerprints (no index of their own).
func keyIndexHint(conn *db.DB, col string) string {
	if col == "ip_address" {
		return conn.EventIPIndexHint()
	}
	return conn.EventDateIndexHint("w")
}

// PathCount: one path a client requested, how many times, and where -- the
// site, scheme and port the module recorded on the serve, so the row can
// offer the full address (Open / Copy) the way the hunt log does.
// Operator (2026-09-13): "パスもヒット数があるといいかも".
type PathCount struct {
	Path   string `json:"path"`
	Hits   int    `json:"hits"`
	Site   string `json:"site,omitempty"`
	Scheme string `json:"scheme,omitempty"`
	Port   int    `json:"port,omitempty"`
}

// topPaths: how many paths a row lists.
const topPaths = 3

// MorePaths: the paths the row does not list.
func (c Candidate) MorePaths() int { return floor0(c.DistinctPaths - len(c.Paths)) }

type pathFacet struct {
	Top      []PathCount
	Distinct int
}

// keyPaths tallies the serve events of the given keys by the path served
// (the module's orig_path; path is the older / test shape), keeping each
// key's most requested topPaths with the origin of the latest-sorting serve
// and how many different paths there were.
func keyPaths(ctx context.Context, conn *db.DB, col string, keys []any, windowMinutes int) (map[string]pathFacet, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	ph := strings.TrimRight(strings.Repeat("?,", len(keys)), ",")
	path := "COALESCE(NULLIF(" + conn.JSONExtract("payload_json", "$.orig_path") + ", ''), " + conn.JSONExtract("payload_json", "$.path") + ", '')"
	q := `SELECT ` + col + `, ` + path + `, COUNT(*), MAX(COALESCE(site, '')), MAX(COALESCE(scheme, '')), MAX(COALESCE(port, 0))
	      FROM unmask_event` + keyIndexHint(conn, col) + `
	      WHERE date_created > ` + conn.NowMinusMinutes(windowMinutes) + `
	        AND phase='serve' AND ` + col + ` IN (` + ph + `)
	      GROUP BY 1, 2`
	rows, err := conn.QueryContext(ctx, q, keys...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	all := map[string][]PathCount{}
	for rows.Next() {
		var key []byte
		var p PathCount
		if err := rows.Scan(&key, &p.Path, &p.Hits, &p.Site, &p.Scheme, &p.Port); err != nil {
			return nil, err
		}
		if p.Path == "" {
			continue
		}
		k := string(key)
		if col == "ip_address" {
			k = unpackIP(key)
		}
		all[k] = append(all[k], p)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := map[string]pathFacet{}
	for k, ps := range all {
		sort.SliceStable(ps, func(i, j int) bool {
			if ps[i].Hits != ps[j].Hits {
				return ps[i].Hits > ps[j].Hits
			}
			return ps[i].Path < ps[j].Path
		})
		f := pathFacet{Distinct: len(ps), Top: ps}
		if len(f.Top) > topPaths {
			f.Top = f.Top[:topPaths]
		}
		out[k] = f
	}
	return out, nil
}

// FillPaths puts the most requested paths on the candidates that have none
// -- the reviewer's "what were they after".  Per key: an address through
// its index, a fingerprint through the date index.  One shared sample of
// the newest 400 events over every candidate at once went to the busiest
// few and left the other rows empty, and fingerprint rows and the model's
// picks were never read at all (operator, 2026-09-13: "要求パス例が空欄の
// ものが多いのはなぜ？").  The engine calls it on its candidates, the page
// on the picks it appends.
func FillPaths(ctx context.Context, conn *db.DB, cands []Candidate, opt Options) error {
	opt = opt.resolved()
	var ips, ja4s []string
	for _, c := range cands {
		if len(c.Paths) > 0 {
			continue
		}
		switch c.Type {
		case "ip":
			ips = append(ips, c.Target)
		case "ja4":
			ja4s = append(ja4s, c.Target)
		}
	}
	byIP, err := keyPaths(ctx, conn, "ip_address", packedIPs(ips), opt.WindowMinutes)
	if err != nil {
		return err
	}
	byJA4, err := keyPaths(ctx, conn, "ja4", ja4Keys(ja4s), opt.WindowMinutes)
	if err != nil {
		return err
	}
	for i := range cands {
		c := &cands[i]
		if len(c.Paths) > 0 {
			continue
		}
		var f pathFacet
		switch c.Type {
		case "ip":
			f = byIP[c.Target]
		case "ja4":
			f = byJA4[c.Target]
		}
		c.Paths, c.DistinctPaths = f.Top, f.Distinct
		c.SamplePaths = c.SamplePaths[:0]
		for _, p := range f.Top {
			c.SamplePaths = append(c.SamplePaths, p.Path)
		}
	}
	return nil
}

// packedIPs: the addresses as the table stores them, for an IN list.
func packedIPs(ips []string) []any {
	var out []any
	for _, ip := range ips {
		if p := events.PackIP(ip); p != nil {
			out = append(out, p)
		}
	}
	return out
}

func ja4Keys(ja4s []string) []any {
	out := make([]any, 0, len(ja4s))
	for _, j := range ja4s {
		out = append(out, j)
	}
	return out
}

// applyFacets puts a key's facets on a row: the reasons, the user agents,
// and the most frequent user agent as the row's one (in place of the
// alphabetical maximum the ranking query yields) when there is one.
func applyFacets(f facets, reasons *[]ReasonCount, top *[]UACount, distinct *int, ua *string) {
	*reasons, *top, *distinct = f.Reasons, f.TopUAs, f.DistinctUAs
	if len(f.TopUAs) > 0 {
		*ua = f.TopUAs[0].UA
	}
}

// fillFacets puts the escalation reasons and the user agents on the
// candidates.
func fillFacets(ctx context.Context, conn *db.DB, cands []Candidate, opt Options) error {
	var ips, ja4s []string
	for _, c := range cands {
		switch c.Type {
		case "ip":
			ips = append(ips, c.Target)
		case "ja4":
			ja4s = append(ja4s, c.Target)
		}
	}
	byIP, err := keyFacets(ctx, conn, "ip_address", packedIPs(ips), opt.WindowMinutes)
	if err != nil {
		return err
	}
	byJA4, err := keyFacets(ctx, conn, "ja4", ja4Keys(ja4s), opt.WindowMinutes)
	if err != nil {
		return err
	}
	for i := range cands {
		c := &cands[i]
		switch c.Type {
		case "ip":
			applyFacets(byIP[c.Target], &c.Reasons, &c.TopUAs, &c.DistinctUAs, &c.UA)
		case "ja4":
			applyFacets(byJA4[c.Target], &c.Reasons, &c.TopUAs, &c.DistinctUAs, &c.UA)
		}
	}
	return nil
}

// fillPoolFacets: the same for the pool rows, so a nomination carries them
// (fillFromPool) and the model reads them.
func fillPoolFacets(ctx context.Context, conn *db.DB, pool *Pool, windowMinutes int) error {
	ips := make([]string, 0, len(pool.IPs))
	for _, r := range pool.IPs {
		ips = append(ips, r.IP)
	}
	ja4s := make([]string, 0, len(pool.JA4s))
	for _, r := range pool.JA4s {
		ja4s = append(ja4s, r.JA4)
	}
	byIP, err := keyFacets(ctx, conn, "ip_address", packedIPs(ips), windowMinutes)
	if err != nil {
		return err
	}
	byJA4, err := keyFacets(ctx, conn, "ja4", ja4Keys(ja4s), windowMinutes)
	if err != nil {
		return err
	}
	for i := range pool.IPs {
		r := &pool.IPs[i]
		applyFacets(byIP[r.IP], &r.Reasons, &r.TopUAs, &r.DistinctUAs, &r.UA)
		if len(r.UA) > maxUAForBundle {
			r.UA = r.UA[:maxUAForBundle]
		}
	}
	for i := range pool.JA4s {
		r := &pool.JA4s[i]
		applyFacets(byJA4[r.JA4], &r.Reasons, &r.TopUAs, &r.DistinctUAs, &r.UA)
		if len(r.UA) > maxUAForBundle {
			r.UA = r.UA[:maxUAForBundle]
		}
	}
	return nil
}
