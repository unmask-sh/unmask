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

// serveReasons tallies the serve events of the given keys -- packed
// addresses for ip_address, fingerprints for ja4 -- by force_reason in one
// grouped query; the JSON path is read on those serve rows only.  "none"
// and a missing reason are the ordinary path ("").
func serveReasons(ctx context.Context, conn *db.DB, col string, keys []any, windowMinutes int) (map[string][]ReasonCount, error) {
	if len(keys) == 0 {
		return nil, nil
	}
	ph := strings.TrimRight(strings.Repeat("?,", len(keys)), ",")
	reason := "COALESCE(" + conn.JSONExtract("payload_json", "$.force_reason") + ", '')"
	q := `SELECT ` + col + `, ` + reason + `, COUNT(*) FROM unmask_event` + conn.EventDateIndexHint("w") + `
	      WHERE date_created > ` + conn.NowMinusMinutes(windowMinutes) + `
	        AND phase='serve' AND ` + col + ` IN (` + ph + `)
	      GROUP BY 1, 2`
	rows, err := conn.QueryContext(ctx, q, keys...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]ReasonCount{}
	for rows.Next() {
		var key []byte
		var r string
		var n int
		if err := rows.Scan(&key, &r, &n); err != nil {
			return nil, err
		}
		k := string(key)
		if col == "ip_address" {
			k = unpackIP(key)
		}
		if r == "none" {
			r = ""
		}
		out[k] = append(out[k], ReasonCount{Reason: r, Serves: n})
	}
	for k := range out {
		sortReasons(out[k])
	}
	return out, rows.Err()
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

// fillReasons puts the escalation reasons on the candidates.
func fillReasons(ctx context.Context, conn *db.DB, cands []Candidate, opt Options) error {
	var ips, ja4s []string
	for _, c := range cands {
		switch c.Type {
		case "ip":
			ips = append(ips, c.Target)
		case "ja4":
			ja4s = append(ja4s, c.Target)
		}
	}
	byIP, err := serveReasons(ctx, conn, "ip_address", packedIPs(ips), opt.WindowMinutes)
	if err != nil {
		return err
	}
	byJA4, err := serveReasons(ctx, conn, "ja4", ja4Keys(ja4s), opt.WindowMinutes)
	if err != nil {
		return err
	}
	for i := range cands {
		switch cands[i].Type {
		case "ip":
			cands[i].Reasons = byIP[cands[i].Target]
		case "ja4":
			cands[i].Reasons = byJA4[cands[i].Target]
		}
	}
	return nil
}

// fillPoolReasons: the same for the pool rows, so a nomination carries
// them (fillFromPool) and the model reads them.
func fillPoolReasons(ctx context.Context, conn *db.DB, pool *Pool, windowMinutes int) error {
	ips := make([]string, 0, len(pool.IPs))
	for _, r := range pool.IPs {
		ips = append(ips, r.IP)
	}
	ja4s := make([]string, 0, len(pool.JA4s))
	for _, r := range pool.JA4s {
		ja4s = append(ja4s, r.JA4)
	}
	byIP, err := serveReasons(ctx, conn, "ip_address", packedIPs(ips), windowMinutes)
	if err != nil {
		return err
	}
	byJA4, err := serveReasons(ctx, conn, "ja4", ja4Keys(ja4s), windowMinutes)
	if err != nil {
		return err
	}
	for i := range pool.IPs {
		pool.IPs[i].Reasons = byIP[pool.IPs[i].IP]
	}
	for i := range pool.JA4s {
		pool.JA4s[i].Reasons = byJA4[pool.JA4s[i].JA4]
	}
	return nil
}
