// collateral.go — what a JA4 ban would hit besides its target.
//
// A JA4 names a device-and-browser stack, not a client: every visitor with
// that stack carries the same fingerprint.  Banning one blocks all of them,
// everywhere, until the ban is lifted -- so before a fingerprint is banned
// the operator (and the model) must see how many real visitors passed the
// challenge with it lately.  Seven days is long enough to catch the weekly
// rhythm of a small site; the window the page is looking at is not.
package advisor

import (
	"context"
	"fmt"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

const (
	collateralDays   = 7
	collateralAckMax = 10 // passing addresses from which a ban is refused outright
	collateralUAMax  = 120
)

// Collateral is the answer: how many addresses carried the fingerprint,
// how many of them got through the challenge, what they looked like.
type Collateral struct {
	JA4     string   `json:"ja4"`
	Days    int      `json:"days"`
	IPs     int      `json:"ips"`      // distinct addresses with this fingerprint
	Passes  int      `json:"passes"`   // challenges completed (pass cookies issued)
	PassIPs int      `json:"pass_ips"` // distinct addresses that completed one
	PassUAs []string `json:"pass_uas"` // what the passers called themselves (top 3)
	Verdict string   `json:"verdict"`  // the fingerprint's most common JA4 verdict on serves ("" = none)
	// Level: "none" (no passer: a ban hits nobody real), "some" (a few:
	// the operator must acknowledge the collateral), "block" (too many
	// real visitors share it: not from this dialog).
	Level string `json:"level"`
}

// JA4Collateral measures the last collateralDays for one fingerprint.
func JA4Collateral(ctx context.Context, conn *db.DB, ja4 string) (Collateral, error) {
	c := Collateral{JA4: ja4, Days: collateralDays, PassUAs: []string{}}
	since := conn.NowMinusMinutes(collateralDays * 24 * 60)
	hint := conn.EventJA4IndexHint()
	row := conn.QueryRowContext(ctx, `SELECT COUNT(DISTINCT ip_address),
	        COALESCE(SUM(CASE WHEN phase IN `+cookiePhaseList+` THEN 1 ELSE 0 END), 0),
	        COUNT(DISTINCT CASE WHEN phase IN `+cookiePhaseList+` THEN ip_address END)
	      FROM unmask_event`+hint+`
	      WHERE date_created > `+since+` AND ja4 = ?`, ja4)
	if err := row.Scan(&c.IPs, &c.Passes, &c.PassIPs); err != nil {
		return c, fmt.Errorf("collateral: %w", err)
	}
	if c.Passes > 0 {
		rows, err := conn.QueryContext(ctx, `SELECT COALESCE(user_agent, ''), COUNT(*) AS n
		      FROM unmask_event`+hint+`
		      WHERE date_created > `+since+` AND ja4 = ? AND phase IN `+cookiePhaseList+`
		      GROUP BY user_agent ORDER BY n DESC LIMIT 3`, ja4)
		if err != nil {
			return c, fmt.Errorf("collateral uas: %w", err)
		}
		for rows.Next() {
			var ua string
			var n int
			if err := rows.Scan(&ua, &n); err != nil {
				rows.Close()
				return c, err
			}
			ua = strings.TrimSpace(ua)
			if ua == "" {
				continue
			}
			if len(ua) > collateralUAMax {
				ua = ua[:collateralUAMax]
			}
			c.PassUAs = append(c.PassUAs, ua)
		}
		rows.Close()
	}
	var verdict string
	var n int
	if err := conn.QueryRowContext(ctx, `SELECT COALESCE(ja4_verdict, ''), COUNT(*) AS n
	      FROM unmask_event`+hint+`
	      WHERE date_created > `+since+` AND ja4 = ? AND phase = 'serve'
	      GROUP BY ja4_verdict ORDER BY n DESC LIMIT 1`, ja4).Scan(&verdict, &n); err == nil {
		c.Verdict = verdict
	}
	c.Level = collateralLevel(c.PassIPs)
	return c, nil
}

// collateralLevel grades a passer count for the ban dialog.
func collateralLevel(passIPs int) string {
	switch {
	case passIPs == 0:
		return "none"
	case passIPs < collateralAckMax:
		return "some"
	default:
		return "block"
	}
}

// JA4PassersMany answers the one collateral question a consultation asks of
// every fingerprint candidate: how many addresses completed the challenge
// with it in the last seven days.  That is what the model is given and what
// decides whether a ban would hit real visitors.
//
// It is deliberately narrower than JA4Collateral, which the ban dialog uses.
// The dialog asks about one fingerprint while a human waits, and shows the
// total addresses and the passers' user agents besides.  A consultation asks
// about all of the candidates at once, and the candidates are the busiest
// fingerprints on the node -- narrowing to them still leaves most of the
// table, so counting their distinct addresses read nearly everything, twice.
// The completions among those rows are a small fraction of them.  Filtering
// on the phase in the query, with the phase in the index, is the whole
// difference: the read goes to the rows that answer the question instead of
// to everything those fingerprints did.
func JA4PassersMany(ctx context.Context, conn *db.DB, ja4s []string) (map[string]int, error) {
	out := map[string]int{}
	keys := make([]any, 0, len(ja4s))
	for _, j := range ja4s {
		if j == "" {
			continue
		}
		if _, dup := out[j]; dup {
			continue
		}
		out[j] = 0
		keys = append(keys, j)
	}
	if len(keys) == 0 {
		return out, nil
	}
	ph := strings.TrimRight(strings.Repeat("?,", len(keys)), ",")
	rows, err := conn.QueryContext(ctx, `SELECT ja4, COUNT(DISTINCT ip_address)
	      FROM unmask_event`+conn.EventJA4IndexHint()+`
	      WHERE date_created > `+conn.NowMinusMinutes(collateralDays*24*60)+`
	        AND ja4 IN (`+ph+`) AND phase IN `+cookiePhaseList+`
	      GROUP BY ja4`, keys...)
	if err != nil {
		return nil, fmt.Errorf("collateral passers: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var j string
		var passIPs int
		if err := rows.Scan(&j, &passIPs); err != nil {
			return nil, fmt.Errorf("collateral passers: %w", err)
		}
		out[j] = passIPs
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("collateral passers: %w", err)
	}
	return out, nil
}
