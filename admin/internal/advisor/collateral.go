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
	hint := conn.EventDateIndexHint("w")
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

// JA4CollateralMany measures the same seven days for a set of fingerprints
// at once -- the consultation's case, where a dozen fingerprint candidates
// each need their passers and verdict.  One fingerprint at a time cost
// three walks of the week per fingerprint (the event table has no
// fingerprint index; the date index is walked and filtered), which on a
// busy node was over a minute per consultation (tool1-us, 2026-09-14:
// 12 fingerprints, 73 s).  Grouped, the week is walked twice in all: the
// counts, then the verdicts.  The passers' user agents are not read here;
// they belong to the dialog, which asks for one fingerprint.
func JA4CollateralMany(ctx context.Context, conn *db.DB, ja4s []string) (map[string]Collateral, error) {
	out := map[string]Collateral{}
	keys := make([]any, 0, len(ja4s))
	for _, j := range ja4s {
		if j == "" {
			continue
		}
		if _, dup := out[j]; dup {
			continue
		}
		out[j] = Collateral{JA4: j, Days: collateralDays, PassUAs: []string{}, Level: "none"}
		keys = append(keys, j)
	}
	if len(keys) == 0 {
		return out, nil
	}
	ph := strings.TrimRight(strings.Repeat("?,", len(keys)), ",")
	since := conn.NowMinusMinutes(collateralDays * 24 * 60)
	hint := conn.EventDateIndexHint("w")
	rows, err := conn.QueryContext(ctx, `SELECT ja4, COUNT(DISTINCT ip_address),
	        COALESCE(SUM(CASE WHEN phase IN `+cookiePhaseList+` THEN 1 ELSE 0 END), 0),
	        COUNT(DISTINCT CASE WHEN phase IN `+cookiePhaseList+` THEN ip_address END)
	      FROM unmask_event`+hint+`
	      WHERE date_created > `+since+` AND ja4 IN (`+ph+`)
	      GROUP BY ja4`, keys...)
	if err != nil {
		return nil, fmt.Errorf("collateral: %w", err)
	}
	for rows.Next() {
		var j string
		var ips, passes, passIPs int
		if err := rows.Scan(&j, &ips, &passes, &passIPs); err != nil {
			rows.Close()
			return nil, fmt.Errorf("collateral: %w", err)
		}
		c := out[j]
		c.IPs, c.Passes, c.PassIPs = ips, passes, passIPs
		c.Level = collateralLevel(passIPs)
		out[j] = c
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("collateral: %w", err)
	}
	// The most common verdict on each fingerprint's serves: grouped by
	// fingerprint and verdict, the first (largest) row per fingerprint wins.
	rows, err = conn.QueryContext(ctx, `SELECT ja4, COALESCE(ja4_verdict, ''), COUNT(*) AS n
	      FROM unmask_event`+hint+`
	      WHERE date_created > `+since+` AND ja4 IN (`+ph+`) AND phase = 'serve'
	      GROUP BY ja4, ja4_verdict ORDER BY ja4, n DESC`, keys...)
	if err != nil {
		return nil, fmt.Errorf("collateral verdicts: %w", err)
	}
	seen := map[string]bool{}
	for rows.Next() {
		var j, verdict string
		var n int
		if err := rows.Scan(&j, &verdict, &n); err != nil {
			rows.Close()
			return nil, fmt.Errorf("collateral verdicts: %w", err)
		}
		if seen[j] {
			continue
		}
		seen[j] = true
		c := out[j]
		c.Verdict = verdict
		out[j] = c
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("collateral verdicts: %w", err)
	}
	return out, nil
}
