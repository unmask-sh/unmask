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
	switch {
	case c.PassIPs == 0:
		c.Level = "none"
	case c.PassIPs < collateralAckMax:
		c.Level = "some"
	default:
		c.Level = "block"
	}
	return c, nil
}
