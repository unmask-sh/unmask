// analyze: aggregate unmask_event to suggest candidates for new fingerprints.
//
// Logic:
//   - Aggregate ja4 of reqs in the window (= -days 30) where verdict='ok'
//     and the UA claims is_known_browser.
//   - Surface fingerprints that exceed threshold (= -threshold 100) and also
//     have many unique IPs as candidates to add to ja4-verdict.map.
//   - Exclude already-known fingerprints (= those carrying verdict other than 'ok').
//
// Example output:
//
//	== suggested ja4 to investigate (= top 20) ==
//	   req       uniq_ip  ja4                                         sample_ua
//	   12345     8421     t13d1517h2_8daaf6152771_b0da82dd1658        Mozilla/5.0 (Windows NT 10.0; Win64;...
//
// Risk of false positives from a browser's intentional fingerprint, so always
// review before manually adding to ja4-verdict.map.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

func cmdAnalyze(args []string) error {
	fs := flag.NewFlagSet("analyze", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	days := fs.Int("days", 30, "lookback days")
	threshold := fs.Int("threshold", 100, "min req count to suggest")
	limit := fs.Int("limit", 20, "max rows to print")
	site := fs.String("site", "", "filter by site")
	_ = fs.Parse(args)

	s, err := loadSettings(*configPath)
	if err != nil {
		return err
	}
	conn, err := db.Open(s.DB)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Identifying browser UAs via LIKE is limited.  Use the Mozilla/5.0 prefix
	// as "claims to be a browser."  Legitimate bots (= Googlebot etc.) include
	// Mozilla in the UA but also explicitly state "bot" later in the UA, so
	// exclude anything containing "bot" / "crawler" / "spider" in the tail.
	stmt := fmt.Sprintf(`
        SELECT ja4,
               COUNT(*) AS req,
               COUNT(DISTINCT ip_address) AS uniq_ip,
               MAX(user_agent) AS sample_ua
        FROM unmask_event
        WHERE date_created > %s
          AND ja4 IS NOT NULL AND ja4 <> ''
          AND COALESCE(ja4_verdict, '') IN ('', 'ok')
          AND user_agent LIKE 'Mozilla/5.0%%'
          AND LOWER(user_agent) NOT LIKE '%%bot%%'
          AND LOWER(user_agent) NOT LIKE '%%crawler%%'
          AND LOWER(user_agent) NOT LIKE '%%spider%%'
          %s
        GROUP BY ja4
        HAVING COUNT(*) >= ?
        ORDER BY uniq_ip DESC, req DESC
        LIMIT ?`,
		conn.NowMinusMinutes(*days*24*60),
		siteCondLiteral(*site),
	)
	rows, err := conn.QueryContext(ctx, stmt, *threshold, *limit)
	if err != nil {
		return err
	}
	defer rows.Close()

	fmt.Fprintln(os.Stdout, "== suggested ja4 to investigate ==")
	fmt.Fprintf(os.Stdout, "  %-8s  %-7s  %-44s  %s\n", "req", "uniq_ip", "ja4", "sample_ua")
	n := 0
	for rows.Next() {
		var ja4, ua string
		var req, uniq int
		if err := rows.Scan(&ja4, &req, &uniq, &ua); err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "  %-8d  %-7d  %-44s  %s\n",
			req, uniq, ja4, truncForCLI(ua, 60))
		n++
	}
	if n == 0 {
		fmt.Fprintln(os.Stdout, "  (= no matches.  Retry with a lower threshold or longer window.)")
	}
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, "Format for adding to ja4-verdict.map:")
	fmt.Fprintln(os.Stdout, `  "~^t13d1517h2_<...>"     "bot_<reason>";`)
	return rows.Err()
}

// siteCondLiteral: returns "" if site is empty, otherwise an `AND site = '...'`
// literal.  The CLI is operator-controlled (self-injection only), but strip both
// the quote AND the backslash so a trailing `\` can't escape the closing quote
// and run on into the rest of the statement under MySQL backslash-escaping.
func siteCondLiteral(site string) string {
	if site == "" {
		return ""
	}
	site = strings.NewReplacer("'", "", "\\", "").Replace(site)
	return "AND site = '" + site + "'"
}
