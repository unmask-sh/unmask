// stats: read-only aggregate dump for operators who cannot query the database
// themselves.
//
// The motivating case is CentOS 6, whose sqlite3 is 3.6.20 -- it predates WAL
// and refuses to open the file at all ("file is encrypted or is not a
// database"), so the usual "just run a SELECT" advice is unavailable exactly
// where an operator is most likely to be debugging by hand.  The same is true
// of a MariaDB install whose credentials live only in config.yml, and of any
// host where handing out a database client is a worse idea than handing out a
// read-only command.
//
// Everything here reads.  Nothing writes, and no schema change can be
// triggered from this path.
//
// Example:
//
//	# what happened in the last day
//	unmask stats
//
//	# the phase breakdown for one site over a week, for a script
//	unmask stats -kind phase -since 7d -site www.example.com -tsv
//
//	# everything, to paste into a support thread
//	unmask stats -kind all -since 24h
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
)

// statsKind is one report.  The dispatch table below is the single source for
// the help text, the `-kind all` order, and the validation of -kind, so none
// of the three can drift from what is actually implemented.
type statsKind struct {
	name string
	desc string
	run  func(ctx context.Context, out *statsWriter, conn *db.DB, o statsOpts) error
}

// statsKinds is the dispatch table, in the order `-kind all` prints them.
var statsKinds = []statsKind{
	{"traffic", "request composition (challenged / passed / bypassed / ...)", statsTraffic},
	{"phase", "challenge events by phase", statsPhase},
	{"verdict", "challenge events by JA4 verdict", statsVerdict},
	{"ip", "top source addresses", statsTopIP},
	{"ua", "top user-agents", statsTopUA},
	{"ja4", "top TLS fingerprints", statsTopJA4},
}

type statsOpts struct {
	minutes int
	site    string
	limit   int
}

func cmdStats(args []string) error {
	fs := flag.NewFlagSet("stats", flag.ExitOnError)
	configPath := fs.String("config", "", "path to config.yml")
	kind := fs.String("kind", "traffic", "what to report: "+statsKindList()+", or all")
	since := fs.String("since", "24h", "lookback window (e.g. 90m, 24h, 7d)")
	site := fs.String("site", "", "filter by site id (empty = every site)")
	limit := fs.Int("limit", 20, "rows to print for the ranking reports")
	tsv := fs.Bool("tsv", false, "tab-separated output for scripts (no headings, no alignment)")
	timeout := fs.Duration("timeout", 60*time.Second, "give up on a query after this long")
	_ = fs.Parse(args)

	minutes, err := parseLookback(*since)
	if err != nil {
		return err
	}
	chosen, err := selectStatsKinds(*kind)
	if err != nil {
		return err
	}
	if *limit < 1 {
		*limit = 1
	}

	s, err := loadSettings(*configPath)
	if err != nil {
		return err
	}
	conn, err := db.Open(s.DB)
	if err != nil {
		return err
	}
	defer conn.Close()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	out := &statsWriter{w: os.Stdout, tsv: *tsv}
	opts := statsOpts{minutes: minutes, site: *site, limit: *limit}

	if !*tsv {
		scope := "every site"
		if *site != "" {
			scope = *site
		}
		fmt.Fprintf(os.Stdout, "window: last %s (until now, UTC)   site: %s\n", *since, scope)
	}
	for i, k := range chosen {
		if !*tsv && i > 0 {
			fmt.Fprintln(os.Stdout)
		}
		if err := k.run(ctx, out, conn, opts); err != nil {
			// A timeout mid-report must say so.  Printing the partial rows and
			// stopping would read as "that is all there was".
			if errors.Is(err, context.DeadlineExceeded) {
				return fmt.Errorf("%s: gave up after %s -- narrow the window with -since, or raise -timeout", k.name, *timeout)
			}
			return fmt.Errorf("%s: %w", k.name, err)
		}
	}
	return nil
}

// --- reports ---------------------------------------------------------------

func statsTraffic(ctx context.Context, out *statsWriter, conn *db.DB, o statsOpts) error {
	c, err := dashboard.TrafficRequests(ctx, conn, o.minutes, o.site)
	if err != nil {
		return err
	}
	out.section("traffic", "requests, from the access-log counters", "kind", "requests", "share")
	if !c.OK {
		out.note("no counter data in this window -- the access-log feed is off, or nothing was served")
		out.end()
		return nil
	}
	// Named buckets first, then the remainder.  Unchallenged is already the
	// by-subtraction bucket, so it is not recomputed here.
	for _, r := range []struct {
		name string
		n    int
	}{
		{"total", c.Total},
		{"challenged", c.Challenged},
		{"passed_with_cookie", c.Passed},
		{"pow_cookie", c.PowPass},
		{"captcha_cookie", c.CaptchaPass},
		{"rebound", c.Rebound},
		{"crawler_pass", c.Benign},
		{"bypass_pass", c.Bypassed},
		{"passthrough", c.Passthrough},
		{"unchallenged", c.Unchallenged},
	} {
		out.row("traffic", r.name, itoa(r.n), share(r.n, c.Total))
	}
	out.end()
	return nil
}

func statsPhase(ctx context.Context, out *statsWriter, conn *db.DB, o statsOpts) error {
	return groupedEventCount(ctx, out, conn, o, "phase", "phase", "challenge events by phase")
}

func statsVerdict(ctx context.Context, out *statsWriter, conn *db.DB, o statsOpts) error {
	return groupedEventCount(ctx, out, conn, o, "COALESCE(NULLIF(ja4_verdict,''),'(none)')", "verdict", "challenge events by JA4 verdict")
}

// groupedEventCount counts unmask_event over the window, grouped by one
// low-cardinality column.  Raw SQL rather than the ORM, matching the rest of
// the aggregate layer; the site comes in bound, not interpolated.
func groupedEventCount(ctx context.Context, out *statsWriter, conn *db.DB, o statsOpts, expr, label, desc string) error {
	cond, args := statsSiteCond(o.site)
	stmt := fmt.Sprintf(`
        SELECT %s AS k, COUNT(*) AS c
        FROM unmask_event
        WHERE date_created > %s%s
        GROUP BY k
        ORDER BY c DESC`,
		expr, conn.NowMinusMinutes(o.minutes), cond)
	rows, err := conn.QueryContext(ctx, stmt, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	type kv struct {
		k string
		c int
	}
	var all []kv
	total := 0
	for rows.Next() {
		var r kv
		if err := rows.Scan(&r.k, &r.c); err != nil {
			return err
		}
		all = append(all, r)
		total += r.c
	}
	if err := rows.Err(); err != nil {
		return err
	}

	out.section(label, desc, label, "events", "share")
	if len(all) == 0 {
		out.note("no events in this window")
	}
	for _, r := range all {
		out.row(label, r.k, itoa(r.c), share(r.c, total))
	}
	out.end()
	return nil
}

// The three rankings go through the events package rather than SQL written
// here: it unpacks the binary-stored ip_address into something readable, and
// it carries the date-index hint (plus the fallback for a database whose
// index is missing) that keeps these from scanning the whole event table.
func statsTopIP(ctx context.Context, out *statsWriter, conn *db.DB, o statsOpts) error {
	rows, err := events.RankByIP(ctx, conn, o.minutes, o.limit, o.site)
	if err != nil {
		return err
	}
	return rankReport(out, "ip", "top source addresses by event count", "address", rows, o.limit)
}

func statsTopUA(ctx context.Context, out *statsWriter, conn *db.DB, o statsOpts) error {
	rows, err := events.RankByUA(ctx, conn, o.minutes, o.limit, o.site)
	if err != nil {
		return err
	}
	return rankReport(out, "ua", "top user-agents by event count", "user-agent", rows, o.limit)
}

func statsTopJA4(ctx context.Context, out *statsWriter, conn *db.DB, o statsOpts) error {
	rows, err := events.RankByJA4(ctx, conn, o.minutes, o.limit, o.site)
	if err != nil {
		return err
	}
	return rankReport(out, "ja4", "top TLS fingerprints by event count", "ja4", rows, o.limit)
}

// rankReport prints a Key/Count ranking.
func rankReport(out *statsWriter, name, desc, keyCol string, rows []events.RankRow, limit int) error {
	out.section(name, desc, keyCol, "events", "")
	if len(rows) == 0 {
		out.note("no events in this window")
	}
	for _, r := range rows {
		out.row(name, r.Key, itoa(r.Count), "")
	}
	if len(rows) == limit {
		out.note(fmt.Sprintf("cut off at -limit %d; there may be more", limit))
	}
	out.end()
	return nil
}

// --- output ----------------------------------------------------------------

// statsWriter renders either an aligned table for a human or one flat
// tab-separated record per line for a script.  The TSV form leads with the
// report name so `-kind all -tsv` stays parseable as a single stream.
type statsWriter struct {
	w    io.Writer
	tsv  bool
	tw   *tabwriter.Writer
	cols int
}

func (s *statsWriter) section(name, desc string, headings ...string) {
	if s.tsv {
		return
	}
	fmt.Fprintf(s.w, "\n== %s -- %s ==\n", name, desc)
	s.tw = tabwriter.NewWriter(s.w, 0, 0, 2, ' ', 0)
	var kept []string
	for _, h := range headings {
		if h != "" {
			kept = append(kept, h)
		}
	}
	s.cols = len(kept)
	fmt.Fprintln(s.tw, strings.Join(kept, "\t"))
}

func (s *statsWriter) row(name string, cells ...string) {
	if s.tsv {
		fmt.Fprintln(s.w, name+"\t"+strings.Join(trimTrailingEmpty(cells), "\t"))
		return
	}
	kept := trimTrailingEmpty(cells)
	for len(kept) < s.cols {
		kept = append(kept, "")
	}
	fmt.Fprintln(s.tw, strings.Join(kept[:s.cols], "\t"))
}

// note is commentary, not data: it goes to stderr under -tsv so it cannot be
// mistaken for a record by whatever is parsing stdout.
func (s *statsWriter) note(msg string) {
	if s.tsv {
		fmt.Fprintln(os.Stderr, "note: "+msg)
		return
	}
	fmt.Fprintln(s.tw, "("+msg+")")
}

func (s *statsWriter) end() {
	if s.tsv || s.tw == nil {
		return
	}
	_ = s.tw.Flush()
	s.tw = nil
}

func trimTrailingEmpty(in []string) []string {
	for len(in) > 0 && in[len(in)-1] == "" {
		in = in[:len(in)-1]
	}
	return in
}

// --- helpers ---------------------------------------------------------------

func statsKindList() string {
	names := make([]string, 0, len(statsKinds))
	for _, k := range statsKinds {
		names = append(names, k.name)
	}
	return strings.Join(names, " / ")
}

func selectStatsKinds(kind string) ([]statsKind, error) {
	if kind == "all" {
		return statsKinds, nil
	}
	for _, k := range statsKinds {
		if k.name == kind {
			return []statsKind{k}, nil
		}
	}
	return nil, fmt.Errorf("unknown -kind %q: pick one of %s, or all", kind, statsKindList())
}

// parseLookback accepts Go durations plus a day suffix, because a week is the
// window an operator actually asks for and time.ParseDuration has no 'd'.
func parseLookback(s string) (int, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, errors.New("-since is empty")
	}
	if rest, ok := strings.CutSuffix(s, "d"); ok {
		days, err := strconv.Atoi(rest)
		if err != nil || days <= 0 {
			return 0, fmt.Errorf("bad -since %q: expected something like 7d", s)
		}
		return days * 24 * 60, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("bad -since %q: expected something like 90m, 24h or 7d", s)
	}
	if d <= 0 {
		return 0, fmt.Errorf("bad -since %q: must be positive", s)
	}
	mins := int(d / time.Minute)
	if mins < 1 {
		mins = 1
	}
	return mins, nil
}

// statsSiteCond returns the optional site predicate plus the value to bind.
// Bound rather than interpolated: -site is a string off the command line, and
// there is no reason for it to reach the statement text.
func statsSiteCond(site string) (string, []any) {
	if site == "" {
		return "", nil
	}
	return " AND site = ?", []any{site}
}

func itoa(n int) string { return strconv.Itoa(n) }

// share renders n as a percentage of total.  Empty when there is no total to
// divide by -- "0.0%" would be a claim we cannot make.
func share(n, total int) string {
	if total <= 0 {
		return ""
	}
	return fmt.Sprintf("%.1f%%", float64(n)*100/float64(total))
}
