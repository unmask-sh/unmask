// Package dashboard: aggregation queries for the dashboard.
//
// Layout: 1) funnel (per verdict) 2) cookie passage 3) flags distribution
// 4) JA4 verdict distribution 5) JA4 hit verdict 6) reload loop 7) CAPTCHA fail IP
// 8) cookie_set_ok=false 9) stealth bypass 10) JS error 11) 30-day trend.
package dashboard

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// BotVerdictNames: collects all verdict names with action=bot or suspect from
// settings. Combines preset (= all, including disabled) and extra rules (= same)
// into a deduped list.
//
// Use: building `ja4_verdict IN (?, ?, ...)` SQL + classify fast lookup (= map).
//
// "Includes disabled" because we aggregate historical events. Even after a user
// disables a verdict, past events were recorded with that verdict name and
// should still count as bot.
func BotVerdictNames(n settings.Nginx) []string {
	seen := map[string]bool{}
	for _, g := range nginxconf.JA4VerdictGroups {
		for _, rule := range g.Rules {
			if nginxconf.IsBotAction(rule.Action) {
				seen[rule.Verdict] = true
			}
		}
	}
	for _, p := range n.JA4Verdicts.Extra {
		if nginxconf.IsBotAction(p.Action) {
			seen[p.Verdict] = true
		}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// BotVerdictSet: set form of the same list. For classify cache lookup.
func BotVerdictSet(n settings.Nginx) map[string]bool {
	out := map[string]bool{}
	for _, v := range BotVerdictNames(n) {
		out[v] = true
	}
	return out
}

// inClause: helper to build `IN (?, ?, ...)`. Also appends values to args slice.
// Empty list returns "IN (”)" (= no match). Dialect-independent.
func inClause(values []string) (string, []any) {
	if len(values) == 0 {
		return "IN ('')", nil
	}
	placeholders := make([]string, len(values))
	args := make([]any, len(values))
	for i, v := range values {
		placeholders[i] = "?"
		args[i] = v
	}
	return "IN (" + strings.Join(placeholders, ",") + ")", args
}

// inClauseInt: `IN (?, ?, ...)` for an int slice. Used for ID-based linking.
// Empty list returns "IN (-1)" (= no match; -1 is never used as an ID).
func inClauseInt(values []int) (string, []any) {
	if len(values) == 0 {
		return "IN (-1)", nil
	}
	placeholders := make([]string, len(values))
	args := make([]any, len(values))
	for i, v := range values {
		placeholders[i] = "?"
		args[i] = v
	}
	return "IN (" + strings.Join(placeholders, ",") + ")", args
}

// parseDateTimeToUnix: converts a SQLite/MariaDB datetime string
// ("2006-01-02 15:04:05" UTC) to unix seconds. Returns 0 for parse error / empty.
//
// Use: lets the template reformat LastSeen-style columns in browser TZ by
// passing <time class="js-datetime" data-ts="<unix>">.
func parseDateTimeToUnix(s string) int64 {
	if s == "" {
		return 0
	}
	// Accept the millisecond ingest format ("2006-01-02 15:04:05.000"), the
	// legacy second-precision format and RFC3339.  Treat as UTC when no TZ
	// info is present (= timestamps are stamped in UTC).
	for _, layout := range []string{
		"2006-01-02 15:04:05.000",
		"2006-01-02T15:04:05.000Z",
		"2006-01-02 15:04:05",
		"2006-01-02T15:04:05Z",
		time.RFC3339,
	} {
		if t, err := time.Parse(layout, s); err == nil {
			return t.Unix()
		}
	}
	return 0
}

// Range accepts 1d / 7d / 30d. Invalid input falls back to 1d.
func RangeHours(s string) int {
	switch s {
	case "7d":
		return 24 * 7
	case "30d":
		return 24 * 30
	case "90d":
		return 24 * 90
	case "180d":
		return 24 * 180
	case "365d", "all":
		// "all" resolves to [oldest event, now] via the ctx window; this is only
		// its fallback span when the oldest timestamp is unavailable.
		return 24 * 365
	default:
		return 24
	}
}

// siteCond returns "AND site = '<site>'" if site is non-empty.
// Empty string → "" (= aggregate across all sites).
//
// SQL injection guard: caller must validate site (= [a-z0-9-]{1,32}) before
// passing in. handlers.pickSite gates with a regex so this concatenates literally.
// siteValRE: allowed chars for a site filter value (= a normalized request
// Host).  Embedded into SQL literally, so restrict to hostname-safe chars
// (alnum . - _ and : for IPv6 literals).  See hostValRE.
var siteValRE = regexp.MustCompile(`^[a-z0-9.:_-]+$`)

// siteCond: SQL fragment for the single-select site filter.  "" or the
// "default" sentinel means "all sites" (= the dashboard's unfiltered view; a
// real per-vhost site never equals "default" after normalizeSite).  A value
// failing siteValRE is ignored (= SQL injection guard, mirrors hostCond).
func siteCond(site string) string {
	if site == "" || site == "default" {
		return ""
	}
	if !siteValRE.MatchString(site) {
		return ""
	}
	return " AND site = '" + site + "'"
}

// hostValRE: allowed chars for host filter values (= hostname / host id). Since
// it is embedded into SQL literally, restrict strictly to alnum + ._- only.
// Values containing anything else are ignored in hostCond (= SQL injection guard).
var hostValRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// disabledHosts holds the SQL-quoted, charset-validated host ids excluded from
// every aggregation query (= retired / mis-configured instances, from
// settings.Hosts.Disabled).  Set via SetDisabledHosts; read by hostCond.
var (
	disabledHostsMu sync.RWMutex
	disabledHosts   []string
)

// SetDisabledHosts hot-swaps the list of host ids excluded from aggregation.
// Called on startup and after the host inventory toggle saves; applied by
// hostCond on the next query.  Ids failing the charset guard are dropped.
func SetDisabledHosts(hosts []string) {
	q := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if hostValRE.MatchString(h) {
			q = append(q, "'"+h+"'")
		}
	}
	disabledHostsMu.Lock()
	disabledHosts = q
	disabledHostsMu.Unlock()
}

// hostCond: SQL fragment for the host multi-select filter. Returns "" if empty
// or all-invalid (= all hosts). unmask_event has a host column (= identifies
// machine of origin in shared DB). Note: unmask_cookie_minute lacks a host
// column, so the host filter has no effect on CookieStatus / DailyPassByDay
// (= they remain aggregated across all hosts).
//
// Disabled hosts (= SetDisabledHosts) are always excluded with an extra
// "host NOT IN (...)" so a retired / mis-configured instance drops out of
// every aggregation regardless of the picker selection.
func hostCond(hosts []string) string {
	valid := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if hostValRE.MatchString(h) {
			valid = append(valid, "'"+h+"'")
		}
	}
	cond := ""
	if len(valid) > 0 {
		cond = " AND host IN (" + strings.Join(valid, ",") + ")"
	}
	disabledHostsMu.RLock()
	dh := disabledHosts
	disabledHostsMu.RUnlock()
	if len(dh) > 0 {
		cond += " AND host NOT IN (" + strings.Join(dh, ",") + ")"
	}
	return cond
}

// SiteSummary: per-site summary for the /admin/ index.
type SiteSummary struct {
	Site       string
	Events     int
	Serve      int
	Verify     int
	UniqIP     int
	LastSeen   string
	LastSeenTS int64 // unix sec UTC; template emits <time class="js-datetime" data-ts="..."> and JS formats it in browser TZ
}

// Sites returns one row per distinct site observed in the last `hours` hours,
// plus 'default' even if no events.  The hourly aggregate (= bucket_kinds
// hkSiteAll / hkSiteServe / hkSiteBV / hkSiteIP) supplies all counts when
// available; the raw scan stays as a fallback for the brief window after a
// fresh start before AggregateHourly has run to completion.
func Sites(ctx context.Context, d *db.DB, hours int) ([]SiteSummary, error) {
	if HourlyAggReady() {
		return sitesAgg(ctx, d, hours)
	}
	return sitesScan(ctx, d, hours)
}

// sitesAgg reads SiteSummary from unmask_aggregate_hourly + unmask_aggregate_hll.
// O(buckets * sites) -> stable a few hundred rows even on 30d / multi-site
// installs, vs the raw GROUP BY site that scales with the event table.
func sitesAgg(ctx context.Context, d *db.DB, hours int) ([]SiteSummary, error) {
	by := map[string]SiteSummary{}

	// plain counts: total / serve / passed per site over the hour window.
	// >= matches the funnel / country aggregate readers: hourAgoExpr names
	// the boundary bucket (= the one covering 'now - hours'), so the bucket
	// itself must be included or the count is short by one hour.
	cntStmt := fmt.Sprintf(`
        SELECT bucket_kind, bucket_key, SUM(cnt) AS c, MAX(bucket_hour) AS last_hour
        FROM unmask_aggregate_hourly
        WHERE %s
          AND bucket_kind IN ('%s','%s','%s')
        GROUP BY bucket_kind, bucket_key`,
		hourWindow(ctx, hours, "bucket_hour"), hkSiteAll, hkSiteServe, hkSiteBV)
	rows, err := d.QueryContext(ctx, cntStmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var kind, site string
		var cnt int64
		var lastHour sql.NullString
		if err := rows.Scan(&kind, &site, &cnt, &lastHour); err != nil {
			return nil, err
		}
		s := by[site]
		s.Site = site
		switch kind {
		case hkSiteAll:
			s.Events = int(cnt)
			// last_hour is 'YYYY-MM-DD HH'; expand to 'YYYY-MM-DD HH:00:00'
			// so the read side / template can parse it the same way as the
			// raw scan's MAX(date_created).
			if lastHour.Valid && lastHour.String != "" {
				s.LastSeen = lastHour.String + ":00:00"
				s.LastSeenTS = parseDateTimeToUnix(s.LastSeen)
			}
		case hkSiteServe:
			s.Serve = int(cnt)
		case hkSiteBV:
			s.Verify = int(cnt)
		}
		by[site] = s
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// distinct IP: HLL union per site over the hour window.  Use the same
	// shape as VerdictDistribution's per-verdict HLL read (= load sketches
	// grouped by key, then estimate in Go).
	hllStmt := fmt.Sprintf(`
        SELECT bucket_key, sketch
        FROM unmask_aggregate_hll
        WHERE %s AND bucket_kind = '%s'`,
		hourWindow(ctx, hours, "bucket"), hkSiteIP)
	hRows, err := d.QueryContext(ctx, hllStmt)
	if err != nil {
		return nil, err
	}
	defer hRows.Close()
	sketches := map[string]*hll{}
	for hRows.Next() {
		var site string
		var blob []byte
		if err := hRows.Scan(&site, &blob); err != nil {
			return nil, err
		}
		h := loadHLL(blob)
		if existing, ok := sketches[site]; ok {
			existing.merge(h)
		} else {
			sketches[site] = h
		}
	}
	if err := hRows.Err(); err != nil {
		return nil, err
	}
	for site, h := range sketches {
		s := by[site]
		s.Site = site
		s.UniqIP = int(h.estimate())
		by[site] = s
	}

	if _, ok := by["default"]; !ok {
		by["default"] = SiteSummary{Site: "default"}
	}
	out := make([]SiteSummary, 0, len(by))
	for _, v := range by {
		out = append(out, v)
	}
	sortSites(out)
	return out, nil
}

// sitesScan is the original raw-event implementation, retained as a fallback
// for the pre-aggregate-ready window after a fresh start.
func sitesScan(ctx context.Context, d *db.DB, hours int) ([]SiteSummary, error) {
	// "passed" = any terminal _bv issuance phase (= sum of all challenge_mode
	// success paths).  Matches the meaning of the old verify_ok counter but
	// covers PoW-only completions too.
	stmt := fmt.Sprintf(`
        SELECT site,
               COUNT(*) AS n,
               SUM(CASE WHEN phase='serve' THEN 1 ELSE 0 END) AS n_serve,
               SUM(CASE WHEN phase IN ('bv_pow_only','bv_captcha_only','bv_pow_then_captcha') THEN 1 ELSE 0 END) AS n_passed,
               COUNT(DISTINCT ip_address) AS uniq,
               MAX(date_created) AS last_seen
        FROM unmask_event
        WHERE %s
        GROUP BY site`, tsWindow(ctx, hours, "date_created"))
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	by := map[string]SiteSummary{}
	for rows.Next() {
		var s SiteSummary
		var serve, verify, uniq sql.NullInt64
		var ls sql.NullString
		if err := rows.Scan(&s.Site, &s.Events, &serve, &verify, &uniq, &ls); err != nil {
			return nil, err
		}
		s.Serve = int(serve.Int64)
		s.Verify = int(verify.Int64)
		s.UniqIP = int(uniq.Int64)
		s.LastSeen = ls.String
		s.LastSeenTS = parseDateTimeToUnix(ls.String)
		by[s.Site] = s
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// "default" always appears in the list
	if _, ok := by["default"]; !ok {
		by["default"] = SiteSummary{Site: "default"}
	}
	out := make([]SiteSummary, 0, len(by))
	for _, v := range by {
		out = append(out, v)
	}
	sortSites(out)
	return out, nil
}

// sortSites: default first, then by event count desc, site name asc.
func sortSites(out []SiteSummary) {
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Site == "default" {
			return true
		}
		if out[j].Site == "default" {
			return false
		}
		if out[i].Events != out[j].Events {
			return out[i].Events > out[j].Events
		}
		return out[i].Site < out[j].Site
	})
}

// HostInfo: one observed unmask instance (= host) for the host inventory.
type HostInfo struct {
	HostID       string
	Events       int
	EventsApprox bool // Events is the O(1) id-range estimate (single-host DB), not an exact COUNT — rendered with "≈"
	LastSeen     string
	LastSeenTS   int64 // unix sec UTC; template renders via <time class="js-datetime">
}

// HostInventory returns one row per distinct host that has ever written to
// unmask_event, most-recently-active first.  Unlike Sites it has no time
// window: a retired instance should still appear (with an old last-seen) so
// the operator can spot stale entries in a shared DB.  Capped at 200.
//
// The old `GROUP BY host` full-scanned the (host, date_created) covering index
// (6.6M rows / ~34s cold on tool1-us — worse now that the pickers no longer
// incidentally warm that index).  SQLite gets the same loose-index-scan
// treatment as the pickers: enumerate hosts with a recursive skip-scan, then
// one index seek per host for last-seen (MAX(date_created) WHERE host=? is an
// idx_unmask_event_host seek, ~4ms).  The only O(rows) part left is the exact
// per-host COUNT of a dominant host, so a single-host DB (the common case)
// uses the O(1) MAX(id)-MIN(id)+1 estimate instead.  MariaDB keeps the plain
// GROUP BY (InnoDB loose-scans it).
func HostInventory(ctx context.Context, d *db.DB) ([]HostInfo, error) {
	if d.Driver != "sqlite" {
		return hostInventoryScan(ctx, d)
	}
	hosts, err := distinctHostsSkipScan(ctx, d, 200)
	if err != nil {
		return nil, err
	}
	singleHost := len(hosts) == 1
	var estTotal int
	if singleHost {
		estTotal = tableRowEstimate(ctx, d)
	}
	out := make([]HostInfo, 0, len(hosts))
	for _, host := range hosts {
		hi := HostInfo{HostID: host}
		var ls sql.NullString
		// MAX(date_created) WHERE host=? -> idx_unmask_event_host seek (last entry
		// of the host's range).  All-time, so a retired host keeps its true
		// last-seen.
		if err := d.QueryRowContext(ctx,
			`SELECT MAX(date_created) FROM unmask_event WHERE host = ?`, host).Scan(&ls); err == nil {
			hi.LastSeen = ls.String
			hi.LastSeenTS = parseDateTimeToUnix(ls.String)
		}
		if singleHost {
			hi.Events = estTotal
			hi.EventsApprox = true
		} else {
			// Multiple hosts: each per-host count seeks the host's index range —
			// fast for the usual balanced fleet.  (A single dominant host among
			// many would still be O(its rows); rare, and a follow-up rollup could
			// cover it.)
			_ = d.QueryRowContext(ctx, `SELECT COUNT(*) FROM unmask_event WHERE host = ?`, host).Scan(&hi.Events)
		}
		out = append(out, hi)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].LastSeenTS > out[j].LastSeenTS
	})
	return out, nil
}

// distinctHostsSkipScan enumerates the distinct non-empty host values via a
// recursive loose index scan (one idx_unmask_event_host seek per value), the
// same technique the host/site pickers use.
func distinctHostsSkipScan(ctx context.Context, d *db.DB, limit int) ([]string, error) {
	rows, err := d.QueryContext(ctx, `WITH RECURSIVE h(v) AS (
    SELECT (SELECT MIN(host) FROM unmask_event WHERE host > '')
    UNION ALL
    SELECT (SELECT MIN(host) FROM unmask_event WHERE host > h.v) FROM h WHERE h.v IS NOT NULL
)
SELECT v FROM h WHERE v IS NOT NULL LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// tableRowEstimate approximates the unmask_event row count from the id range
// (MAX-MIN+1) in two O(1) index-endpoint seeks — near-exact for an append-only,
// pruned-oldest-first table.  Same trick the retention tab uses.
func tableRowEstimate(ctx context.Context, d *db.DB) int {
	var minID, maxID int64
	_ = d.QueryRowContext(ctx, `SELECT COALESCE(MIN(id), 0) FROM unmask_event`).Scan(&minID)
	_ = d.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM unmask_event`).Scan(&maxID)
	if maxID <= 0 {
		return 0
	}
	return int(maxID - minID + 1)
}

// hostInventoryScan is the original GROUP BY implementation, kept for MariaDB
// (InnoDB does a loose index scan for the grouped aggregate).
func hostInventoryScan(ctx context.Context, d *db.DB) ([]HostInfo, error) {
	rows, err := d.QueryContext(ctx, `
        SELECT host, COUNT(*) AS n, MAX(date_created) AS last_seen
        FROM unmask_event
        WHERE host IS NOT NULL AND host != ''
        GROUP BY host
        LIMIT 200`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []HostInfo{}
	for rows.Next() {
		var hi HostInfo
		var ls sql.NullString
		if err := rows.Scan(&hi.HostID, &hi.Events, &ls); err != nil {
			return nil, err
		}
		hi.LastSeen = ls.String
		hi.LastSeenTS = parseDateTimeToUnix(ls.String)
		out = append(out, hi)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.SliceStable(out, func(i, j int) bool {
		return out[i].LastSeenTS > out[j].LastSeenTS
	})
	return out, nil
}

// fixedVerdicts: verdicts always shown even at 0 (= all presets + ok + (none)).
// Preset verdict names are collected dynamically from nginxconf.JA4VerdictGroups
// (= no hardcode). User-added extra-rule verdicts appear on first observed
// traffic, so they are not part of the fixed list.
func fixedVerdicts() []string {
	out := make([]string, 0, 16)
	seen := map[string]bool{}
	for _, g := range nginxconf.JA4VerdictGroups {
		for _, rule := range g.Rules {
			if rule.Verdict == "" || seen[rule.Verdict] {
				continue
			}
			seen[rule.Verdict] = true
			out = append(out, rule.Verdict)
		}
	}
	sort.Strings(out)
	out = append(out, "ok", "(none)")
	return out
}

// keyFlags: representative flags-column values always shown for the load phase.
var keyFlags = []int{0, 1, 2, 4, 8, 16, 3, 5, 9, 17, 31}

// FunnelRow: one row = one verdict (= JA4 verdict + aggregated categories).
//
// Authentication outcome is broken out per challenge_mode so the row answers
// "what path issued _bv?" directly.  Each BV* field name mirrors a
// challenge_mode value, which means adding a new mode in the future maps
// 1:1 to a new column (= no overloaded "chain" bucket).
//
//	BVPowOnly         : _bv issued via challenge_mode=pow_only
//	BVCaptchaOnly     : _bv issued via challenge_mode=captcha_only
//	BVPowThenCaptcha  : _bv issued via challenge_mode=pow_then_captcha
//
// PowPass counts the multi-step midpoint (= PoW solved, still unauthenticated;
// the follow-up stage is in payload.next).  PowSolved / BVTotal are derived
// summaries for chart rendering.
type FunnelRow struct {
	Verdict          string // free label. "ok" / "rate_limit" / "TOTAL" / preset / extra
	Serve            int    // count of challenge HTML deliveries
	ServeRL          int    // serves that came via ?_rl=1 (= rate-limit path)
	Load             int
	LoadUniq         int // unique IPs in the load phase
	Silent           int // = max(0, Serve - Load). Challenge served but JS never started
	Stealth          int // load phase rows with flags=0 + verdict configured as bot/suspect
	PowPass          int // midpoint: PoW solved, handing off to next stage
	Captcha          int // CAPTCHA UI displayed (= still unauthenticated)
	BVPowOnly        int // terminal: _bv issued via challenge_mode=pow_only
	BVCaptchaOnly    int // terminal: _bv issued via challenge_mode=captcha_only
	BVPowThenCaptcha int // terminal: _bv issued via challenge_mode=pow_then_captcha
	VerifyNG         int
	CookieErr        int
	JSError          int
	PowSolved        int     // = BVPowOnly + PowPass (= total PoW pass-through; chart-facing)
	BVTotal          int     // = BVPowOnly + BVCaptchaOnly + BVPowThenCaptcha (= total auth completions; chart-facing)
	CaptchaPassed    int     // = BVCaptchaOnly + BVPowThenCaptcha (= _bv issued after a CAPTCHA was shown; PoW-only is excluded)
	PowRate          float64 // = PowSolved / Load
	CaptchaRate      float64 // = Captcha / Load
}

// Funnel returns one row per verdict in the fixed list plus a rate_limit row
// (= IP-joined for serves where payload.rl=1) and a TOTAL row.
//
// botVerdicts is the list of verdict names configured as action=bot or suspect
// in settings (= preset + extra merged). Used for stealth-count classification.
// An empty list disables the stealth concept (stealth=0 is always emitted).
// funnelVP / funnelLoad are the intermediate aggregation maps shared by
// Funnel's scan and aggregate paths.
type funnelVP struct{ verdict, phase string }
type funnelLoad struct{ uniq, stealth int }

// canonVerdict normalizes a verdict for ID-based linking: a known ID snaps to
// the current preset name (= reflects renames); unknown IDs (= NULL / 0) fall
// back to a registry name lookup and then the raw name. This merges pre- and
// post-rename events sharing one ID into a single group.
func canonVerdict(reg *nginxconf.VerdictRegistry, id int64, raw string) string {
	if reg != nil {
		if id > 0 {
			if cur := reg.IDToVerdict(int(id)); cur != "" {
				return cur
			}
		}
		if raw != "" {
			if regID := reg.NameToID(raw); regID > 0 {
				if cur := reg.IDToVerdict(regID); cur != "" {
					return cur
				}
			}
		}
	}
	return raw
}

// Funnel returns the challenge funnel for the window. The default view (no
// site / no host filter) reads the hourly aggregate (unmask_aggregate_hourly);
// site/host-filtered views and the brief pre-backfill window after a restart
// fall back to scanning raw events.
func Funnel(ctx context.Context, d *db.DB, site string, hosts []string, hours int, botVerdicts []string, reg *nginxconf.VerdictRegistry) ([]FunnelRow, error) {
	if site == "" && len(hosts) == 0 && HourlyAggReady() {
		return funnelAgg(ctx, d, hours, botVerdicts, reg)
	}
	return funnelScan(ctx, d, site, hosts, hours, botVerdicts, reg)
}

// funnelScan builds the funnel by scanning raw unmask_event. Used for
// site/host-filtered views, which the hourly aggregate deliberately does not
// dimension.
func funnelScan(ctx context.Context, d *db.DB, site string, hosts []string, hours int, botVerdicts []string, reg *nginxconf.VerdictRegistry) ([]FunnelRow, error) {
	since := tsWindow(ctx, hours, "date_created")
	sc := siteCond(site) + hostCond(hosts)

	// A) base aggregation by verdict × phase. SELECT id too so canon can use it.
	rows, err := d.QueryContext(ctx, fmt.Sprintf(`
        SELECT COALESCE(ja4_verdict, '(none)') AS v, ja4_verdict_id AS vid, phase, COUNT(*) AS n
        FROM unmask_event WHERE %s%s
        GROUP BY ja4_verdict, ja4_verdict_id, phase`, since, sc))
	if err != nil {
		return nil, err
	}
	byVP := map[funnelVP]int{}
	for rows.Next() {
		var v, p string
		var vid sql.NullInt64
		var n int
		if err := rows.Scan(&v, &vid, &p, &n); err != nil {
			rows.Close()
			return nil, err
		}
		byVP[funnelVP{canonVerdict(reg, vid.Int64, v), p}] += n
	}
	rows.Close()

	// B) uniq IP + stealth (= flags=0 + verdict configured as bot/suspect) for
	// verdict × phase=load. Stealth detection is ID-based; falls back to
	// name-based if the bot ID list is empty.
	var botFilter string
	var botFilterArgs []any
	if reg != nil {
		botFilter, botFilterArgs = inClauseInt(reg.BotIDs())
		botFilter = "ja4_verdict_id " + botFilter
	} else {
		nameIn, nameArgs := inClause(botVerdicts)
		botFilter = "ja4_verdict " + nameIn
		botFilterArgs = nameArgs
	}
	rows2, err := d.QueryContext(ctx, fmt.Sprintf(`
        SELECT COALESCE(ja4_verdict, '(none)') AS v, ja4_verdict_id AS vid,
               COUNT(DISTINCT ip_address) AS uniq_ip,
               SUM(CASE WHEN flags = 0 AND %s THEN 1 ELSE 0 END) AS stealth
        FROM unmask_event WHERE %s%s AND phase = 'load'
        GROUP BY ja4_verdict, ja4_verdict_id`, botFilter, since, sc), botFilterArgs...)
	if err != nil {
		return nil, err
	}
	loadByV := map[string]funnelLoad{}
	for rows2.Next() {
		var v string
		var vid, u, st sql.NullInt64
		if err := rows2.Scan(&v, &vid, &u, &st); err != nil {
			rows2.Close()
			return nil, err
		}
		k := canonVerdict(reg, vid.Int64, v)
		ex := loadByV[k]
		// Strictly, uniq IP should be re-computed with COUNT(DISTINCT) on the DB
		// side to avoid duplicates, but this approximation is good enough for the
		// rename-merge case (= unlikely the same IP hits both old and new names).
		loadByV[k] = funnelLoad{ex.uniq + int(u.Int64), ex.stealth + int(st.Int64)}
	}
	rows2.Close()

	// C) per-verdict counts where phase=serve and payload.rl=1
	jsonRL := jsonExtract(d, "payload_json", "$.rl")
	rows3, err := d.QueryContext(ctx, fmt.Sprintf(`
        SELECT COALESCE(ja4_verdict, '(none)') AS v, ja4_verdict_id AS vid,
               SUM(CASE WHEN %s IN ('1', 1) THEN 1 ELSE 0 END) AS rl
        FROM unmask_event WHERE %s%s AND phase = 'serve'
        GROUP BY ja4_verdict, ja4_verdict_id`, jsonRL, since, sc))
	if err != nil {
		return nil, err
	}
	rlByV := map[string]int{}
	for rows3.Next() {
		var v string
		var vid, n sql.NullInt64
		if err := rows3.Scan(&v, &vid, &n); err != nil {
			rows3.Close()
			return nil, err
		}
		rlByV[canonVerdict(reg, vid.Int64, v)] += int(n.Int64)
	}
	rows3.Close()

	return buildFunnelRows(ctx, d, site, hosts, since, byVP, loadByV, rlByV, botVerdicts)
}

// funnelAgg builds the funnel from unmask_aggregate_hourly. The verdict×phase
// counts and the stealth / rate-limit-serve sums are summed from the hourly
// buckets; only the per-verdict distinct-IP figures (not summable across
// buckets) are read raw — cheap, as they are phase=load filtered. Used for the
// default no-filter view.
func funnelAgg(ctx context.Context, d *db.DB, hours int, botVerdicts []string, reg *nginxconf.VerdictRegistry) ([]FunnelRow, error) {
	// bot test mirrors funnelScan's botFilter: id-based when a registry is
	// present, else name-based.
	botID := map[int]bool{}
	if reg != nil {
		for _, id := range reg.BotIDs() {
			botID[id] = true
		}
	}
	botName := map[string]bool{}
	for _, v := range botVerdicts {
		botName[v] = true
	}
	isBot := func(vid int, verdict string) bool {
		if reg != nil {
			return botID[vid]
		}
		return botName[verdict]
	}

	byVP := map[funnelVP]int{}
	loadByV := map[string]funnelLoad{}
	rlByV := map[string]int{}

	rows, err := d.QueryContext(ctx, `
        SELECT bucket_kind, bucket_key, cnt FROM unmask_aggregate_hourly
        WHERE `+hourWindow(ctx, hours, "bucket_hour")+`
          AND bucket_kind IN ('fnl', 'lf0', 'srl')`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var kind, key string
		var cnt int
		if err := rows.Scan(&kind, &key, &cnt); err != nil {
			rows.Close()
			return nil, err
		}
		switch kind {
		case hkFunnel:
			vid, verdict, phase, ok := splitFnlKey(key)
			if !ok {
				continue
			}
			byVP[funnelVP{canonVerdict(reg, int64(vid), verdict), phase}] += cnt
		case hkLoadF0:
			vid, verdict, ok := splitVVKey(key)
			if ok && isBot(vid, verdict) {
				k := canonVerdict(reg, int64(vid), verdict)
				e := loadByV[k]
				e.stealth += cnt
				loadByV[k] = e
			}
		case hkServeRL:
			if vid, verdict, ok := splitVVKey(key); ok {
				rlByV[canonVerdict(reg, int64(vid), verdict)] += cnt
			}
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	// per-verdict distinct IP for phase=load: HLL merge across the hour
	// buckets, then estimate per-key.  The same sketches feed the TOTAL row's
	// LoadUniq via a single union pass.  No raw scan in the agg path.
	// since is consumed by buildFunnelRowsWithUniq / rateLimitFunnelRow as a
	// full date_created predicate.  Keep the hour-aligned bound (hourAgoTimestamp)
	// so the raw rate-limit row covers the same boundary as the hourWindow agg
	// buckets above; tsWindow's exact-second bound would desync the two.
	since := "date_created > " + hourAgoTimestamp(d, hours)
	sRows, err := d.QueryContext(ctx, `
        SELECT bucket_key, sketch FROM unmask_aggregate_hll
        WHERE `+hourWindow(ctx, hours, "bucket")+`
          AND bucket_kind = '`+hkLoadVerdictIP+`'`)
	if err != nil {
		return nil, err
	}
	sketches := map[string]*hll{}
	for sRows.Next() {
		var verdict string
		var blob []byte
		if err := sRows.Scan(&verdict, &blob); err != nil {
			sRows.Close()
			return nil, err
		}
		h := loadHLL(blob)
		if existing, ok := sketches[verdict]; ok {
			existing.merge(h)
		} else {
			sketches[verdict] = h
		}
	}
	if err := sRows.Err(); err != nil {
		sRows.Close()
		return nil, err
	}
	sRows.Close()
	// per-verdict estimate → loadByV.uniq; total union → totalUniqOverride.
	totalSketch := &hll{}
	for v, h := range sketches {
		k := canonVerdict(reg, 0, v)
		e := loadByV[k]
		e.uniq += int(h.estimate())
		loadByV[k] = e
		totalSketch.merge(h)
	}
	totalUniq := int(totalSketch.estimate())

	// rate-limit row skip gate: when the aggregate already accumulates zero
	// rate-limited serves in the window, the row would be empty -- skip it.
	var rlTotal int64
	_ = d.QueryRowContext(ctx, `
        SELECT COALESCE(SUM(cnt), 0) FROM unmask_aggregate_hourly
        WHERE bucket_kind = '`+hkServeRL+`' AND `+hourWindow(ctx, hours, "bucket_hour")).Scan(&rlTotal)

	// Prefer the hourly rate-limit-funnel rollup (settled hours) + a short raw
	// tail over the per-IP self-join scan of the whole window.  Fall back to that
	// scan only until the rollup has completed its first pass (rolled == false).
	rlRow, rolled, err := rateLimitFunnelRowAgg(ctx, d, hours, botVerdicts)
	if err != nil {
		return nil, err
	}
	if rolled || rlTotal == 0 {
		rows, err := buildFunnelRowsWithUniq(ctx, d, "", nil, since, byVP, loadByV, rlByV, botVerdicts, &totalUniq, true)
		if err != nil {
			return nil, err
		}
		// header/asn/geo pseudo-rows from the frf aggregate (skipRateLimitRow=true
		// above meant buildFunnelRowsWithUniq did not add the scan-path ones).
		if frRows, err := forceReasonFunnelRowsAgg(ctx, d, hours); err == nil {
			rows = append(frRows, rows...)
		}
		if rolled && rlTotal > 0 {
			rows = append([]FunnelRow{rlRow}, rows...)
		}
		return rows, nil
	}
	// Not rolled yet and there are rate-limited serves: raw scan (pre-rollup only).
	return buildFunnelRowsWithUniq(ctx, d, "", nil, since, byVP, loadByV, rlByV, botVerdicts, &totalUniq, false)
}

// forceReasonFunnelRowsScan builds the header/asn/geo funnel pseudo-rows by
// scanning raw events (site/host-filtered views + the pre-rollup fallback).
// force_reason rides every phase beacon, so a plain force_reason x phase
// group-by reconstructs each axis's serve->load->pass chain -- no IP-window
// correlation (the rate_limit row needs that only because "rate-limited" is not
// a per-event flag).  `since` is a raw date_created predicate; empty axes are
// omitted.
func forceReasonFunnelRowsScan(ctx context.Context, d *db.DB, site string, hosts []string, since string) ([]FunnelRow, error) {
	reasonExpr := jsonExtract(d, "payload_json", "$.force_reason")
	stmt := fmt.Sprintf(`
        SELECT %s AS fr, phase, COUNT(*) AS n
        FROM unmask_event
        WHERE %s%s AND %s IN (%s)
        GROUP BY fr, phase`, reasonExpr, since, siteCond(site)+hostCond(hosts), reasonExpr, forceReasonFunnelInList())
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byRP := map[string]map[string]int{}
	for rows.Next() {
		var fr, phase string
		var n int
		if err := rows.Scan(&fr, &phase, &n); err != nil {
			return nil, err
		}
		if byRP[fr] == nil {
			byRP[fr] = map[string]int{}
		}
		byRP[fr][phase] += n
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return forceReasonRowsFromPhaseMaps(byRP), nil
}

// forceReasonFunnelRowsAgg builds the header/asn/geo funnel rows from the hourly
// frf aggregate (install-wide default view).  key = '<reason>|<phase>'.
func forceReasonFunnelRowsAgg(ctx context.Context, d *db.DB, hours int) ([]FunnelRow, error) {
	rows, err := d.QueryContext(ctx, `
        SELECT bucket_key, cnt FROM unmask_aggregate_hourly
        WHERE `+hourWindow(ctx, hours, "bucket_hour")+`
          AND bucket_kind = '`+hkForceFunnel+`'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	byRP := map[string]map[string]int{}
	for rows.Next() {
		var key string
		var cnt int
		if err := rows.Scan(&key, &cnt); err != nil {
			return nil, err
		}
		i := strings.IndexByte(key, '|')
		if i < 0 {
			continue
		}
		reason, phase := key[:i], key[i+1:]
		if byRP[reason] == nil {
			byRP[reason] = map[string]int{}
		}
		byRP[reason][phase] += cnt
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return forceReasonRowsFromPhaseMaps(byRP), nil
}

// buildFunnelRows turns the per-verdict aggregation maps into ordered
// FunnelRows: the rate_limit pseudo-row, the verdict rows in fixed order, then
// the TOTAL row. The rate-limit row and the total distinct-IP count are read
// raw from unmask_event over `since` (a SQL datetime expression); both Funnel
// paths supply a window-consistent `since`.
// buildFunnelRows is the scan-path entry point: it queries TOTAL distinct IP
// raw.  Agg-path callers should use buildFunnelRowsWithUniq so the LoadUniq
// piece can be sourced from a pre-computed HLL merge instead.
func buildFunnelRows(ctx context.Context, d *db.DB, site string, hosts []string, since string, byVP map[funnelVP]int, loadByV map[string]funnelLoad, rlByV map[string]int, botVerdicts []string) ([]FunnelRow, error) {
	return buildFunnelRowsWithUniq(ctx, d, site, hosts, since, byVP, loadByV, rlByV, botVerdicts, nil, false)
}

func buildFunnelRowsWithUniq(ctx context.Context, d *db.DB, site string, hosts []string, since string, byVP map[funnelVP]int, loadByV map[string]funnelLoad, rlByV map[string]int, botVerdicts []string, totalLoadUniq *int, skipRateLimitRow bool) ([]FunnelRow, error) {
	// D) verdict list = fixed-list order + unknown verdicts seen in the DB
	// (= appended in name order). The fixed list is all presets + ok + (none).
	// User extra-rule verdicts are added via seenInDB when first observed.
	seen := map[string]bool{}
	order := fixedVerdicts()
	for _, v := range order {
		seen[v] = true
	}
	var unknown []string
	for k := range byVP {
		if !seen[k.verdict] {
			seen[k.verdict] = true
			unknown = append(unknown, k.verdict)
		}
	}
	sort.Strings(unknown)
	order = append(order, unknown...)

	// "ok" (= normal traffic, no bot/suspect rule matched) always reads last
	// among the verdict rows, below every bot / suspect / unknown verdict.
	{
		reordered := make([]string, 0, len(order))
		for _, v := range order {
			if v != "ok" {
				reordered = append(reordered, v)
			}
		}
		order = append(reordered, "ok")
	}

	var out []FunnelRow
	total := FunnelRow{Verdict: "TOTAL"}
	for _, v := range order {
		row := FunnelRow{
			Verdict:          v,
			Serve:            byVP[funnelVP{v, "serve"}],
			ServeRL:          rlByV[v],
			Load:             byVP[funnelVP{v, "load"}],
			LoadUniq:         loadByV[v].uniq,
			Stealth:          loadByV[v].stealth,
			PowPass:          byVP[funnelVP{v, "pow_pass"}],
			Captcha:          byVP[funnelVP{v, "captcha"}],
			BVPowOnly:        byVP[funnelVP{v, "bv_pow_only"}],
			BVCaptchaOnly:    byVP[funnelVP{v, "bv_captcha_only"}],
			BVPowThenCaptcha: byVP[funnelVP{v, "bv_pow_then_captcha"}],
			VerifyNG:         byVP[funnelVP{v, "verify_ng"}],
			CookieErr:        byVP[funnelVP{v, "cookie_err"}],
			JSError:          byVP[funnelVP{v, "error"}],
		}
		if row.Serve > row.Load {
			row.Silent = row.Serve - row.Load
		}
		row.PowSolved = row.BVPowOnly + row.PowPass
		row.BVTotal = row.BVPowOnly + row.BVCaptchaOnly + row.BVPowThenCaptcha
		row.CaptchaPassed = row.BVCaptchaOnly + row.BVPowThenCaptcha
		if row.Load > 0 {
			row.PowRate = float64(row.PowSolved) / float64(row.Load)
			row.CaptchaRate = float64(row.Captcha) / float64(row.Load)
		}
		total.Serve += row.Serve
		total.ServeRL += row.ServeRL
		total.Load += row.Load
		total.Silent += row.Silent
		total.Stealth += row.Stealth
		total.PowPass += row.PowPass
		total.Captcha += row.Captcha
		total.BVPowOnly += row.BVPowOnly
		total.BVCaptchaOnly += row.BVCaptchaOnly
		total.BVPowThenCaptcha += row.BVPowThenCaptcha
		total.VerifyNG += row.VerifyNG
		total.CookieErr += row.CookieErr
		total.JSError += row.JSError
		out = append(out, row)
	}
	total.PowSolved = total.BVPowOnly + total.PowPass
	total.BVTotal = total.BVPowOnly + total.BVCaptchaOnly + total.BVPowThenCaptcha
	total.CaptchaPassed = total.BVCaptchaOnly + total.BVPowThenCaptcha

	// rate_limit row: aggregate all-phase transitions of IPs with rl=1 serves
	// via IP join.  Agg-path callers pass skipRateLimitRow=true when the
	// hkServeRL aggregate shows zero rate-limited serves in the window --
	// otherwise this raw scan sweeps the whole phase=serve subset only to
	// return an empty row.
	if !skipRateLimitRow {
		// header/asn/geo pseudo-rows first, then the rate_limit row prepended on
		// top, so the cross-verdict axis rows cluster above the per-verdict rows.
		// Like rate_limit, these overlap the verdict rows and stay out of TOTAL.
		if frRows, err := forceReasonFunnelRowsScan(ctx, d, site, hosts, since); err == nil {
			out = append(frRows, out...)
		}
		rlRow, err := rateLimitFunnelRow(ctx, d, site, hosts, since, botVerdicts)
		if err == nil {
			out = append([]FunnelRow{rlRow}, out...)
		}
	}

	// total uniq is a separate SQL (= so the same IP is not counted across verdicts).
	// Agg path skips this round-trip by passing the value down via totalLoadUniq.
	if totalLoadUniq != nil {
		total.LoadUniq = *totalLoadUniq
	} else {
		row := d.QueryRowContext(ctx, fmt.Sprintf(
			`SELECT COUNT(DISTINCT ip_address) FROM unmask_event WHERE %s%s AND phase = 'load'`,
			since, siteCond(site)+hostCond(hosts)))
		_ = row.Scan(&total.LoadUniq)
	}
	if total.Load > 0 {
		total.PowRate = float64(total.PowSolved) / float64(total.Load)
		total.CaptchaRate = float64(total.Captcha) / float64(total.Load)
	}
	out = append(out, total)
	return out, nil
}

// rateLimitFunnelRow scans one window with a single boundary for both the
// counted events and the rate-limited-IP set.  The agg-path tail uses
// rateLimitFunnelRowRange to look the IP set back slightly further than the
// counted events (so an interaction straddling the settled/tail boundary is
// still attributed), so this wrapper just passes the same bound for both.
func rateLimitFunnelRow(ctx context.Context, d *db.DB, site string, hosts []string, since string, botVerdicts []string) (FunnelRow, error) {
	return rateLimitFunnelRowRange(ctx, d, site, hosts, since, since, botVerdicts)
}

func rateLimitFunnelRowRange(ctx context.Context, d *db.DB, site string, hosts []string, outerSince, innerSince string, botVerdicts []string) (FunnelRow, error) {
	jsonRL := jsonExtract(d, "payload_json", "$.rl")
	sc := siteCond(site) + hostCond(hosts)
	botIn, botArgs := inClause(botVerdicts)
	stmt := fmt.Sprintf(`
        SELECT
          SUM(CASE WHEN phase='serve' THEN 1 ELSE 0 END)                AS n_serve,
          SUM(CASE WHEN phase='load' THEN 1 ELSE 0 END)                 AS n_load,
          SUM(CASE WHEN phase='load' AND flags=0 AND ja4_verdict `+botIn+` THEN 1 ELSE 0 END) AS n_stealth,
          SUM(CASE WHEN phase='pow_pass' THEN 1 ELSE 0 END)             AS n_pow_pass,
          SUM(CASE WHEN phase='captcha' THEN 1 ELSE 0 END)              AS n_captcha,
          SUM(CASE WHEN phase='bv_pow_only' THEN 1 ELSE 0 END)          AS n_bv_pow_only,
          SUM(CASE WHEN phase='bv_captcha_only' THEN 1 ELSE 0 END)      AS n_bv_captcha_only,
          SUM(CASE WHEN phase='bv_pow_then_captcha' THEN 1 ELSE 0 END)  AS n_bv_pow_then_captcha,
          SUM(CASE WHEN phase='verify_ng' THEN 1 ELSE 0 END)            AS n_verify_ng,
          SUM(CASE WHEN phase='cookie_err' THEN 1 ELSE 0 END)            AS n_cookie_err,
          SUM(CASE WHEN phase='error' THEN 1 ELSE 0 END)                AS n_error
        FROM unmask_event
        WHERE %s%s
          AND ip_address IN (
              SELECT ip_address FROM unmask_event
              WHERE %s%s AND phase='serve'
                AND %s IN ('1', 1)
          )`, outerSince, sc, innerSince, sc, jsonRL)
	row := d.QueryRowContext(ctx, stmt, botArgs...)
	var r FunnelRow
	r.Verdict = "rate_limit"
	var serve, load, stealth, powPass, capt, bvPowOnly, bvCaptOnly, bvPowThenCapt, vng, ce, jse sql.NullInt64
	if err := row.Scan(&serve, &load, &stealth, &powPass, &capt, &bvPowOnly, &bvCaptOnly, &bvPowThenCapt, &vng, &ce, &jse); err != nil {
		return r, err
	}
	r.Serve = int(serve.Int64)
	r.ServeRL = r.Serve
	r.Load = int(load.Int64)
	r.Stealth = int(stealth.Int64)
	r.PowPass = int(powPass.Int64)
	r.Captcha = int(capt.Int64)
	r.BVPowOnly = int(bvPowOnly.Int64)
	r.BVCaptchaOnly = int(bvCaptOnly.Int64)
	r.BVPowThenCaptcha = int(bvPowThenCapt.Int64)
	r.VerifyNG = int(vng.Int64)
	r.CookieErr = int(ce.Int64)
	r.JSError = int(jse.Int64)
	if r.Serve > r.Load {
		r.Silent = r.Serve - r.Load
	}
	r.PowSolved = r.BVPowOnly + r.PowPass
	r.BVTotal = r.BVPowOnly + r.BVCaptchaOnly + r.BVPowThenCaptcha
	r.CaptchaPassed = r.BVCaptchaOnly + r.BVPowThenCaptcha
	if r.Load > 0 {
		r.PowRate = float64(r.PowSolved) / float64(r.Load)
		r.CaptchaRate = float64(r.Captcha) / float64(r.Load)
	}
	return r, nil
}

// VerdictCount: per-JA4-verdict count + uniq IP.
type VerdictCount struct {
	Verdict string
	Count   int
	UniqIP  int
}

// VerdictDistribution returns per-verdict counts + distinct IPs. The default
// view (no site / no host filter) reads the hourly aggregate; filtered views
// and the pre-backfill window fall back to scanning raw events.
func VerdictDistribution(ctx context.Context, d *db.DB, site string, hosts []string, hours int) ([]VerdictCount, error) {
	if site == "" && len(hosts) == 0 && HourlyAggReady() {
		return verdictDistAgg(ctx, d, hours)
	}
	return verdictDistScan(ctx, d, site, hosts, hours)
}

func verdictDistScan(ctx context.Context, d *db.DB, site string, hosts []string, hours int) ([]VerdictCount, error) {
	stmt := fmt.Sprintf(`
        SELECT COALESCE(ja4_verdict, '(none)') AS v,
               COUNT(*) AS cnt,
               COUNT(DISTINCT ip_address) AS uniq
        FROM unmask_event WHERE %s%s
        GROUP BY ja4_verdict`, tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts))
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	by := map[string]VerdictCount{}
	for rows.Next() {
		var v VerdictCount
		if err := rows.Scan(&v.Verdict, &v.Count, &v.UniqIP); err != nil {
			return nil, err
		}
		by[v.Verdict] = v
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return buildVerdictRows(by), nil
}

// verdictDistAgg builds the distribution from the hourly aggregate: per-verdict
// counts summed from the 'fnl' buckets, distinct-IP estimated by merging the
// 'vdip' HLL sketches in the window.
func verdictDistAgg(ctx context.Context, d *db.DB, hours int) ([]VerdictCount, error) {
	by := map[string]VerdictCount{}

	// counts: sum fnl over (verdict id, phase) per raw verdict name.
	crows, err := d.QueryContext(ctx, `
        SELECT bucket_key, cnt FROM unmask_aggregate_hourly
        WHERE `+hourWindow(ctx, hours, "bucket_hour")+` AND bucket_kind = 'fnl'`)
	if err != nil {
		return nil, err
	}
	for crows.Next() {
		var key string
		var cnt int
		if err := crows.Scan(&key, &cnt); err != nil {
			crows.Close()
			return nil, err
		}
		if _, verdict, _, ok := splitFnlKey(key); ok {
			r := by[verdict]
			r.Verdict = verdict
			r.Count += cnt
			by[verdict] = r
		}
	}
	if err := crows.Err(); err != nil {
		crows.Close()
		return nil, err
	}
	crows.Close()

	// distinct IP: merge the per-hour vdip sketches per verdict.
	sketches := map[string]*hll{}
	hrows, err := d.QueryContext(ctx, `
        SELECT bucket_key, sketch FROM unmask_aggregate_hll
        WHERE `+hourWindow(ctx, hours, "bucket")+` AND bucket_kind = 'vdip'`)
	if err != nil {
		return nil, err
	}
	for hrows.Next() {
		var verdict string
		var blob []byte
		if err := hrows.Scan(&verdict, &blob); err != nil {
			hrows.Close()
			return nil, err
		}
		s := sketches[verdict]
		if s == nil {
			s = &hll{}
			sketches[verdict] = s
		}
		s.merge(loadHLL(blob))
	}
	if err := hrows.Err(); err != nil {
		hrows.Close()
		return nil, err
	}
	hrows.Close()
	for verdict, s := range sketches {
		r := by[verdict]
		r.Verdict = verdict
		r.UniqIP = s.estimate()
		by[verdict] = r
	}
	return buildVerdictRows(by), nil
}

// buildVerdictRows orders the verdict map: the fixed verdict list first,
// unknown verdicts seen in the data appended in name order, then sorted by
// count desc (0-count rows trail, keeping the 0-row display policy).
func buildVerdictRows(by map[string]VerdictCount) []VerdictCount {
	all := fixedVerdicts()
	seen := map[string]bool{}
	for _, v := range all {
		seen[v] = true
	}
	var unknown []string
	for v := range by {
		if !seen[v] {
			unknown = append(unknown, v)
		}
	}
	sort.Strings(unknown)
	all = append(all, unknown...)

	out := make([]VerdictCount, 0, len(all))
	for _, v := range all {
		if r, ok := by[v]; ok {
			out = append(out, r)
		} else {
			out = append(out, VerdictCount{Verdict: v})
		}
	}
	// Sort by count desc → verdict alpha. 0-count rows trail in declaration order.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return false
	})
	return out
}

// CookieStatusRow: 4-way breakdown of cookie presence across all nginx requests.
//
// Data source: unmask_cookie_minute table (= aggregated from nginx access_log
// over a unix socket). If /var/lib/unmask/nginx/http.inc is not included in
// http {}, everything returns 0 (= the access_log directive never fires).
//
//	total          : all nginx-received requests
//	captcha_passed : _bv cookie HMAC verified OK (= bv=1)
//	pow_passed     : _br cookie present (= bv=0 & bp=1)
//	none           : neither cookie
type CookieStatusRow struct {
	Kind        string // "total" / "captcha_passed" / "pow_passed" / "none"
	Label       string // display label ("total" / "CAPTCHA passed" / "PoW passed" / "no cookie")
	Count       int
	Description string // right-column description
	Color       string // row text color
}

// CookieStatus: SUM aggregation from the unmask_cookie_minute table.
// hours = 24 / 168 / 720. site = "" aggregates all sites (not used by dashboard).
//
// In environments where nginx log.conf is not included the table stays empty,
// so all-zero rows are returned (= the card itself is still rendered).
func CookieStatus(ctx context.Context, d *db.DB, site string, hosts []string, hours int) ([]CookieStatusRow, error) {
	cond := siteCond(site) // validates via siteValRE; never interpolate site raw

	// kind/cnt normalized schema. Aggregate the 3 kinds total / captcha / pow in one query.
	stmt := fmt.Sprintf(`
        SELECT
          COALESCE(SUM(CASE WHEN kind = 'total'   THEN cnt ELSE 0 END), 0) AS total,
          COALESCE(SUM(CASE WHEN kind = 'captcha' THEN cnt ELSE 0 END), 0) AS bv,
          COALESCE(SUM(CASE WHEN kind = 'pow'     THEN cnt ELSE 0 END), 0) AS bp
        FROM unmask_cookie_minute
        WHERE %s%s`, minWindow(ctx, hours, "bucket_min"), cond)
	row := d.QueryRowContext(ctx, stmt)
	var total, bv, bp sql.NullInt64
	if err := row.Scan(&total, &bv, &bp); err != nil {
		return nil, err
	}
	t := int(total.Int64)
	b := int(bv.Int64)
	p := int(bp.Int64)
	none := t - b - p
	if none < 0 {
		none = 0
	}
	// Label / Description are resolved by i18n on the template side
	// (= "cookie.row.<kind>" / "cookie.desc.<kind>"). Server side only sets
	// Kind / Count / Color.
	return []CookieStatusRow{
		{Kind: "total", Count: t},
		{Kind: "captcha_passed", Count: b, Color: "#16a34a"},
		{Kind: "pow_passed", Count: p, Color: "#0ea5e9"},
		{Kind: "none", Count: none, Color: "#94a3b8"},
	}, nil
}

// FlagsRow: flags-bit distribution (load phase).
type FlagsRow struct {
	Flags  int
	Bin    string // 5-bit binary notation
	Count  int
	UniqIP int
	Note   string
}

// Flag-bit notes. Short keywords like "webdriver", "no-plugins", "chrome-spoof".
var flagsNotes = map[int]string{
	0:  "-",
	1:  "webdriver",
	2:  "no-plugins",
	4:  "no-languages",
	8:  "screen-zero",
	16: "chrome-spoof",
	3:  "webdriver, no-plugins",
	5:  "webdriver, no-languages",
	9:  "webdriver, screen-zero",
	17: "webdriver, chrome-spoof",
	31: "webdriver, no-plugins, no-languages, screen-zero, chrome-spoof",
}

func FlagsDistribution(ctx context.Context, d *db.DB, site string, hosts []string, hours int) ([]FlagsRow, error) {
	if site == "" && len(hosts) == 0 && HourlyAggReady() {
		return flagsDistributionAgg(ctx, d, hours)
	}
	return flagsDistributionScan(ctx, d, site, hosts, hours)
}

// flagsDistributionScan: the original raw-scan path.  Used when a host or
// site filter rules out the install-wide aggregate.
func flagsDistributionScan(ctx context.Context, d *db.DB, site string, hosts []string, hours int) ([]FlagsRow, error) {
	stmt := fmt.Sprintf(`
        SELECT flags, COUNT(*) AS n, COUNT(DISTINCT ip_address) AS uniq
        FROM unmask_event WHERE %s%s AND phase='load'
        GROUP BY flags`, tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts))
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	by := map[int]FlagsRow{}
	for rows.Next() {
		var fl, n, u int
		if err := rows.Scan(&fl, &n, &u); err != nil {
			return nil, err
		}
		by[fl] = FlagsRow{Flags: fl, Count: n, UniqIP: u}
	}
	return orderFlagsRows(by), nil
}

// flagsDistributionAgg: install-wide aggregate read.  hkFlags supplies the
// count per flags value; hkFlagsIP HLL sketches are merged per flags value
// for the distinct-IP estimate.
func flagsDistributionAgg(ctx context.Context, d *db.DB, hours int) ([]FlagsRow, error) {
	by := map[int]FlagsRow{}

	cRows, err := d.QueryContext(ctx, `
        SELECT bucket_key, SUM(cnt) FROM unmask_aggregate_hourly
        WHERE bucket_kind = '`+hkFlags+`' AND `+hourWindow(ctx, hours, "bucket_hour")+`
        GROUP BY bucket_key`)
	if err != nil {
		return nil, err
	}
	for cRows.Next() {
		var keyStr string
		var n int64
		if err := cRows.Scan(&keyStr, &n); err != nil {
			cRows.Close()
			return nil, err
		}
		fl, err := strconv.Atoi(keyStr)
		if err != nil {
			continue // malformed key (shouldn't happen for new rows)
		}
		r := by[fl]
		r.Flags = fl
		r.Count = int(n)
		by[fl] = r
	}
	if err := cRows.Err(); err != nil {
		cRows.Close()
		return nil, err
	}
	cRows.Close()

	sRows, err := d.QueryContext(ctx, `
        SELECT bucket_key, sketch FROM unmask_aggregate_hll
        WHERE `+hourWindow(ctx, hours, "bucket")+`
          AND bucket_kind = '`+hkFlagsIP+`'`)
	if err != nil {
		return nil, err
	}
	sketches := map[int]*hll{}
	for sRows.Next() {
		var keyStr string
		var blob []byte
		if err := sRows.Scan(&keyStr, &blob); err != nil {
			sRows.Close()
			return nil, err
		}
		fl, err := strconv.Atoi(keyStr)
		if err != nil {
			continue
		}
		h := loadHLL(blob)
		if existing, ok := sketches[fl]; ok {
			existing.merge(h)
		} else {
			sketches[fl] = h
		}
	}
	if err := sRows.Err(); err != nil {
		sRows.Close()
		return nil, err
	}
	sRows.Close()
	for fl, h := range sketches {
		r := by[fl]
		r.Flags = fl
		r.UniqIP = int(h.estimate())
		by[fl] = r
	}

	return orderFlagsRows(by), nil
}

// orderFlagsRows materialises the by-flags map into UI display order:
// keyFlags first (= always shown so the table doesn't lose a familiar slot
// on a quiet hour), then any remaining observed values, then re-sort by
// count desc / flags asc, then cap at 30 rows.
func orderFlagsRows(by map[int]FlagsRow) []FlagsRow {
	seen := map[int]bool{}
	var out []FlagsRow
	for _, fl := range keyFlags {
		seen[fl] = true
		r := by[fl]
		r.Flags = fl
		r.Bin = bin5(fl)
		r.Note = flagsNotes[fl]
		out = append(out, r)
	}
	for fl := range by {
		if !seen[fl] {
			r := by[fl]
			r.Bin = bin5(fl)
			r.Note = flagsNotes[fl]
			out = append(out, r)
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Flags < out[j].Flags
	})
	if len(out) > 30 {
		out = out[:30]
	}
	return out
}

// CaptchaForceRow: per-reason counts from load-phase payload_json.force_reason.
//
// Reason values are decided at serve time:
//
//	"none"       normal PoW (= not forced)
//	"ja4_bot"    JA4 verdict action=bot
//	"honeypot"   hit a honeypot path
//	"banned"     hit the persistent BAN list
//	"protected"  protected path (captcha / strict mode)
//	"rate_limit" rate-limit redirect (= /_rl/...)
//	"test"       debug path (_test_ja4 / _force=captcha)
//	"unknown"    flag not recorded (= old challenge.html etc.; normally absent)
type CaptchaForceRow struct {
	Kind   string
	Count  int
	UniqIP int
}

// captchaForceKinds: display order = none / each forced reason / unknown.
var captchaForceKinds = []string{"none", "ja4_bot", "honeypot", "banned", "protected", "rate_limit", "test", "stale", "header", "asn", "geo", "unknown"}

// AITrafficRow: one crawler-tag's traffic share over the window.
//
// `Tag` is a crawler-user-agents.json tag (= "ai-crawler", "ai-training",
// "ai-user", "search-engine", etc.).  This card answers "how much of the
// rl-clean serve traffic was attributable to each crawler family" — the
// agent-commerce dashboard AWS WAF and Cloudflare are surfacing in 2026.
type AITrafficRow struct {
	Tag    string
	Count  int
	UniqIP int
}

// AITrafficBreakdown returns per-crawler-tag counts + distinct IP for the
// last `hours` window.
//
// Path selection:
//
//   - site == "" && len(hosts) == 0 && agg ready → install-wide aggregate
//     (hkAITag / hkAITagIP)
//   - site != ""                     && agg ready → per-site aggregate
//     (hkAITagSite / hkAITagSiteIP, keyed '<site>|<tag>')
//   - host filter (= len(hosts) > 0) || agg not ready → zero rows
//
// Host scoping isn't a dimension on this aggregate; the operator filtering
// by host sees an honest empty card instead of a 30s raw scan.  Same
// principle for the post-restart window where the aggregate hasn't caught
// up yet — better to render zeros than to time out the entire dashboard.
func AITrafficBreakdown(ctx context.Context, d *db.DB, site string, hosts []string, hours int) ([]AITrafficRow, error) {
	if len(hosts) > 0 || !HourlyAggReady() {
		return orderAITrafficRows(nil), nil
	}
	if site == "" {
		return aiTrafficBreakdownAgg(ctx, d, hours)
	}
	return aiTrafficBreakdownAggSite(ctx, d, site, hours)
}

// aiTrafficBreakdownAgg reads the hkAITag count + hkAITagIP HLL bucket
// kinds.  Order is classify.CrawlerTagOrder (= AI tags first) so the
// table layout stays stable across refreshes.
func aiTrafficBreakdownAgg(ctx context.Context, d *db.DB, hours int) ([]AITrafficRow, error) {
	by := map[string]AITrafficRow{}

	cRows, err := d.QueryContext(ctx, `
        SELECT bucket_key, SUM(cnt) FROM unmask_aggregate_hourly
        WHERE bucket_kind = '`+hkAITag+`' AND `+hourWindow(ctx, hours, "bucket_hour")+`
        GROUP BY bucket_key`)
	if err != nil {
		return nil, err
	}
	for cRows.Next() {
		var tag string
		var n int64
		if err := cRows.Scan(&tag, &n); err != nil {
			cRows.Close()
			return nil, err
		}
		r := by[tag]
		r.Tag = tag
		r.Count = int(n)
		by[tag] = r
	}
	if err := cRows.Err(); err != nil {
		cRows.Close()
		return nil, err
	}
	cRows.Close()

	sRows, err := d.QueryContext(ctx, `
        SELECT bucket_key, sketch FROM unmask_aggregate_hll
        WHERE `+hourWindow(ctx, hours, "bucket")+`
          AND bucket_kind = '`+hkAITagIP+`'`)
	if err != nil {
		return nil, err
	}
	sketches := map[string]*hll{}
	for sRows.Next() {
		var tag string
		var blob []byte
		if err := sRows.Scan(&tag, &blob); err != nil {
			sRows.Close()
			return nil, err
		}
		h := loadHLL(blob)
		if existing, ok := sketches[tag]; ok {
			existing.merge(h)
		} else {
			sketches[tag] = h
		}
	}
	if err := sRows.Err(); err != nil {
		sRows.Close()
		return nil, err
	}
	sRows.Close()
	for tag, h := range sketches {
		r := by[tag]
		r.Tag = tag
		r.UniqIP = int(h.estimate())
		by[tag] = r
	}
	return orderAITrafficRows(by), nil
}

// aiTrafficBreakdownAggSite reads the per-site bucket (hkAITagSite /
// hkAITagSiteIP).  bucket_key is '<site>|<tag>'; the SQL WHERE narrows by
// the '<site>|' prefix and Scan splits the tag off the key.
func aiTrafficBreakdownAggSite(ctx context.Context, d *db.DB, site string, hours int) ([]AITrafficRow, error) {
	by := map[string]AITrafficRow{}
	prefix := site + "|"
	likeArg := prefix + "%"

	cRows, err := d.QueryContext(ctx, `
        SELECT bucket_key, SUM(cnt) FROM unmask_aggregate_hourly
        WHERE bucket_kind = '`+hkAITagSite+`'
          AND `+hourWindow(ctx, hours, "bucket_hour")+`
          AND bucket_key LIKE ?
        GROUP BY bucket_key`, likeArg)
	if err != nil {
		return nil, err
	}
	for cRows.Next() {
		var key string
		var n int64
		if err := cRows.Scan(&key, &n); err != nil {
			cRows.Close()
			return nil, err
		}
		tag := strings.TrimPrefix(key, prefix)
		if tag == key {
			continue // unexpected key shape; skip rather than mis-bucket
		}
		r := by[tag]
		r.Tag = tag
		r.Count = int(n)
		by[tag] = r
	}
	if err := cRows.Err(); err != nil {
		cRows.Close()
		return nil, err
	}
	cRows.Close()

	sRows, err := d.QueryContext(ctx, `
        SELECT bucket_key, sketch FROM unmask_aggregate_hll
        WHERE `+hourWindow(ctx, hours, "bucket")+`
          AND bucket_kind = '`+hkAITagSiteIP+`'
          AND bucket_key LIKE ?`, likeArg)
	if err != nil {
		return nil, err
	}
	sketches := map[string]*hll{}
	for sRows.Next() {
		var key string
		var blob []byte
		if err := sRows.Scan(&key, &blob); err != nil {
			sRows.Close()
			return nil, err
		}
		tag := strings.TrimPrefix(key, prefix)
		if tag == key {
			continue
		}
		h := loadHLL(blob)
		if existing, ok := sketches[tag]; ok {
			existing.merge(h)
		} else {
			sketches[tag] = h
		}
	}
	if err := sRows.Err(); err != nil {
		sRows.Close()
		return nil, err
	}
	sRows.Close()
	for tag, h := range sketches {
		r := by[tag]
		r.Tag = tag
		r.UniqIP = int(h.estimate())
		by[tag] = r
	}
	return orderAITrafficRows(by), nil
}

// orderAITrafficRows materialises by-tag map sorted by Count DESC, with
// classify.CrawlerTagOrder as the stable tie-breaker.  Every tag is returned
// even when its count is zero so operators see the full crawler-tag taxonomy
// at a glance and can confirm an install really got nothing rather than
// wondering whether the card silently dropped a row.  Zero-count tags fall
// to the bottom but stay visible (feedback_zero_row_policy).  Mirrors
// orderCaptchaForceRows.
func orderAITrafficRows(by map[string]AITrafficRow) []AITrafficRow {
	out := make([]AITrafficRow, 0, len(classify.CrawlerTagOrder))
	for _, tag := range classify.CrawlerTagOrder {
		if r, ok := by[tag]; ok {
			r.Tag = tag
			out = append(out, r)
		} else {
			out = append(out, AITrafficRow{Tag: tag})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	return out
}

func CaptchaForceBreakdown(ctx context.Context, d *db.DB, site string, hosts []string, hours int) ([]CaptchaForceRow, error) {
	if site == "" && len(hosts) == 0 && HourlyAggReady() {
		return captchaForceBreakdownAgg(ctx, d, hours)
	}
	return captchaForceBreakdownScan(ctx, d, site, hosts, hours)
}

// captchaForceBreakdownScan: the original raw-scan path.  Used when a host
// or site filter rules out the install-wide aggregate (= aggregates don't
// carry host / site dimensions for this card).
func captchaForceBreakdownScan(ctx context.Context, d *db.DB, site string, hosts []string, hours int) ([]CaptchaForceRow, error) {
	reasonExpr := jsonExtract(d, "payload_json", "$.force_reason")
	stmt := fmt.Sprintf(`
        SELECT
          CASE
            WHEN %s IN ('none','ja4_bot','honeypot','banned','protected','rate_limit','test','stale','header','asn','geo') THEN %s
            ELSE 'unknown'
          END AS kind,
          COUNT(*) AS n,
          COUNT(DISTINCT ip_address) AS uniq
        FROM unmask_event WHERE %s%s AND phase='load'
        GROUP BY kind`, reasonExpr, reasonExpr, tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts))
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	by := map[string]CaptchaForceRow{}
	for rows.Next() {
		var v CaptchaForceRow
		if err := rows.Scan(&v.Kind, &v.Count, &v.UniqIP); err != nil {
			return nil, err
		}
		by[v.Kind] = v
	}
	return orderCaptchaForceRows(by), nil
}

// captchaForceBreakdownAgg: install-wide aggregate read.  hkCaptchaForce
// supplies the count per reason; hkCaptchaForceIP HLL sketches are merged
// per reason for the distinct-IP estimate.  Same row shape as the scan
// path so the template doesn't care which one ran.
func captchaForceBreakdownAgg(ctx context.Context, d *db.DB, hours int) ([]CaptchaForceRow, error) {
	by := map[string]CaptchaForceRow{}

	cRows, err := d.QueryContext(ctx, `
        SELECT bucket_key, SUM(cnt) FROM unmask_aggregate_hourly
        WHERE bucket_kind = '`+hkCaptchaForce+`' AND `+hourWindow(ctx, hours, "bucket_hour")+`
        GROUP BY bucket_key`)
	if err != nil {
		return nil, err
	}
	for cRows.Next() {
		var kind string
		var n int64
		if err := cRows.Scan(&kind, &n); err != nil {
			cRows.Close()
			return nil, err
		}
		r := by[kind]
		r.Kind = kind
		r.Count = int(n)
		by[kind] = r
	}
	if err := cRows.Err(); err != nil {
		cRows.Close()
		return nil, err
	}
	cRows.Close()

	sRows, err := d.QueryContext(ctx, `
        SELECT bucket_key, sketch FROM unmask_aggregate_hll
        WHERE `+hourWindow(ctx, hours, "bucket")+`
          AND bucket_kind = '`+hkCaptchaForceIP+`'`)
	if err != nil {
		return nil, err
	}
	sketches := map[string]*hll{}
	for sRows.Next() {
		var kind string
		var blob []byte
		if err := sRows.Scan(&kind, &blob); err != nil {
			sRows.Close()
			return nil, err
		}
		h := loadHLL(blob)
		if existing, ok := sketches[kind]; ok {
			existing.merge(h)
		} else {
			sketches[kind] = h
		}
	}
	if err := sRows.Err(); err != nil {
		sRows.Close()
		return nil, err
	}
	sRows.Close()
	for kind, h := range sketches {
		r := by[kind]
		r.Kind = kind
		r.UniqIP = int(h.estimate())
		by[kind] = r
	}

	return orderCaptchaForceRows(by), nil
}

// orderCaptchaForceRows materialises the by-kind map into captchaForceKinds
// display order, filling missing kinds with zero rows so the UI table never
// drops a reason.
func orderCaptchaForceRows(by map[string]CaptchaForceRow) []CaptchaForceRow {
	out := make([]CaptchaForceRow, 0, len(captchaForceKinds))
	for _, k := range captchaForceKinds {
		if r, ok := by[k]; ok {
			out = append(out, r)
		} else {
			out = append(out, CaptchaForceRow{Kind: k})
		}
	}
	return out
}

// ReloadLoopRow: same IP, load phase, reload_count >= 2.
type ReloadLoopRow struct {
	IP          string
	Count       int
	MaxReload   int
	MaxFlags    int
	UA          string
	UAFull      string // raw UA before truncate, for cellpop full-value popover
	LastSeen    string
	LastSeenTS  int64
	CountryCode string
}

func ReloadLoops(ctx context.Context, d *db.DB, site string, hosts []string, hours int) ([]ReloadLoopRow, error) {
	stmt := fmt.Sprintf(`
        SELECT ip_address, COUNT(*) AS n, MAX(reload_count) AS max_rc,
               MAX(flags) AS max_flags, MAX(user_agent) AS ua, MAX(date_created) AS last_seen
        FROM unmask_event WHERE %s%s AND phase='load' AND reload_count >= 1
        GROUP BY ip_address
        HAVING max_rc >= 2 OR n >= 3
        ORDER BY max_rc DESC, n DESC LIMIT 30`, tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts))
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ReloadLoopRow
	for rows.Next() {
		var raw []byte
		var n, mr, mf int
		var ua, ls sql.NullString
		if err := rows.Scan(&raw, &n, &mr, &mf, &ua, &ls); err != nil {
			return nil, err
		}
		out = append(out, ReloadLoopRow{
			IP: ipFromBytes(raw), Count: n, MaxReload: mr, MaxFlags: mf,
			UA: truncate(ua.String, 50), UAFull: ua.String,
			LastSeen: ls.String, LastSeenTS: parseDateTimeToUnix(ls.String),
		})
	}
	return out, rows.Err()
}

// RLIPRow: phase=serve + payload.rl=1 aggregated per IP.
type RLIPRow struct {
	IP          string
	Count       int
	UA          string
	UAFull      string // raw UA before truncate, for cellpop full-value popover
	LastSeen    string
	LastSeenTS  int64
	CountryCode string
}

// RLPathRow: phase=serve + payload.rl=1 aggregated per original path.
type RLPathRow struct {
	Path  string
	Count int
}

// RLSummary: aggregation period + total hit count (= header description text).
type RLSummary struct {
	From  string
	To    string
	Total int
}

// HasRateLimited reports whether any phase=serve+rl=1 events landed in the
// last `hours`.  Read straight off the existing hkServeRL aggregate (= per-
// verdict rate-limited serve count).  Site/host scoping is not modelled in
// the aggregate, so we conservatively return true when filtered; callers
// only use this as a "skip all RateLimit* cards when nothing happened" gate.
func HasRateLimited(ctx context.Context, d *db.DB, site string, hosts []string, hours int) (bool, error) {
	if site != "" || len(hosts) > 0 || !HourlyAggReady() {
		return true, nil
	}
	var total int64
	err := d.QueryRowContext(ctx, `
        SELECT COALESCE(SUM(cnt), 0) FROM unmask_aggregate_hourly
        WHERE bucket_kind = '`+hkServeRL+`' AND `+hourWindow(ctx, hours, "bucket_hour")).Scan(&total)
	if err != nil {
		return true, err
	}
	return total > 0, nil
}

// RateLimitAll computes all four rate-limit cards (summary / by-IP / by-path /
// queries-per-path) from a SINGLE pass over the phase=serve, payload.rl=1 rows
// in the window.  The stats page used to run them as four independent parallel
// cards, each re-scanning the serve window and re-reading every serve row's
// payload_json — so a cold DB paid ~4x the I/O and the four contended for the
// same pages.  SQLite now fetches the rl=1 rows once and aggregates in Go;
// MariaDB keeps the four grouped queries (InnoDB handles them and avoids
// shipping the raw rows over the wire).
func RateLimitAll(ctx context.Context, d *db.DB, site string, hosts []string, hours, ipLimit, pathLimit, perPathQ int) (RLSummary, []RLIPRow, []RLPathRow, map[string][]RLQueryCount, error) {
	if d.Driver != db.DriverSQLite {
		s, err := RateLimitSummary(ctx, d, site, hosts, hours)
		if err != nil {
			return s, nil, nil, nil, err
		}
		ips, err := RateLimitIPs(ctx, d, site, hosts, hours, ipLimit)
		if err != nil {
			return s, nil, nil, nil, err
		}
		paths, err := RateLimitPaths(ctx, d, site, hosts, hours, pathLimit)
		if err != nil {
			return s, ips, nil, nil, err
		}
		q, err := RateLimitQueriesByPath(ctx, d, site, hosts, hours, perPathQ)
		return s, ips, paths, q, err
	}

	jsonRL := jsonExtract(d, "payload_json", "$.rl")
	jsonPath := jsonExtract(d, "payload_json", "$.orig_path")
	stmt := fmt.Sprintf(`
        SELECT ip_address, COALESCE(user_agent, ''), date_created, COALESCE(%s, '')
        FROM unmask_event
        WHERE %s%s AND phase='serve' AND %s IN ('1', 1)`,
		jsonPath, tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts), jsonRL)
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return RLSummary{}, nil, nil, nil, err
	}
	defer rows.Close()

	type ipAcc struct {
		count        int
		ua, lastSeen string
	}
	ipm := map[string]*ipAcc{}
	pathCount := map[string]int{}
	queryCount := map[string]map[string]int{}
	var total int
	var minDate, maxDate string
	for rows.Next() {
		var raw []byte
		var ua, dc, path string
		if err := rows.Scan(&raw, &ua, &dc, &path); err != nil {
			return RLSummary{}, nil, nil, nil, err
		}
		total++
		if minDate == "" || dc < minDate {
			minDate = dc
		}
		if dc > maxDate {
			maxDate = dc
		}
		ip := ipFromBytes(raw)
		a := ipm[ip]
		if a == nil {
			a = &ipAcc{}
			ipm[ip] = a
		}
		a.count++
		if ua > a.ua { // MAX(user_agent) parity
			a.ua = ua
		}
		if dc > a.lastSeen {
			a.lastSeen = dc
		}
		// path / query split (jsonExtract may wrap the value in quotes); rows
		// with no orig_path are still counted above (summary / IPs) but skipped
		// for the path breakdown, matching RateLimitPaths' `<> ''` filter.
		p := strings.Trim(path, `"`)
		if p == "" {
			continue
		}
		base, q := p, ""
		if i := strings.Index(p, "?"); i >= 0 {
			base, q = p[:i], p[i+1:]
		}
		pathCount[base]++
		if q != "" {
			if queryCount[base] == nil {
				queryCount[base] = map[string]int{}
			}
			queryCount[base][q]++
		}
	}
	if err := rows.Err(); err != nil {
		return RLSummary{}, nil, nil, nil, err
	}

	summary := RLSummary{Total: total, From: minDate, To: maxDate}

	ipRows := make([]RLIPRow, 0, len(ipm))
	for ip, a := range ipm {
		ipRows = append(ipRows, RLIPRow{
			IP: ip, Count: a.count,
			UA: truncate(a.ua, 60), UAFull: a.ua,
			LastSeen: a.lastSeen, LastSeenTS: parseDateTimeToUnix(a.lastSeen),
		})
	}
	sort.Slice(ipRows, func(i, j int) bool { return ipRows[i].Count > ipRows[j].Count })
	if len(ipRows) > ipLimit {
		ipRows = ipRows[:ipLimit]
	}

	pathRows := make([]RLPathRow, 0, len(pathCount))
	for p, c := range pathCount {
		pathRows = append(pathRows, RLPathRow{Path: p, Count: c})
	}
	sort.Slice(pathRows, func(i, j int) bool { return pathRows[i].Count > pathRows[j].Count })
	if len(pathRows) > pathLimit {
		pathRows = pathRows[:pathLimit]
	}

	queriesByPath := map[string][]RLQueryCount{}
	for p, qm := range queryCount {
		qs := make([]RLQueryCount, 0, len(qm))
		for q, c := range qm {
			qs = append(qs, RLQueryCount{Query: q, Count: c})
		}
		sort.Slice(qs, func(i, j int) bool { return qs[i].Count > qs[j].Count })
		if len(qs) > perPathQ {
			qs = qs[:perPathQ]
		}
		queriesByPath[p] = qs
	}

	return summary, ipRows, pathRows, queriesByPath, nil
}

func RateLimitIPs(ctx context.Context, d *db.DB, site string, hosts []string, hours, limit int) ([]RLIPRow, error) {
	jsonRL := jsonExtract(d, "payload_json", "$.rl")
	stmt := fmt.Sprintf(`
        SELECT ip_address,
               COUNT(*) AS n,
               MAX(user_agent) AS ua,
               MAX(date_created) AS last_seen
        FROM unmask_event
        WHERE %s%s AND phase='serve' AND %s IN ('1', 1)
        GROUP BY ip_address ORDER BY n DESC LIMIT ?`, tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts), jsonRL)
	rows, err := d.QueryContext(ctx, stmt, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RLIPRow
	for rows.Next() {
		var raw []byte
		var n int
		var ua, ls sql.NullString
		if err := rows.Scan(&raw, &n, &ua, &ls); err != nil {
			return nil, err
		}
		out = append(out, RLIPRow{
			IP: ipFromBytes(raw), Count: n,
			UA: truncate(ua.String, 60), UAFull: ua.String,
			LastSeen: ls.String, LastSeenTS: parseDateTimeToUnix(ls.String),
		})
	}
	return out, rows.Err()
}

// --- CAPTCHA pass report (= "CAPTCHA 突破レポート") -------------------------
//
// Surfaces the clients that completed a CAPTCHA -- phase bv_captcha_only /
// bv_pow_then_captcha, i.e. ones that obtained a reusable _bv cookie by solving
// the CAPTCHA.  The headline signal is how many carry a NON-ok JA4 verdict: a
// real human solving a CAPTCHA has an 'ok' TLS fingerprint, so a high bot-JA4
// share means automated clients are passing the CAPTCHA and can then reuse the
// cookie to scrape.  These read unmask_event directly (raw, not the aggregate):
// captcha passes are rare (a handful/day) so the filtered scan is cheap and the
// per-row detail the report needs isn't in the minute rollups anyway.
const captchaPassPhases = "('bv_captcha_only','bv_pow_then_captcha')"

// CaptchaPassRow is one captcha-pass event (= the recent-detail list).
type CaptchaPassRow struct {
	TS          int64
	Date        string
	IP          string
	Verdict     string
	JA4         string // raw TLS fingerprint behind the verdict (= verdict-cell popover)
	UA          string
	UAFull      string
	Path        string
	Ref         string
	Phase       string
	ForceReason string // "$.force_reason": axis that raised the challenge (none = normal path)
	IsBot       bool   // filled by the handler from the verdict->action map
	CountryCode string // filled by the handler from IP-geo
}

// CaptchaPassIPRow is one IP's repeated captcha passes (= the ranking).
type CaptchaPassIPRow struct {
	IP          string
	Verdict     string
	JA4         string // raw TLS fingerprint behind the verdict (= verdict-cell popover)
	UA          string
	UAFull      string
	Passes      int
	Paths       int
	LastSeen    string
	LastSeenTS  int64
	IsBot       bool
	CountryCode string
}

// CaptchaPassVerdictCounts returns captcha passes grouped by JA4 verdict over
// the window, so the handler can roll them into bot / ok totals for the KPI.
func CaptchaPassVerdictCounts(ctx context.Context, d *db.DB, site string, hosts []string, hours int) (map[string]int, error) {
	stmt := fmt.Sprintf(`
        SELECT COALESCE(ja4_verdict, ''), COUNT(*)
        FROM unmask_event
        WHERE %s%s AND phase IN %s
        GROUP BY ja4_verdict`, tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts), captchaPassPhases)
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var v string
		var n int
		if err := rows.Scan(&v, &n); err != nil {
			return nil, err
		}
		out[v] = n
	}
	return out, rows.Err()
}

// CaptchaPassForceReasonCounts breaks the CAPTCHA passes down by the force_reason
// that raised the challenge (header / stale / asn / geo / honeypot / banned /
// protected / rate_limit / none / ...), so an operator can see WHICH axis's
// CAPTCHAs are being solved -- a high count on a bot-facing axis flags a solver.
// force_reason rides the pass beacon; passes served before the challenge.js
// carried it fold into "none".  Same small phase=bv_* subset as the verdict
// counts, so no extra full scan.
func CaptchaPassForceReasonCounts(ctx context.Context, d *db.DB, site string, hosts []string, hours int) (map[string]int, error) {
	reasonExpr := jsonExtract(d, "payload_json", "$.force_reason")
	stmt := fmt.Sprintf(`
        SELECT COALESCE(%s, 'none'), COUNT(*)
        FROM unmask_event
        WHERE %s%s AND phase IN %s
        GROUP BY %s`, reasonExpr, tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts), captchaPassPhases, reasonExpr)
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var v string
		var n int
		if err := rows.Scan(&v, &n); err != nil {
			return nil, err
		}
		if v == "" {
			v = "none"
		}
		out[v] += n
	}
	return out, rows.Err()
}

// CaptchaFailForceReasonCounts is the fail-side twin of
// CaptchaPassForceReasonCounts: it breaks the CAPTCHA *failures* (verify_ng)
// down by the force_reason that raised the challenge, so pass-by-axis and
// fail-by-axis read together as each axis's CAPTCHA effectiveness (a high fail
// count on a bot-facing axis = the wall is working; a high pass count = solver).
func CaptchaFailForceReasonCounts(ctx context.Context, d *db.DB, site string, hosts []string, hours int) (map[string]int, error) {
	reasonExpr := jsonExtract(d, "payload_json", "$.force_reason")
	stmt := fmt.Sprintf(`
        SELECT COALESCE(%s, 'none'), COUNT(*)
        FROM unmask_event
        WHERE %s%s AND phase = 'verify_ng'
        GROUP BY %s`, reasonExpr, tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts), reasonExpr)
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var v string
		var n int
		if err := rows.Scan(&v, &n); err != nil {
			return nil, err
		}
		if v == "" {
			v = "none"
		}
		out[v] += n
	}
	return out, rows.Err()
}

// CaptchaPassTopIPs ranks IPs by how many times they passed a CAPTCHA in the
// window (= repeat passers are the persistent bots re-solving for fresh cookies).
func CaptchaPassTopIPs(ctx context.Context, d *db.DB, site string, hosts []string, hours, limit int) ([]CaptchaPassIPRow, error) {
	pathExpr := jsonExtract(d, "payload_json", "$.orig_path")
	stmt := fmt.Sprintf(`
        SELECT ip_address,
               MAX(ja4_verdict)  AS verdict,
               MAX(ja4)          AS ja4,
               MAX(user_agent)   AS ua,
               COUNT(*)          AS passes,
               COUNT(DISTINCT %s) AS paths,
               MAX(date_created) AS last_seen
        FROM unmask_event
        WHERE %s%s AND phase IN %s
        GROUP BY ip_address
        ORDER BY passes DESC, last_seen DESC LIMIT ?`,
		pathExpr, tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts), captchaPassPhases)
	rows, err := d.QueryContext(ctx, stmt, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CaptchaPassIPRow
	for rows.Next() {
		var raw []byte
		var passes, paths int
		var verdict, ja4, ua, ls sql.NullString
		if err := rows.Scan(&raw, &verdict, &ja4, &ua, &passes, &paths, &ls); err != nil {
			return nil, err
		}
		out = append(out, CaptchaPassIPRow{
			IP: ipFromBytes(raw), Verdict: verdict.String, JA4: ja4.String,
			UA: truncate(ua.String, 80), UAFull: ua.String,
			Passes: passes, Paths: paths,
			LastSeen: ls.String, LastSeenTS: parseDateTimeToUnix(ls.String),
		})
	}
	return out, rows.Err()
}

// CaptchaPassRecent returns the latest captcha passes (= the per-client detail
// list) with the path requested and the support Ref ID at the time of the pass.
func CaptchaPassRecent(ctx context.Context, d *db.DB, site string, hosts []string, hours, limit int) ([]CaptchaPassRow, error) {
	pathExpr := jsonExtract(d, "payload_json", "$.orig_path")
	refExpr := jsonExtract(d, "payload_json", "$.ref")
	frExpr := jsonExtract(d, "payload_json", "$.force_reason")
	stmt := fmt.Sprintf(`
        SELECT date_created, ip_address, COALESCE(ja4_verdict, ''), COALESCE(ja4, ''), COALESCE(user_agent, ''),
               COALESCE(%s, ''), COALESCE(%s, ''), phase, COALESCE(%s, '')
        FROM unmask_event
        WHERE %s%s AND phase IN %s
        ORDER BY date_created DESC LIMIT ?`,
		pathExpr, refExpr, frExpr, tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts), captchaPassPhases)
	rows, err := d.QueryContext(ctx, stmt, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CaptchaPassRow
	for rows.Next() {
		var raw []byte
		var dc, verdict, ja4, ua, path, ref, phase, fr string
		if err := rows.Scan(&dc, &raw, &verdict, &ja4, &ua, &path, &ref, &phase, &fr); err != nil {
			return nil, err
		}
		out = append(out, CaptchaPassRow{
			TS: parseDateTimeToUnix(dc), Date: dc, IP: ipFromBytes(raw),
			Verdict: verdict, JA4: ja4, UA: truncate(ua, 80), UAFull: ua,
			Path: path, Ref: ref, Phase: phase, ForceReason: fr,
		})
	}
	return out, rows.Err()
}

// --- cookie reuse ranking (= "使い回しクッキー アクセスランキング") -----------
//
// Ranks IPs by how many requests they made REUSING a valid _bv cookie (= the
// actual scrape volume of a single cookie).  Unlike the CAPTCHA-pass report
// above -- which reads unmask_event, where the challenge fires -- a reused valid
// cookie triggers NO challenge, so this signal exists only in the nginx
// access-log stream the nginxlog worker aggregates into unmask_cookie_ip_minute.
// Every other per-IP view on this dashboard reads unmask_event, which is exactly
// why this traffic is invisible without the card.
//
// The two kinds read very differently:
//
//	captcha -- the client had to clear a CAPTCHA, so holding the cookie at all
//	           is already a suspicion signal; volume alone is the story.
//	pow     -- the transparent challenge every first-time visitor solves, so
//	           ordinary humans hold these too.  Volume alone is NOT a signal:
//	           a carrier CGNAT egress or a corporate proxy will out-request any
//	           scraper simply by having hundreds of people behind it.  What
//	           separates them is fingerprint spread -- a NAT shows many distinct
//	           JA4s, one scraper riding one solve shows exactly one.  Hence
//	           JA4Count, which is what makes the PoW section worth reading.

// CookieReuseRow is one IP's cookie-reuse volume over the window.
type CookieReuseRow struct {
	IP      string
	JA4     string
	Verdict string // filled by the handler by resolving JA4 -> verdict name
	UA      string
	UAFull  string
	// JA4Count: distinct JA4s seen for this IP in the window.  1 alongside a
	// high request count means a single client; many means shared egress.
	JA4Count    int
	Requests    int
	LastSeen    string
	LastSeenTS  int64
	IsBot       bool   // filled by the handler by classifying JA4 -> verdict action
	CountryCode string // filled by the handler from IP-geo
}

// CookieReuseTopIPs ranks IPs by reused-cookie request volume from
// unmask_cookie_ip_minute for one cookie kind ("captcha" / "pow").  Like the
// other cookie_minute-backed reads (CookieStatus / DailyPassByDay) it filters by
// site only: the table carries no host column, so the hosts argument is accepted
// for signature parity but not applied.  Valid on both SQLite (glebarez) and
// MariaDB.
//
// kind is bound as a parameter, never interpolated.
func CookieReuseTopIPs(ctx context.Context, d *db.DB, site, kind string, hosts []string, hours, limit int) ([]CookieReuseRow, error) {
	_ = hosts              // no host column on unmask_cookie_ip_minute (mirrors CookieStatus / DailyPassByDay)
	cond := siteCond(site) // validates via siteValRE; never interpolate site raw
	// The row keeps one ja4 per (minute, ip), so COUNT(DISTINCT ja4) over the
	// window is a lower bound on the fingerprints behind the IP -- enough to
	// tell "one client" from "shared egress", which is all the column claims.
	stmt := fmt.Sprintf(`
        SELECT ip,
               MAX(ja4)                 AS ja4,
               MAX(ua)                  AS ua,
               COUNT(DISTINCT ja4)      AS ja4n,
               COALESCE(SUM(cnt), 0)    AS reqs,
               MAX(last_seen)           AS last_seen
        FROM unmask_cookie_ip_minute
        WHERE %s%s AND kind = ?
        GROUP BY ip
        ORDER BY reqs DESC, last_seen DESC LIMIT ?`, minWindow(ctx, hours, "bucket_min"), cond)
	rows, err := d.QueryContext(ctx, stmt, kind, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CookieReuseRow
	for rows.Next() {
		var raw []byte
		var ja4n, reqs int
		var ja4, ua, ls sql.NullString
		if err := rows.Scan(&raw, &ja4, &ua, &ja4n, &reqs, &ls); err != nil {
			return nil, err
		}
		out = append(out, CookieReuseRow{
			IP: ipFromBytes(raw), JA4: ja4.String,
			UA: truncate(ua.String, 80), UAFull: ua.String,
			JA4Count: ja4n, Requests: reqs,
			LastSeen: ls.String, LastSeenTS: parseDateTimeToUnix(ls.String),
		})
	}
	return out, rows.Err()
}

func RateLimitPaths(ctx context.Context, d *db.DB, site string, hosts []string, hours, limit int) ([]RLPathRow, error) {
	jsonRL := jsonExtract(d, "payload_json", "$.rl")
	jsonPath := jsonExtract(d, "payload_json", "$.orig_path")
	// When aggregating by path, drop the query string (= merge different queries
	// for /api/x into a single row). The SUBSTRING function name differs per driver:
	//   SQLite : CASE WHEN instr(p, '?') > 0 THEN substr(p, 1, instr(p, '?')-1) ELSE p END
	//   MySQL  : SUBSTRING_INDEX(p, '?', 1)
	var pathExpr string
	if d.Driver == db.DriverSQLite {
		pathExpr = fmt.Sprintf(`CASE WHEN instr(%s, '?') > 0 THEN substr(%s, 1, instr(%s, '?')-1) ELSE %s END`,
			jsonPath, jsonPath, jsonPath, jsonPath)
	} else {
		pathExpr = fmt.Sprintf(`SUBSTRING_INDEX(%s, '?', 1)`, jsonPath)
	}
	stmt := fmt.Sprintf(`
        SELECT %s AS path, COUNT(*) AS n
        FROM unmask_event
        WHERE %s%s AND phase='serve' AND %s IN ('1', 1)
          AND %s IS NOT NULL AND %s <> ''
        GROUP BY path ORDER BY n DESC LIMIT ?`,
		pathExpr, tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts), jsonRL, jsonPath, jsonPath)
	rows, err := d.QueryContext(ctx, stmt, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []RLPathRow
	for rows.Next() {
		var p sql.NullString
		var n int
		if err := rows.Scan(&p, &n); err != nil {
			return nil, err
		}
		path := strings.Trim(p.String, `"`)
		out = append(out, RLPathRow{Path: path, Count: n})
	}
	return out, rows.Err()
}

// RLQueryCount: a single query string for a given path with its count.
type RLQueryCount struct {
	Query string
	Count int
}

// RateLimitQueriesByPath: returns the top-N frequent query strings per path.
// Result: path string → []RLQueryCount (= count desc, up to perPathLimit entries).
// Empty queries (= requests with no query string) are skipped.
func RateLimitQueriesByPath(ctx context.Context, d *db.DB, site string, hosts []string, hours, perPathLimit int) (map[string][]RLQueryCount, error) {
	jsonRL := jsonExtract(d, "payload_json", "$.rl")
	jsonPath := jsonExtract(d, "payload_json", "$.orig_path")
	// Split path / query in SQL.
	var pathExpr, queryExpr string
	if d.Driver == db.DriverSQLite {
		pathExpr = fmt.Sprintf(`CASE WHEN instr(%s, '?') > 0 THEN substr(%s, 1, instr(%s, '?')-1) ELSE %s END`,
			jsonPath, jsonPath, jsonPath, jsonPath)
		queryExpr = fmt.Sprintf(`CASE WHEN instr(%s, '?') > 0 THEN substr(%s, instr(%s, '?')+1) ELSE '' END`,
			jsonPath, jsonPath, jsonPath)
	} else {
		pathExpr = fmt.Sprintf(`SUBSTRING_INDEX(%s, '?', 1)`, jsonPath)
		queryExpr = fmt.Sprintf(`CASE WHEN LOCATE('?', %s) > 0 THEN SUBSTRING(%s, LOCATE('?', %s)+1) ELSE '' END`,
			jsonPath, jsonPath, jsonPath)
	}
	stmt := fmt.Sprintf(`
        SELECT %s AS p, %s AS q, COUNT(*) AS n
        FROM unmask_event
        WHERE %s%s AND phase='serve' AND %s IN ('1', 1)
          AND %s IS NOT NULL AND %s <> ''
        GROUP BY p, q
        HAVING q <> ''
        ORDER BY p, n DESC`,
		pathExpr, queryExpr, tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts), jsonRL, jsonPath, jsonPath)
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[string][]RLQueryCount{}
	for rows.Next() {
		var p, q sql.NullString
		var n int
		if err := rows.Scan(&p, &q, &n); err != nil {
			return nil, err
		}
		path := strings.Trim(p.String, `"`)
		query := strings.Trim(q.String, `"`)
		if len(out[path]) >= perPathLimit {
			continue // already at top N, skip
		}
		out[path] = append(out[path], RLQueryCount{Query: query, Count: n})
	}
	return out, rows.Err()
}

func RateLimitSummary(ctx context.Context, d *db.DB, site string, hosts []string, hours int) (RLSummary, error) {
	jsonRL := jsonExtract(d, "payload_json", "$.rl")
	stmt := fmt.Sprintf(`
        SELECT COUNT(*) AS n,
               MIN(date_created) AS f,
               MAX(date_created) AS t
        FROM unmask_event
        WHERE %s%s AND phase='serve' AND %s IN ('1', 1)`,
		tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts), jsonRL)
	row := d.QueryRowContext(ctx, stmt)
	var s RLSummary
	var n sql.NullInt64
	var f, t sql.NullString
	if err := row.Scan(&n, &f, &t); err != nil {
		return s, err
	}
	s.Total = int(n.Int64)
	s.From = f.String
	s.To = t.String
	return s, nil
}

// splitReasons turns a GROUP_CONCAT(DISTINCT force_reason) result into a slice,
// dropping empty entries (the "none"-folded NULLs leave nothing to show).
func splitReasons(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// VerifyNGRow: verify_ng IP ranking with method (math/behavioral) breakdown.
type VerifyNGRow struct {
	IP          string
	Total       int
	Math        int
	Behavioral  int
	AvgScore    float64
	UA          string
	UAFull      string // raw UA before truncate, for cellpop full-value popover
	JA4         string
	LastSeen    string
	LastSeenTS  int64
	CountryCode string
	// ForceReasons: the distinct escalation axes behind this IP's failures
	// ("none" dropped) -- an IP is usually escalated by one rule, so this reads
	// as a single badge; mixed rules show the honest set.
	ForceReasons []string
}

func VerifyNGRanking(ctx context.Context, d *db.DB, site string, hosts []string, hours, limit int) ([]VerifyNGRow, error) {
	method := jsonExtract(d, "payload_json", "$.method")
	score := jsonExtract(d, "payload_json", "$.score")
	fr := jsonExtract(d, "payload_json", "$.force_reason")
	// GROUP_CONCAT(DISTINCT ...) with "none"/NULL folded to NULL so the join
	// keeps only the real escalation axes; portable across SQLite + MariaDB
	// (both default the separator to ",").
	stmt := fmt.Sprintf(`
        SELECT ip_address,
               COUNT(*) AS total,
               SUM(CASE WHEN %s = 'math' THEN 1 ELSE 0 END) AS n_math,
               COUNT(*) - SUM(CASE WHEN %s = 'math' THEN 1 ELSE 0 END) AS n_beh,
               AVG(%s + 0.0) AS avg_score,
               MAX(user_agent) AS ua,
               MAX(COALESCE(ja4_verdict, '(none)')) AS ja4,
               MAX(date_created) AS last_seen,
               GROUP_CONCAT(DISTINCT NULLIF(COALESCE(%s, 'none'), 'none')) AS reasons
        FROM unmask_event WHERE %s%s AND phase='verify_ng'
        GROUP BY ip_address ORDER BY total DESC LIMIT ?`, method, method, score, fr, tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts))
	rows, err := d.QueryContext(ctx, stmt, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VerifyNGRow
	for rows.Next() {
		var raw []byte
		var total int
		var math, beh sql.NullInt64
		var avg sql.NullFloat64
		var ua, ja4, ls, reasons sql.NullString
		if err := rows.Scan(&raw, &total, &math, &beh, &avg, &ua, &ja4, &ls, &reasons); err != nil {
			return nil, err
		}
		out = append(out, VerifyNGRow{
			IP: ipFromBytes(raw), Total: total,
			Math: int(math.Int64), Behavioral: int(beh.Int64),
			AvgScore:     avg.Float64,
			UA:           truncate(ua.String, 50),
			UAFull:       ua.String,
			JA4:          ja4.String,
			LastSeen:     ls.String,
			LastSeenTS:   parseDateTimeToUnix(ls.String),
			ForceReasons: splitReasons(reasons.String),
		})
	}
	return out, rows.Err()
}

// CookieFailRow: bv_pow_only rows where challenge.js reported cookie_set_ok=false
// (= _bv write was blocked client-side; only the PoW-only terminal carries this
// flag because that's the only branch that writes the cookie from JS).
type CookieFailRow struct {
	IP          string
	Count       int
	UA          string
	UAFull      string // raw UA before truncate, for cellpop full-value popover
	LastSeen    string
	LastSeenTS  int64
	CountryCode string
}

func CookieSetFails(ctx context.Context, d *db.DB, site string, hosts []string, hours int) ([]CookieFailRow, error) {
	cookieOK := jsonExtract(d, "payload_json", "$.cookie_set_ok")
	stmt := fmt.Sprintf(`
        SELECT ip_address, COUNT(*) AS n, MAX(user_agent) AS ua, MAX(date_created) AS ls
        FROM unmask_event
        WHERE %s%s AND phase='bv_pow_only' AND %s IN ('false', 0)
        GROUP BY ip_address ORDER BY n DESC LIMIT 30`, tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts), cookieOK)
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []CookieFailRow
	for rows.Next() {
		var raw []byte
		var n int
		var ua, ls sql.NullString
		if err := rows.Scan(&raw, &n, &ua, &ls); err != nil {
			return nil, err
		}
		out = append(out, CookieFailRow{IP: ipFromBytes(raw), Count: n, UA: truncate(ua.String, 50), UAFull: ua.String, LastSeen: ls.String, LastSeenTS: parseDateTimeToUnix(ls.String)})
	}
	return out, rows.Err()
}

// StealthRow: clients with a bot/suspect ja4_verdict that nonetheless passed
// the CAPTCHA and obtained an _bv cookie (= phase bv_captcha_only or
// bv_pow_then_captcha).  PoW-only passes (bv_pow_only) are deliberately
// excluded — PoW is automatable by design, so only a CAPTCHA pass is a
// meaningful "stealth bot got through" signal.
type StealthRow struct {
	IP          string
	Verdict     string
	UA          string
	UAFull      string // raw UA before truncate, for cellpop full-value popover
	Count       int
	LastSeen    string
	LastSeenTS  int64
	CountryCode string
}

// StealthPassed: botVerdicts is the list of verdict names configured as
// action=bot or suspect in settings. Prefix-based detection is removed
// (= supports arbitrary naming).
func StealthPassed(ctx context.Context, d *db.DB, site string, hosts []string, hours int, botVerdicts []string) ([]StealthRow, error) {
	if len(botVerdicts) == 0 {
		return nil, nil // no verdicts marked as bot → stealth is 0 by definition
	}
	botIn, botArgs := inClause(botVerdicts)
	stmt := fmt.Sprintf(`
        SELECT ip_address, COALESCE(ja4_verdict,'(none)') AS v,
               MAX(user_agent) AS ua, COUNT(*) AS n, MAX(date_created) AS ls
        FROM unmask_event
        WHERE %s%s
          AND phase IN ('bv_captcha_only','bv_pow_then_captcha')
          AND ja4_verdict %s
        GROUP BY ip_address, ja4_verdict ORDER BY n DESC LIMIT 30`, tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts), botIn)
	rows, err := d.QueryContext(ctx, stmt, botArgs...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []StealthRow
	for rows.Next() {
		var raw []byte
		var v string
		var ua, ls sql.NullString
		var n int
		if err := rows.Scan(&raw, &v, &ua, &n, &ls); err != nil {
			return nil, err
		}
		out = append(out, StealthRow{
			IP: ipFromBytes(raw), Verdict: v, UA: truncate(ua.String, 80), UAFull: ua.String,
			Count: n, LastSeen: ls.String, LastSeenTS: parseDateTimeToUnix(ls.String),
		})
	}
	return out, rows.Err()
}

// JSErrorRow: a JS error carried in payload of the error phase.
type JSErrorRow struct {
	IP          string
	UA          string
	UAFull      string // raw UA before truncate, for cellpop full-value popover
	Flags       int
	Error       string
	Date        string
	DateTS      int64
	CountryCode string
}

// jsForeignCond: error-phase rows whose source is NOT unmask's own code.
// challenge.js classifies at capture time (payload kind=js_foreign: in-app
// webview bridges, extensions, carrier-injected scripts); rows ingested
// before that classification existed are caught by the masked message
// cross-origin scripts always produce ("Script error.").
func jsForeignCond(d *db.DB) string {
	kind := jsonExtract(d, "payload_json", "$.kind")
	errMsg := jsonExtract(d, "payload_json", "$.error_msg")
	return fmt.Sprintf("(COALESCE(%s,'') = 'js_foreign' OR COALESCE(%s,'') = 'Script error.')", kind, errMsg)
}

func jsErrorRows(ctx context.Context, d *db.DB, site string, hosts []string, hours int, foreign bool, limit int) ([]JSErrorRow, error) {
	errMsg := jsonExtract(d, "payload_json", "$.error_msg")
	cond := "NOT " + jsForeignCond(d)
	if foreign {
		cond = jsForeignCond(d)
	}
	stmt := fmt.Sprintf(`
        SELECT ip_address, user_agent, flags, %s AS err, date_created
        FROM unmask_event
        WHERE %s%s AND phase='error' AND %s
        ORDER BY id DESC LIMIT %d`, errMsg, tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts), cond, limit)
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []JSErrorRow
	for rows.Next() {
		var raw []byte
		var ua, errStr, ds sql.NullString
		var fl int
		if err := rows.Scan(&raw, &ua, &fl, &errStr, &ds); err != nil {
			return nil, err
		}
		out = append(out, JSErrorRow{
			IP: ipFromBytes(raw), UA: truncate(ua.String, 80), UAFull: ua.String, Flags: fl,
			Error:  truncate(strings.Trim(errStr.String, `"`), 120),
			Date:   ds.String,
			DateTS: parseDateTimeToUnix(ds.String),
		})
	}
	return out, rows.Err()
}

// JSErrors: failures attributable to the challenge page itself (inline page
// script / /unmask/ assets / external CAPTCHA provider kinds).
func JSErrors(ctx context.Context, d *db.DB, site string, hosts []string, hours int) ([]JSErrorRow, error) {
	return jsErrorRows(ctx, d, site, hosts, hours, false, 30)
}

// JSForeignErrors: ambient noise from scripts unmask did not ship.  Stored
// verbatim like every raw event; only the dashboard presentation separates
// them so they don't bury real challenge-JS failures.
func JSForeignErrors(ctx context.Context, d *db.DB, site string, hosts []string, hours int) ([]JSErrorRow, error) {
	return jsErrorRows(ctx, d, site, hosts, hours, true, 15)
}

// JSForeignErrorCount: window total of foreign-script error rows (the list
// above is capped at 15, the count shows the real volume).
func JSForeignErrorCount(ctx context.Context, d *db.DB, site string, hosts []string, hours int) (int, error) {
	stmt := fmt.Sprintf(`
        SELECT COUNT(*)
        FROM unmask_event
        WHERE %s%s AND phase='error' AND %s`,
		tsWindow(ctx, hours, "date_created"), siteCond(site)+hostCond(hosts), jsForeignCond(d))
	var n int
	if err := d.QueryRowContext(ctx, stmt).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

// DailyBucket: daily trend series.
type DailyBucket struct {
	Date             string
	Serve            int
	Load             int
	PowPass          int // chain midpoint: PoW solved, handing off to next stage
	Captcha          int
	BVPowOnly        int // _bv issued via challenge_mode=pow_only
	BVCaptchaOnly    int // _bv issued via challenge_mode=captcha_only
	BVPowThenCaptcha int // _bv issued via challenge_mode=pow_then_captcha
}

// is_bot kind: same as classify.Category (= 0/1/2/4/5/6) + 99 = rate_limit (= >100r/min).
const KindRateLimit = 99

// pass kind: 4-way breakdown for the 30-day chart (= derived from unmask_cookie_minute).
//
//	KindWhitePass  : passed through with no signal (= cnt_total - bv - bp - fc)
//	KindCaptchaPass: holds CAPTCHA-passed cookie (= cnt_bv / _bv cookie)
//	KindPoWPass    : holds PoW-passed cookie (= cnt_bp / _br cookie)
//	KindNotPass    : received a challenge (= cnt_fc)
//
// Numeric order = stacked-bar stack order, so white → captcha → pow → not_pass.
const (
	KindWhitePass   = 1
	KindCaptchaPass = 2
	KindPoWPass     = 3
	KindNotPass     = 4
)

// DailyKindBucket: per-(date × is_bot kind) request count.
type DailyKindBucket struct {
	Date string
	Kind int
	Req  int
}

// DailyTotal: per-day totals (req + uniq IP).
type DailyTotal struct {
	Date    string
	Req     int
	UniqIPs int
}

// CountryRow: per-country totals (= for the right-side horizontal bar on the 30-day chart).
type CountryRow struct {
	CountryCode string // ISO 3166-1 alpha-2 (= "JP", "US")
	Req         int
	UniqIPs     int
}

// DailyServeByKind: per-(date × kind) request counts for the 30-day chart 2,
// plus per-day req + uniq IP totals.
//
// Return:
//   - daily: list of (date, kind, req) for the stacked bar
//   - total: list of per-day req + uniq IP
//
// Fast path reads pre-aggregated rows from unmask_aggregate (written hourly by
// `unmask aggregate` → AggregateServeKind).  Scanning the large, growing
// unmask_event table on every dashboard load was the page's dominant latency;
// the pre-aggregation moves that cost to the hourly cron.  Falls back to a
// live scan when a host filter is active (unmask_aggregate has no host
// dimension) or when the aggregate table has not been populated yet.
// eventTimeLayouts lists the date_created layouts unmask has used over time;
// SQLite hands TEXT back, MariaDB a time.Time.  Kept private to the dashboard
// package -- the events package has its own (different signature) variant.
var eventTimeLayouts = []string{
	"2006-01-02 15:04:05.000",
	"2006-01-02T15:04:05.000Z",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05Z",
}

// normalizeEventTime turns a driver-returned date_created cell into a UTC
// time.Time so callers can apply *time.Location for the operator's cookie TZ.
// Returns (zero, false) when the value cannot be parsed.
func normalizeEventTime(v any) (time.Time, bool) {
	switch x := v.(type) {
	case time.Time:
		return x.UTC(), true
	case []byte:
		return parseEventTimeStr(string(x))
	case string:
		return parseEventTimeStr(x)
	}
	return time.Time{}, false
}

func parseEventTimeStr(s string) (time.Time, bool) {
	for _, layout := range eventTimeLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t.UTC(), true
		}
	}
	return time.Time{}, false
}

func DailyServeByKind(ctx context.Context, d *db.DB, site string, hosts []string, days int, botVerdicts []string, tz *time.Location) ([]DailyKindBucket, []DailyTotal, error) {
	t0 := time.Now()
	defer func() {
		if elapsed := time.Since(t0); elapsed > 500*time.Millisecond {
			log.Printf("DailyServeByKind: %v elapsed (slow)", elapsed)
		}
	}()
	// Aggregate fast path: unmask_aggregate_hourly stores per-(hour, ua-class,
	// verdict) counts and a per-hour HLL of distinct IPs.  We pull those rows
	// and group them in Go using *time.Location, so the day boundaries follow
	// the operator's cookie TZ -- the constraint that made the old DATE-column
	// fast path impossible.  Site / host filters and the brief post-restart
	// window still drop to the raw scan.
	if HourlyAggReady() && site == "" && len(hosts) == 0 {
		return dailyServeByKindAgg(ctx, d, days, botVerdicts, tz)
	}
	return dailyServeByKindScan(ctx, d, site, hosts, days, botVerdicts, tz)
}

// dailyServeByKindAgg reads hkServeKind / hkServeIP from
// unmask_aggregate_hourly + _hll and folds the hour buckets into the
// operator's cookie TZ on the way out.  ja4Action="" was used at rollup time,
// so the read side promotes ua_class=Human + verdict ∈ botVerdicts to JA4Bot
// here -- the only piece classify needs that the rollup couldn't preserve.
func dailyServeByKindAgg(ctx context.Context, d *db.DB, days int, botVerdicts []string, tz *time.Location) ([]DailyKindBucket, []DailyTotal, error) {
	if tz == nil {
		tz = time.UTC
	}
	botSet := map[string]bool{}
	for _, v := range botVerdicts {
		botSet[v] = true
	}

	hours := days * 24
	cntStmt := fmt.Sprintf(`
        SELECT bucket_hour, bucket_key, cnt
        FROM unmask_aggregate_hourly
        WHERE bucket_kind = '%s'
          AND %s`, hkServeKind, hourWindow(ctx, hours, "bucket_hour"))
	rows, err := d.QueryContext(ctx, cntStmt)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	type dkKey struct {
		date string
		kind int
	}
	byDateKind := map[dkKey]int{}
	type totAcc struct {
		req int
	}
	byTotal := map[string]*totAcc{}

	for rows.Next() {
		var bucketHour, key string
		var cnt int
		if err := rows.Scan(&bucketHour, &key, &cnt); err != nil {
			return nil, nil, err
		}
		// bucket_hour is 'YYYY-MM-DD HH' (UTC).  Parse and shift to the
		// operator's TZ before the date label is assigned.
		hourT, err := time.ParseInLocation("2006-01-02 15", bucketHour, time.UTC)
		if err != nil {
			continue
		}
		date := hourT.In(tz).Format("2006-01-02")
		// key = '<ua_class>|<verdict>'.  Split + promote ua_class=Human to
		// JA4Bot when the verdict is currently flagged a bot verdict.
		sep := strings.IndexByte(key, '|')
		if sep < 0 {
			continue
		}
		uaClassN, perr := strconv.Atoi(key[:sep])
		if perr != nil {
			continue
		}
		verdict := key[sep+1:]
		kind := classify.Category(uaClassN)
		// Mirror classify.IsBot precedence: a bot JA4 verdict promotes ANY
		// non-search category (Human/OldUA/Service/UserDev) to JA4Bot.  The scan
		// path (IsBot(ua,"bot")) already does this, so promoting only Human here
		// made the default agg view under-report ja4_bot vs the filtered view.
		if kind != classify.SearchAI && verdict != "(none)" && botSet[verdict] {
			kind = classify.JA4Bot
		}
		byDateKind[dkKey{date, int(kind)}] += cnt
		tot := byTotal[date]
		if tot == nil {
			tot = &totAcc{}
			byTotal[date] = tot
		}
		tot.req += cnt
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	// distinct IP per (operator-TZ day) via per-hour HLL merge.
	hllStmt := fmt.Sprintf(`
        SELECT bucket, sketch
        FROM unmask_aggregate_hll
        WHERE bucket_kind = '%s'
          AND %s`, hkServeIP, hourWindow(ctx, hours, "bucket"))
	hRows, err := d.QueryContext(ctx, hllStmt)
	if err != nil {
		return nil, nil, err
	}
	defer hRows.Close()
	sketchByDay := map[string]*hll{}
	for hRows.Next() {
		var bucketHour string
		var blob []byte
		if err := hRows.Scan(&bucketHour, &blob); err != nil {
			return nil, nil, err
		}
		hourT, err := time.ParseInLocation("2006-01-02 15", bucketHour, time.UTC)
		if err != nil {
			continue
		}
		date := hourT.In(tz).Format("2006-01-02")
		h := loadHLL(blob)
		if existing, ok := sketchByDay[date]; ok {
			existing.merge(h)
		} else {
			sketchByDay[date] = h
		}
	}
	if err := hRows.Err(); err != nil {
		return nil, nil, err
	}

	dailyKeys := make([]dkKey, 0, len(byDateKind))
	for k := range byDateKind {
		dailyKeys = append(dailyKeys, k)
	}
	sort.Slice(dailyKeys, func(i, j int) bool {
		if dailyKeys[i].date != dailyKeys[j].date {
			return dailyKeys[i].date < dailyKeys[j].date
		}
		return dailyKeys[i].kind < dailyKeys[j].kind
	})
	daily := make([]DailyKindBucket, 0, len(dailyKeys))
	for _, k := range dailyKeys {
		daily = append(daily, DailyKindBucket{Date: k.date, Kind: k.kind, Req: byDateKind[k]})
	}

	totals := make([]DailyTotal, 0, len(byTotal))
	for date, tot := range byTotal {
		uniq := 0
		if h := sketchByDay[date]; h != nil {
			uniq = int(h.estimate())
		}
		totals = append(totals, DailyTotal{Date: date, Req: tot.req, UniqIPs: uniq})
	}
	sort.Slice(totals, func(i, j int) bool { return totals[i].Date < totals[j].Date })

	return daily, totals, nil
}

// dailyServeByKindScan is the only serve-kind read path.  The previous
// "aggregate fast path" (dailyServeByKindAgg + AggregateServeKind) wrote
// per-day rows into unmask_aggregate using a DATE column, which cannot honour
// a per-operator cookie TZ.  Both were retired in favour of this raw scan,
// which is still cheap (~100 ms at 100k events / 30 days).  Two scans, each producing a
// small result set: query A groups by (date, verdict, ua-prefix) — deliberately
// NOT by ip_address (including ip yields ~200k rows on a busy 30-day window) —
// and query B groups by date only for COUNT(*) + COUNT(DISTINCT ip_address).
func dailyServeByKindScan(ctx context.Context, d *db.DB, site string, hosts []string, days int, botVerdicts []string, tz *time.Location) ([]DailyKindBucket, []DailyTotal, error) {
	if tz == nil {
		tz = time.UTC
	}
	jsonRL := jsonExtract(d, "payload_json", "$.rl")
	cond := siteCond(site) + hostCond(hosts)
	// rate_limit serve hits are orthogonal to the bot-type breakdown and are
	// excluded (they have a dedicated rate_limit card).  Filtering them in
	// WHERE keeps is_rl out of the GROUP BY.  COALESCE guards a NULL
	// payload_json (no rl key) → '' → kept.
	notRL := fmt.Sprintf("COALESCE(%s, '') NOT IN ('1', 1)", jsonRL)

	type dkKey struct {
		date string
		kind int
	}
	byDateKind := map[dkKey]int{}

	// classify cache (= same (ua, isJA4Bot) tuple always maps to the same kind).
	// Memoize because IsBot runs a regex with 600 alternations per call.
	botSet := map[string]bool{}
	for _, v := range botVerdicts {
		botSet[v] = true
	}
	type classifyKey struct {
		ua    string
		isBot bool
	}
	classifyCache := make(map[classifyKey]int, 256)

	// Read the raw serve rows and bucket them per (TZ-shifted date, ua-prefix,
	// verdict) in Go.  GROUP BY in SQL would force a server-side DATE() that
	// can't honour the operator's cookie TZ; doing it here keeps the day
	// boundaries correct under any TZ.  We project the timestamp + 80-char
	// ua prefix only, so even at ~100k events / 30d the row payload is small.
	stmt := fmt.Sprintf(`
        SELECT date_created,
               COALESCE(ja4_verdict, '') AS verdict,
               COALESCE(SUBSTR(user_agent, 1, 80), '') AS ua,
               ip_address
        FROM unmask_event
        WHERE phase='serve' AND %s AND %s%s`,
		tsWindow(ctx, days*24, "date_created"), notRL, cond)
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	type totAcc struct {
		req  int
		seen map[string]struct{}
	}
	byTotal := map[string]*totAcc{}

	for rows.Next() {
		var ts any
		var verdict, ua, ip string
		if err := rows.Scan(&ts, &verdict, &ua, &ip); err != nil {
			return nil, nil, err
		}
		t, ok := normalizeEventTime(ts)
		if !ok {
			continue
		}
		date := t.In(tz).Format("2006-01-02")
		isBot := botSet[verdict]
		ck := classifyKey{ua, isBot}
		kind, ok := classifyCache[ck]
		if !ok {
			action := ""
			if isBot {
				action = "bot"
			}
			kind = int(classify.IsBot(ua, action))
			classifyCache[ck] = kind
		}
		byDateKind[dkKey{date, kind}]++

		tot := byTotal[date]
		if tot == nil {
			tot = &totAcc{seen: make(map[string]struct{})}
			byTotal[date] = tot
		}
		tot.req++
		if ip != "" {
			tot.seen[ip] = struct{}{}
		}
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	// daily: sort by date asc, kind asc
	dailyKeys := make([]dkKey, 0, len(byDateKind))
	for k := range byDateKind {
		dailyKeys = append(dailyKeys, k)
	}
	sort.Slice(dailyKeys, func(i, j int) bool {
		if dailyKeys[i].date != dailyKeys[j].date {
			return dailyKeys[i].date < dailyKeys[j].date
		}
		return dailyKeys[i].kind < dailyKeys[j].kind
	})
	daily := make([]DailyKindBucket, 0, len(dailyKeys))
	for _, k := range dailyKeys {
		daily = append(daily, DailyKindBucket{Date: k.date, Kind: k.kind, Req: byDateKind[k]})
	}

	// totals: sort by date asc
	totals := make([]DailyTotal, 0, len(byTotal))
	for date, tot := range byTotal {
		totals = append(totals, DailyTotal{Date: date, Req: tot.req, UniqIPs: len(tot.seen)})
	}
	sort.Slice(totals, func(i, j int) bool { return totals[i].Date < totals[j].Date })

	return daily, totals, nil
}

// DailyPassByDay: aggregate all nginx requests from unmask_cookie_minute by
// date and return a stacked-bar list with 3 categories: white_pass / pow_pass /
// not_pass.
//
// Data source: nginx access_log syslog datagram → memory bucket → DB UPSERT.
// In environments where http.inc is not included in http {}, the
// table stays empty (= returns all zeros).
//
// Day boundaries are UTC (= SQLite DATE(...,unixepoch) without 'localtime' /
// MariaDB DATE(FROM_UNIXTIME(...)) under session time_zone='+00:00').  The
// operator's cookie TZ is then applied by the caller via *time.Location.
// Uniq IP cannot be computed because the
// cookie_minute table has no IP column → DailyTotal.UniqIPs is left at 0
// (= per-IP detail is available via ip-popover / a separate card).
func DailyPassByDay(ctx context.Context, d *db.DB, site string, hosts []string, days int, tz *time.Location) ([]DailyKindBucket, []DailyTotal, error) {
	if tz == nil {
		tz = time.UTC
	}
	type acc struct{ total, bv, bp, fc int }
	byDate := map[string]*acc{}
	var ordered []string // dates in first-seen order; sorted ascending before output
	get := func(date string) *acc {
		a := byDate[date]
		if a == nil {
			a = &acc{}
			byDate[date] = a
			ordered = append(ordered, date)
		}
		return a
	}

	win := windowOr(ctx, days*24)
	cutoffMin := win.Start / 60
	untilMin := win.End / 60
	liveFromMin := cutoffMin

	// The default (all-sites) view reads settled hours from the install-wide
	// hourly rollup (hkCookiePass, ~720 rows) instead of scanning ~333k
	// per-minute, per-site rows; the current unsettled hours come from the live
	// per-minute tail below.  A site-scoped view has no fan-out to avoid, so it
	// reads the per-minute table for the whole window (settled path skipped, so
	// the cursor stays effectively -1 and liveFromMin is the window start).
	cond := siteCond(site) // validates via siteValRE; never interpolate site raw
	if cond == "" {
		cursor, err := stateCursor(ctx, d, installWideState)
		if err != nil {
			return nil, nil, err
		}
		if cursor >= 0 {
			cutoffHour := time.Unix(cutoffMin*60, 0).UTC().Format("2006-01-02 15")
			// Cap the settled upper bound at the window end (a custom range that
			// ends in the past must not pull settled hours past it).
			upToSec := cursor * 3600
			if u := untilMin * 60; u < upToSec {
				upToSec = u
			}
			upToHour := time.Unix(upToSec, 0).UTC().Format("2006-01-02 15")
			hrows, err := d.QueryContext(ctx,
				`SELECT bucket_hour, bucket_key, cnt FROM unmask_aggregate_hourly
                WHERE bucket_kind = ? AND bucket_hour >= ? AND bucket_hour <= ?`,
				hkCookiePass, cutoffHour, upToHour)
			if err != nil {
				return nil, nil, err
			}
			for hrows.Next() {
				var bucketHour, kind string
				var cnt int
				if err := hrows.Scan(&bucketHour, &kind, &cnt); err != nil {
					hrows.Close()
					return nil, nil, err
				}
				t, perr := time.ParseInLocation("2006-01-02 15", bucketHour, time.UTC)
				if perr != nil {
					continue // unparseable bucket: skip rather than mis-date
				}
				a := get(t.In(tz).Format("2006-01-02"))
				switch kind {
				case "total":
					a.total += cnt
				case "captcha":
					a.bv += cnt
				case "pow":
					a.bp += cnt
				case "challenge_served":
					a.fc += cnt
				}
			}
			if err := hrows.Err(); err != nil {
				hrows.Close()
				return nil, nil, err
			}
			hrows.Close()
			if m := (cursor + 1) * 60; m > liveFromMin {
				liveFromMin = m
			}
		}
	}

	// Live tail (all-sites, after the cursor) or the whole window (site-scoped):
	// raw minute buckets aggregated per day in Go using the operator's cookie TZ.
	// This is what makes day boundaries follow the user (= 2026-05-30 in Tokyo
	// runs 2026-05-29 15:00 UTC -> 2026-05-30 14:59 UTC).
	stmt := fmt.Sprintf(`
        SELECT bucket_min,
               COALESCE(SUM(CASE WHEN kind = 'total'            THEN cnt ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN kind = 'captcha'          THEN cnt ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN kind = 'pow'              THEN cnt ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN kind = 'challenge_served' THEN cnt ELSE 0 END), 0)
        FROM unmask_cookie_minute
        WHERE bucket_min >= %d AND bucket_min <= %d%s
        GROUP BY bucket_min`, liveFromMin, untilMin, cond)
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var bucketMin int64
		var total, bv, bp, fc int
		if err := rows.Scan(&bucketMin, &total, &bv, &bp, &fc); err != nil {
			return nil, nil, err
		}
		a := get(time.Unix(bucketMin*60, 0).In(tz).Format("2006-01-02"))
		a.total += total
		a.bv += bv
		a.bp += bp
		a.fc += fc
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	sort.Strings(ordered)

	daily := []DailyKindBucket{}
	totals := []DailyTotal{}
	for _, date := range ordered {
		a := byDate[date]
		notPass := a.fc
		white := a.total - a.bv - a.bp - notPass
		if white < 0 {
			white = 0
		}
		// Drop 0-count buckets (= cleaner stacked bar on the chart)
		if white > 0 {
			daily = append(daily, DailyKindBucket{Date: date, Kind: KindWhitePass, Req: white})
		}
		if a.bv > 0 {
			daily = append(daily, DailyKindBucket{Date: date, Kind: KindCaptchaPass, Req: a.bv})
		}
		if a.bp > 0 {
			daily = append(daily, DailyKindBucket{Date: date, Kind: KindPoWPass, Req: a.bp})
		}
		if notPass > 0 {
			daily = append(daily, DailyKindBucket{Date: date, Kind: KindNotPass, Req: notPass})
		}
		totals = append(totals, DailyTotal{Date: date, Req: a.total, UniqIPs: 0})
	}
	return daily, totals, nil
}

// DailyCountryBucket: per-(date × country × kind) request count for the
// 30-day chart's country breakdown.  Same kind catalogue as DailyKindBucket
// so the read side can render both with the same stack semantics.
type DailyCountryBucket struct {
	Date    string
	Country string // ISO 2-letter; "" = unmappable (rendered as "Unknown")
	Kind    int    // KindWhitePass / KindCaptchaPass / KindPoWPass / KindNotPass
	Req     int
}

// DailyUniq: per-day unique-IP estimate.
type DailyUniq struct {
	Date    string
	UniqIPs int64
}

// DailyPassByCountry: same axis as DailyPassByDay but split by client country.
// Returns one row per (date, country, kind) tuple; country="" carries requests
// that ipgeo could not resolve (= no mmdb, or private IP).
//
// Data source: unmask_traffic_country_hourly (= written by nginxlog.Reader on
// each hour flush, with country resolved per-packet through ipgeo).  When the
// nginxlog pipeline is not running, this table stays empty and the function
// returns an empty slice — callers should treat that as "country breakdown
// unavailable" and fall back to DailyPassByDay's totals.
func DailyPassByCountry(ctx context.Context, d *db.DB, site string, days int, tz *time.Location) ([]DailyCountryBucket, error) {
	if tz == nil {
		tz = time.UTC
	}
	type dcKey struct{ date, country string }
	type acc struct{ total, bv, bp, fc int }
	byKey := map[dcKey]*acc{}
	var ordered []dcKey
	get := func(date, country string) *acc {
		key := dcKey{date, country}
		a := byKey[key]
		if a == nil {
			a = &acc{}
			byKey[key] = a
			ordered = append(ordered, key)
		}
		return a
	}

	win := windowOr(ctx, days*24)
	cutoffHour := win.Start / 3600
	untilHour := win.End / 3600
	liveFromHour := cutoffHour

	// The default (all-sites) view reads settled hours from the install-wide
	// per-country rollup (hkCountryPass) instead of scanning every site's
	// country_hourly rows; the current unsettled hours come from the live tail
	// below.  A site-scoped view reads country_hourly directly for the whole
	// window (settled path skipped).  See DailyPassByDay for the rationale.
	cond := siteCond(site) // validates via siteValRE; never interpolate site raw
	if cond == "" {
		cursor, err := stateCursor(ctx, d, installWideCountryState)
		if err != nil {
			return nil, err
		}
		if cursor >= 0 {
			cutoffHourStr := time.Unix(cutoffHour*3600, 0).UTC().Format("2006-01-02 15")
			upToHour := cursor
			if untilHour < upToHour {
				upToHour = untilHour
			}
			upToHourStr := time.Unix(upToHour*3600, 0).UTC().Format("2006-01-02 15")
			srows, err := d.QueryContext(ctx,
				`SELECT bucket_hour, bucket_key, cnt FROM unmask_aggregate_hourly
                WHERE bucket_kind = ? AND bucket_hour >= ? AND bucket_hour <= ?`,
				hkCountryPass, cutoffHourStr, upToHourStr)
			if err != nil {
				return nil, err
			}
			for srows.Next() {
				var bucketHour, key string
				var cnt int
				if err := srows.Scan(&bucketHour, &key, &cnt); err != nil {
					srows.Close()
					return nil, err
				}
				t, perr := time.ParseInLocation("2006-01-02 15", bucketHour, time.UTC)
				if perr != nil {
					continue // unparseable bucket: skip rather than mis-date
				}
				country, kind, ok := strings.Cut(key, "|")
				if !ok {
					continue
				}
				a := get(t.In(tz).Format("2006-01-02"), country)
				switch kind {
				case "total":
					a.total += cnt
				case "captcha":
					a.bv += cnt
				case "pow":
					a.bp += cnt
				case "challenge_served":
					a.fc += cnt
				}
			}
			if err := srows.Err(); err != nil {
				srows.Close()
				return nil, err
			}
			srows.Close()
			if cursor+1 > liveFromHour {
				liveFromHour = cursor + 1
			}
		}
	}

	// Live tail (all-sites, after the cursor) or the whole window (site-scoped):
	// raw hourly buckets aggregated per (TZ-shifted date, country) in Go.
	stmt := fmt.Sprintf(`
        SELECT bucket_hour, country,
               COALESCE(SUM(CASE WHEN kind = 'total'            THEN cnt ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN kind = 'captcha'          THEN cnt ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN kind = 'pow'              THEN cnt ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN kind = 'challenge_served' THEN cnt ELSE 0 END), 0)
        FROM unmask_traffic_country_hourly
        WHERE bucket_hour >= %d AND bucket_hour <= %d%s
        GROUP BY bucket_hour, country`, liveFromHour, untilHour, cond)
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var bucketHour int64
		var cc sql.NullString
		var total, bv, bp, fc int
		if err := rows.Scan(&bucketHour, &cc, &total, &bv, &bp, &fc); err != nil {
			return nil, err
		}
		country := ""
		if cc.Valid {
			country = cc.String
		}
		a := get(time.Unix(bucketHour*3600, 0).In(tz).Format("2006-01-02"), country)
		a.total += total
		a.bv += bv
		a.bp += bp
		a.fc += fc
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Stable order: date asc, country asc.
	sort.Slice(ordered, func(i, j int) bool {
		if ordered[i].date != ordered[j].date {
			return ordered[i].date < ordered[j].date
		}
		return ordered[i].country < ordered[j].country
	})
	out := []DailyCountryBucket{}
	for _, k := range ordered {
		a := byKey[k]
		notPass := a.fc
		white := a.total - a.bv - a.bp - notPass
		if white < 0 {
			white = 0
		}
		if white > 0 {
			out = append(out, DailyCountryBucket{Date: k.date, Country: k.country, Kind: KindWhitePass, Req: white})
		}
		if a.bv > 0 {
			out = append(out, DailyCountryBucket{Date: k.date, Country: k.country, Kind: KindCaptchaPass, Req: a.bv})
		}
		if a.bp > 0 {
			out = append(out, DailyCountryBucket{Date: k.date, Country: k.country, Kind: KindPoWPass, Req: a.bp})
		}
		if notPass > 0 {
			out = append(out, DailyCountryBucket{Date: k.date, Country: k.country, Kind: KindNotPass, Req: notPass})
		}
	}
	return out, nil
}

// DailyUniqueIPs: per-day unique client-IP estimate, read off merged HLL
// sketches. Days are bucketed using the operator's cookie TZ so the labels
// align with DailyPassByDay's output.
//
// The window is split at the RollupTrafficHLL cursor: settled hours come
// pre-merged from unmask_aggregate_hll(bucket_kind=hkTrafficIP, ~24 sketches
// per day), and everything after the cursor is read live from the per-minute
// unmask_traffic_hll(kind='ip') table so the current hours never lag. Folding
// ~720 hourly sketches + a short tail keeps this well under the card timeout;
// merging all ~65k per-minute rows directly took ~15s and tripped it. When the
// rollup is behind (fresh start / post-downtime) the live side simply covers
// more hours and stays correct — the background rollup then catches up and
// later reads get fast again. When neither table has data the result is empty.
func DailyUniqueIPs(ctx context.Context, d *db.DB, site string, days int, tz *time.Location) ([]DailyUniq, error) {
	if tz == nil {
		tz = time.UTC
	}
	// Window in minute buckets.  Trailing fallback (no ctx window) reproduces the
	// old "now/60 - days*1440 .. now" bounds exactly; a custom range narrows both.
	win := windowOr(ctx, days*24)
	cutoffMin := win.Start / 60
	untilMin := win.End / 60
	// The default (site="") view reads the install-wide hourly sketch
	// (hkTrafficIPAll, one row per hour) folded by RollupInstallWideHourly on its
	// own cursor; a site-scoped view reads that site's per-site hourly sketch
	// (hkTrafficIP) on the traffic cursor.  Either way the live per-minute tail
	// below covers hours the rollup hasn't settled yet.
	// "all sites" (the default view) maps to the install-wide rollup; a real,
	// validated site maps to its per-site rollup.  Reuse siteCond's exact
	// all-vs-one test (it also folds "default"/invalid into "all") so this never
	// diverges from the live-tail filter below.
	perSite := siteCond(site) != ""
	settledKind, settledKey, cursorState := hkTrafficIPAll, "", installWideState
	if perSite {
		settledKind, settledKey, cursorState = hkTrafficIP, site, trafficIPState
	}
	cursor, err := stateCursor(ctx, d, cursorState)
	if err != nil {
		return nil, err
	}

	by := map[string]*hll{}
	var order []string
	get := func(date string) *hll {
		s, ok := by[date]
		if !ok {
			s = &hll{}
			by[date] = s
			order = append(order, date)
		}
		return s
	}

	// 1) settled hours from the hourly rollup (bucket = UTC 'YYYY-MM-DD HH',
	//    chronologically ordered as a fixed-width string).
	if cursor >= 0 {
		cutoffHour := time.Unix(cutoffMin*60, 0).UTC().Format("2006-01-02 15")
		// Cap the settled-hours upper bound at the window end, so a custom range
		// that ends in the past doesn't pull settled hours past it.
		upToSec := cursor * 3600
		if u := untilMin * 60; u < upToSec {
			upToSec = u
		}
		upToHour := time.Unix(upToSec, 0).UTC().Format("2006-01-02 15")
		rows, err := d.QueryContext(ctx,
			`SELECT bucket, sketch FROM unmask_aggregate_hll
            WHERE bucket_kind = ? AND bucket_key = ? AND bucket >= ? AND bucket <= ?`,
			settledKind, settledKey, cutoffHour, upToHour)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var bucket string
			var blob []byte
			if err := rows.Scan(&bucket, &blob); err != nil {
				rows.Close()
				return nil, err
			}
			t, perr := time.ParseInLocation("2006-01-02 15", bucket, time.UTC)
			if perr != nil {
				continue // unparseable bucket: skip rather than mis-date
			}
			get(t.In(tz).Format("2006-01-02")).mergeBytes(blob)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return nil, err
		}
		rows.Close()
	}

	// 2) live tail from the per-minute table: minutes after the cursor's last
	//    settled hour (or the whole window when nothing is rolled yet), never
	//    before the 30-day cutoff.
	liveMin := cutoffMin
	if cursor >= 0 {
		if m := (cursor + 1) * 60; m > liveMin {
			liveMin = m
		}
	}
	args := []any{liveMin, untilMin}
	cond := ""
	if perSite {
		cond = " AND site = ?"
		args = append(args, site)
	}
	rows, err := d.QueryContext(ctx,
		`SELECT bucket_min, sketch FROM unmask_traffic_hll
        WHERE kind = 'ip' AND bucket_min >= ? AND bucket_min <= ?`+cond, args...)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var bm int64
		var blob []byte
		if err := rows.Scan(&bm, &blob); err != nil {
			rows.Close()
			return nil, err
		}
		get(time.Unix(bm*60, 0).In(tz).Format("2006-01-02")).mergeBytes(blob)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	sort.Strings(order)
	out := make([]DailyUniq, 0, len(order))
	for _, date := range order {
		out = append(out, DailyUniq{Date: date, UniqIPs: int64(by[date].estimate())})
	}
	return out, nil
}

// CountriesByServe: aggregate phase='serve' per IP → ipgeo lookup → return
// per-country req / uniq IP aggregates. Returns an empty list when ipgeo.Reader
// is empty (= mmdb not configured / failed to load), so callers know not to
// show the country chart.
// CountriesByServe returns the top serve-traffic source countries. The default
// view (no site / no host filter) reads the hourly aggregate; filtered views
// and the pre-backfill window fall back to scanning raw events.
func CountriesByServe(ctx context.Context, d *db.DB, gip *ipgeo.Reader, site string, hosts []string, days, limit int) ([]CountryRow, error) {
	if gip == nil || !gip.Loaded() {
		return nil, nil
	}
	if site == "" && len(hosts) == 0 && HourlyAggReady() {
		return countriesAgg(ctx, d, days, limit)
	}
	return countriesScan(ctx, d, gip, site, hosts, days, limit)
}

func countriesScan(ctx context.Context, d *db.DB, gip *ipgeo.Reader, site string, hosts []string, days, limit int) ([]CountryRow, error) {
	stmt := fmt.Sprintf(`
        SELECT ip_address, COUNT(*) AS n
        FROM unmask_event
        WHERE %s%s AND phase='serve'
        GROUP BY ip_address`, tsWindow(ctx, days*24, "date_created"), siteCond(site)+hostCond(hosts))
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	type acc struct {
		req     int
		uniqIPs int
	}
	byCC := map[string]*acc{}
	for rows.Next() {
		var raw []byte
		var n int
		if err := rows.Scan(&raw, &n); err != nil {
			return nil, err
		}
		cc := gip.LookupBytes(raw)
		if cc == "" {
			continue
		}
		a, ok := byCC[cc]
		if !ok {
			a = &acc{}
			byCC[cc] = a
		}
		a.req += n
		a.uniqIPs++
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]CountryRow, 0, len(byCC))
	for cc, a := range byCC {
		out = append(out, CountryRow{CountryCode: cc, Req: a.req, UniqIPs: a.uniqIPs})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Req > out[j].Req })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// countriesAgg builds the country ranking from the aggregate: per-country
// serve counts summed from the hourly 'cc' buckets, distinct-IP estimated by
// merging the daily 'ccip' HLL sketches.
func countriesAgg(ctx context.Context, d *db.DB, days, limit int) ([]CountryRow, error) {
	type acc struct{ req, uniq int }
	byCC := map[string]*acc{}

	crows, err := d.QueryContext(ctx, `
        SELECT bucket_key, SUM(cnt) FROM unmask_aggregate_hourly
        WHERE `+hourWindow(ctx, days*24, "bucket_hour")+` AND bucket_kind = 'cc'
        GROUP BY bucket_key`)
	if err != nil {
		return nil, err
	}
	for crows.Next() {
		var cc string
		var req int
		if err := crows.Scan(&cc, &req); err != nil {
			crows.Close()
			return nil, err
		}
		byCC[cc] = &acc{req: req}
	}
	if err := crows.Err(); err != nil {
		crows.Close()
		return nil, err
	}
	crows.Close()

	sketches := map[string]*hll{}
	hrows, err := d.QueryContext(ctx, `
        SELECT bucket_key, sketch FROM unmask_aggregate_hll
        WHERE `+dateWindow(ctx, days*24, "bucket")+` AND bucket_kind = 'ccip'`)
	if err != nil {
		return nil, err
	}
	for hrows.Next() {
		var cc string
		var blob []byte
		if err := hrows.Scan(&cc, &blob); err != nil {
			hrows.Close()
			return nil, err
		}
		s := sketches[cc]
		if s == nil {
			s = &hll{}
			sketches[cc] = s
		}
		s.merge(loadHLL(blob))
	}
	if err := hrows.Err(); err != nil {
		hrows.Close()
		return nil, err
	}
	hrows.Close()
	for cc, s := range sketches {
		a := byCC[cc]
		if a == nil {
			a = &acc{}
			byCC[cc] = a
		}
		a.uniq = s.estimate()
	}

	out := make([]CountryRow, 0, len(byCC))
	for cc, a := range byCC {
		out = append(out, CountryRow{CountryCode: cc, Req: a.req, UniqIPs: a.uniq})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Req > out[j].Req })
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ---- legacy: per-phase daily series (= for the existing chart; deprecated) ----

func DailySeries(ctx context.Context, d *db.DB, days int, tz *time.Location) ([]DailyBucket, error) {
	if tz == nil {
		tz = time.UTC
	}
	stmt := fmt.Sprintf(`
        SELECT date_created, phase FROM unmask_event
        WHERE %s`, tsWindow(ctx, days*24, "date_created"))
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	by := map[string]*DailyBucket{}
	var order []string
	for rows.Next() {
		var ts any
		var phase string
		if err := rows.Scan(&ts, &phase); err != nil {
			return nil, err
		}
		t, ok := normalizeEventTime(ts)
		if !ok {
			continue
		}
		ds := t.In(tz).Format("2006-01-02")
		b, ok := by[ds]
		if !ok {
			b = &DailyBucket{Date: ds}
			by[ds] = b
			order = append(order, ds)
		}
		switch phase {
		case "serve":
			b.Serve++
		case "load":
			b.Load++
		case "pow_pass":
			b.PowPass++
		case "captcha":
			b.Captcha++
		case "bv_pow_only":
			b.BVPowOnly++
		case "bv_captcha_only":
			b.BVCaptchaOnly++
		case "bv_pow_then_captcha":
			b.BVPowThenCaptcha++
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]DailyBucket, 0, len(order))
	for _, k := range order {
		out = append(out, *by[k])
	}
	return out, nil
}

// ----------------------------------------------------------------
// helpers
// ----------------------------------------------------------------

// jsonExtract returns a SQL fragment that extracts a JSON path. SQLite and
// MariaDB use different function names / quoting.
func jsonExtract(d *db.DB, col, path string) string {
	if d.Driver == db.DriverSQLite {
		return fmt.Sprintf("json_extract(%s, '%s')", col, path)
	}
	return fmt.Sprintf("JSON_UNQUOTE(JSON_EXTRACT(%s, '%s'))", col, path)
}

func ipFromBytes(b []byte) string {
	switch len(b) {
	case 4:
		return net.IP(b).To4().String()
	case 16:
		return net.IP(b).To16().String()
	}
	return ""
}

func bin5(n int) string {
	return fmt.Sprintf("%05b", n&0x1F)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// Pinger: dashboard health helper.
func Pinger(d *db.DB) error {
	return d.PingContext(context.Background())
}

// --- observe-mode counters -------------------------------------------------

// ObserveOnlyWouldBlock counts the requests unmask judged as challenge or block
// during the window but let through because observe mode is on.
//
// Why this exists: the landing page's headline is "bot access unmask blocked",
// derived from challenges fired minus challenges passed.  In observe mode no
// challenge is ever fired, so that arithmetic yields zero -- and the card said
// "all quiet, no attacks", on an install whose traffic was mostly scanners.
// The judgement is still recorded (payload.would_be_action), so the honest
// number is available; it is simply a different question, asked here.
func ObserveOnlyWouldBlock(ctx context.Context, d *db.DB, site string, hosts []string, hours int) (int, error) {
	act := jsonExtract(d, "payload_json", "$.would_be_action")
	obs := jsonExtract(d, "payload_json", "$.observe_only")
	cond := siteCond(site)
	stmt := fmt.Sprintf(`
        SELECT COUNT(*) FROM unmask_event
        WHERE %s%s%s
          AND %s = 1
          AND %s IN ('challenge','block')`,
		tsWindow(ctx, hours, "date_created"), cond, hostCond(hosts), obs, act)
	var n int
	if err := d.QueryRowContext(ctx, stmt).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}
