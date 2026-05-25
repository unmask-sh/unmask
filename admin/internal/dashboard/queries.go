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
// plus 'default' even if no events.
func Sites(ctx context.Context, d *db.DB, hours int) ([]SiteSummary, error) {
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
        WHERE date_created > %s
        GROUP BY site`, d.NowMinusMinutes(hours*60))
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
	sort.SliceStable(out, func(i, j int) bool {
		// default first, then by event count desc
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
	return out, nil
}

// HostInfo: one observed unmask instance (= host) for the host inventory.
type HostInfo struct {
	HostID     string
	Events     int
	LastSeen   string
	LastSeenTS int64 // unix sec UTC; template renders via <time class="js-datetime">
}

// HostInventory returns one row per distinct host that has ever written to
// unmask_event, most-recently-active first.  Unlike Sites it has no time
// window: a retired instance should still appear (with an old last-seen) so
// the operator can spot stale entries in a shared DB.  Capped at 200.
func HostInventory(ctx context.Context, d *db.DB) ([]HostInfo, error) {
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
	since := d.NowMinusMinutes(hours * 60)
	sc := siteCond(site) + hostCond(hosts)

	// A) base aggregation by verdict × phase. SELECT id too so canon can use it.
	rows, err := d.QueryContext(ctx, fmt.Sprintf(`
        SELECT COALESCE(ja4_verdict, '(none)') AS v, ja4_verdict_id AS vid, phase, COUNT(*) AS n
        FROM unmask_event WHERE date_created > %s%s
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
        FROM unmask_event WHERE date_created > %s%s AND phase = 'load'
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
        FROM unmask_event WHERE date_created > %s%s AND phase = 'serve'
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
        WHERE bucket_hour >= `+hourAgoExpr(d, hours)+`
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

	// distinct-IP per verdict (phase=load) is not summable across buckets, so
	// read it raw over the same hour-aligned window as the aggregate.
	since := hourAgoTimestamp(d, hours)
	uq, err := d.QueryContext(ctx, fmt.Sprintf(`
        SELECT COALESCE(ja4_verdict, '(none)') AS v, ja4_verdict_id AS vid,
               COUNT(DISTINCT ip_address) AS uniq_ip
        FROM unmask_event WHERE date_created > %s AND phase = 'load'
        GROUP BY ja4_verdict, ja4_verdict_id`, since))
	if err != nil {
		return nil, err
	}
	for uq.Next() {
		var v string
		var vid, u sql.NullInt64
		if err := uq.Scan(&v, &vid, &u); err != nil {
			uq.Close()
			return nil, err
		}
		k := canonVerdict(reg, vid.Int64, v)
		e := loadByV[k]
		e.uniq += int(u.Int64)
		loadByV[k] = e
	}
	if err := uq.Err(); err != nil {
		uq.Close()
		return nil, err
	}
	uq.Close()

	return buildFunnelRows(ctx, d, "", nil, since, byVP, loadByV, rlByV, botVerdicts)
}

// buildFunnelRows turns the per-verdict aggregation maps into ordered
// FunnelRows: the rate_limit pseudo-row, the verdict rows in fixed order, then
// the TOTAL row. The rate-limit row and the total distinct-IP count are read
// raw from unmask_event over `since` (a SQL datetime expression); both Funnel
// paths supply a window-consistent `since`.
func buildFunnelRows(ctx context.Context, d *db.DB, site string, hosts []string, since string, byVP map[funnelVP]int, loadByV map[string]funnelLoad, rlByV map[string]int, botVerdicts []string) ([]FunnelRow, error) {
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

	// rate_limit row: aggregate all-phase transitions of IPs with rl=1 serves via IP join
	rlRow, err := rateLimitFunnelRow(ctx, d, site, hosts, since, botVerdicts)
	if err == nil {
		out = append([]FunnelRow{rlRow}, out...)
	}

	// total uniq is a separate SQL (= so the same IP is not counted across verdicts)
	row := d.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT COUNT(DISTINCT ip_address) FROM unmask_event WHERE date_created > %s%s AND phase = 'load'`,
		since, siteCond(site)+hostCond(hosts)))
	_ = row.Scan(&total.LoadUniq)
	if total.Load > 0 {
		total.PowRate = float64(total.PowSolved) / float64(total.Load)
		total.CaptchaRate = float64(total.Captcha) / float64(total.Load)
	}
	out = append(out, total)
	return out, nil
}

func rateLimitFunnelRow(ctx context.Context, d *db.DB, site string, hosts []string, since string, botVerdicts []string) (FunnelRow, error) {
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
        WHERE date_created > %s%s
          AND ip_address IN (
              SELECT ip_address FROM unmask_event
              WHERE date_created > %s%s AND phase='serve'
                AND %s IN ('1', 1)
          )`, since, sc, since, sc, jsonRL)
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
        FROM unmask_event WHERE date_created > %s%s
        GROUP BY ja4_verdict`, d.NowMinusMinutes(hours*60), siteCond(site)+hostCond(hosts))
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
        WHERE bucket_hour >= `+hourAgoExpr(d, hours)+` AND bucket_kind = 'fnl'`)
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
        WHERE bucket >= `+hourAgoExpr(d, hours)+` AND bucket_kind = 'vdip'`)
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
// over a unix socket). If /etc/unmask/nginx-rendered.conf is not included in
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
	// bucket_min = unix sec / 60. cutoff is computed in the same unit.
	cutoffMin := d.NowMinusMinutes(hours * 60)
	if d.Driver == db.DriverSQLite {
		// SQLite: strftime('%s','now','-N minutes') / 60
		cutoffMin = fmt.Sprintf("(strftime('%%s', 'now', '-%d minutes') / 60)", hours*60)
	} else {
		// MariaDB: UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL N MINUTE)) DIV 60
		cutoffMin = fmt.Sprintf("(UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL %d MINUTE)) DIV 60)", hours*60)
	}

	cond := ""
	if site != "" {
		cond = " AND site = '" + site + "'"
	}

	// kind/cnt normalized schema. Aggregate the 3 kinds total / captcha / pow in one query.
	stmt := fmt.Sprintf(`
        SELECT
          COALESCE(SUM(CASE WHEN kind = 'total'   THEN cnt ELSE 0 END), 0) AS total,
          COALESCE(SUM(CASE WHEN kind = 'captcha' THEN cnt ELSE 0 END), 0) AS bv,
          COALESCE(SUM(CASE WHEN kind = 'pow'     THEN cnt ELSE 0 END), 0) AS bp
        FROM unmask_cookie_minute
        WHERE bucket_min > %s%s`, cutoffMin, cond)
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
	stmt := fmt.Sprintf(`
        SELECT flags, COUNT(*) AS n, COUNT(DISTINCT ip_address) AS uniq
        FROM unmask_event WHERE date_created > %s%s AND phase='load'
        GROUP BY flags`, d.NowMinusMinutes(hours*60), siteCond(site)+hostCond(hosts))
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
	return out, nil
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
var captchaForceKinds = []string{"none", "ja4_bot", "honeypot", "banned", "protected", "rate_limit", "test", "unknown"}

func CaptchaForceBreakdown(ctx context.Context, d *db.DB, site string, hosts []string, hours int) ([]CaptchaForceRow, error) {
	since := d.NowMinusMinutes(hours * 60)
	reasonExpr := jsonExtract(d, "payload_json", "$.force_reason")
	stmt := fmt.Sprintf(`
        SELECT
          CASE
            WHEN %s IN ('none','ja4_bot','honeypot','banned','protected','rate_limit','test') THEN %s
            ELSE 'unknown'
          END AS kind,
          COUNT(*) AS n,
          COUNT(DISTINCT ip_address) AS uniq
        FROM unmask_event WHERE date_created > %s%s AND phase='load'
        GROUP BY kind`, reasonExpr, reasonExpr, since, siteCond(site)+hostCond(hosts))
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
	out := make([]CaptchaForceRow, 0, len(captchaForceKinds))
	for _, k := range captchaForceKinds {
		if r, ok := by[k]; ok {
			out = append(out, r)
		} else {
			out = append(out, CaptchaForceRow{Kind: k})
		}
	}
	return out, nil
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
        FROM unmask_event WHERE date_created > %s%s AND phase='load' AND reload_count >= 1
        GROUP BY ip_address
        HAVING max_rc >= 2 OR n >= 3
        ORDER BY max_rc DESC, n DESC LIMIT 50`, d.NowMinusMinutes(hours*60), siteCond(site)+hostCond(hosts))
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

func RateLimitIPs(ctx context.Context, d *db.DB, site string, hosts []string, hours, limit int) ([]RLIPRow, error) {
	since := d.NowMinusMinutes(hours * 60)
	jsonRL := jsonExtract(d, "payload_json", "$.rl")
	stmt := fmt.Sprintf(`
        SELECT ip_address,
               COUNT(*) AS n,
               MAX(user_agent) AS ua,
               MAX(date_created) AS last_seen
        FROM unmask_event
        WHERE date_created > %s%s AND phase='serve' AND %s IN ('1', 1)
        GROUP BY ip_address ORDER BY n DESC LIMIT ?`, since, siteCond(site)+hostCond(hosts), jsonRL)
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

func RateLimitPaths(ctx context.Context, d *db.DB, site string, hosts []string, hours, limit int) ([]RLPathRow, error) {
	since := d.NowMinusMinutes(hours * 60)
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
        WHERE date_created > %s%s AND phase='serve' AND %s IN ('1', 1)
          AND %s IS NOT NULL AND %s <> ''
        GROUP BY path ORDER BY n DESC LIMIT ?`,
		pathExpr, since, siteCond(site)+hostCond(hosts), jsonRL, jsonPath, jsonPath)
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
	since := d.NowMinusMinutes(hours * 60)
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
        WHERE date_created > %s%s AND phase='serve' AND %s IN ('1', 1)
          AND %s IS NOT NULL AND %s <> ''
        GROUP BY p, q
        HAVING q <> ''
        ORDER BY p, n DESC`,
		pathExpr, queryExpr, since, siteCond(site)+hostCond(hosts), jsonRL, jsonPath, jsonPath)
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
	since := d.NowMinusMinutes(hours * 60)
	jsonRL := jsonExtract(d, "payload_json", "$.rl")
	stmt := fmt.Sprintf(`
        SELECT COUNT(*) AS n,
               MIN(date_created) AS f,
               MAX(date_created) AS t
        FROM unmask_event
        WHERE date_created > %s%s AND phase='serve' AND %s IN ('1', 1)`,
		since, siteCond(site)+hostCond(hosts), jsonRL)
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
}

func VerifyNGRanking(ctx context.Context, d *db.DB, site string, hosts []string, hours, limit int) ([]VerifyNGRow, error) {
	since := d.NowMinusMinutes(hours * 60)
	method := jsonExtract(d, "payload_json", "$.method")
	score := jsonExtract(d, "payload_json", "$.score")
	stmt := fmt.Sprintf(`
        SELECT ip_address,
               COUNT(*) AS total,
               SUM(CASE WHEN %s = 'math' THEN 1 ELSE 0 END) AS n_math,
               COUNT(*) - SUM(CASE WHEN %s = 'math' THEN 1 ELSE 0 END) AS n_beh,
               AVG(CAST(%s AS REAL)) AS avg_score,
               MAX(user_agent) AS ua,
               MAX(COALESCE(ja4_verdict, '(none)')) AS ja4,
               MAX(date_created) AS last_seen
        FROM unmask_event WHERE date_created > %s%s AND phase='verify_ng'
        GROUP BY ip_address ORDER BY total DESC LIMIT ?`, method, method, score, since, siteCond(site)+hostCond(hosts))
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
		var ua, ja4, ls sql.NullString
		if err := rows.Scan(&raw, &total, &math, &beh, &avg, &ua, &ja4, &ls); err != nil {
			return nil, err
		}
		out = append(out, VerifyNGRow{
			IP: ipFromBytes(raw), Total: total,
			Math: int(math.Int64), Behavioral: int(beh.Int64),
			AvgScore:   avg.Float64,
			UA:         truncate(ua.String, 50),
			UAFull:     ua.String,
			JA4:        ja4.String,
			LastSeen:   ls.String,
			LastSeenTS: parseDateTimeToUnix(ls.String),
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
	since := d.NowMinusMinutes(hours * 60)
	cookieOK := jsonExtract(d, "payload_json", "$.cookie_set_ok")
	stmt := fmt.Sprintf(`
        SELECT ip_address, COUNT(*) AS n, MAX(user_agent) AS ua, MAX(date_created) AS ls
        FROM unmask_event
        WHERE date_created > %s%s AND phase='bv_pow_only' AND %s IN ('false', 0)
        GROUP BY ip_address ORDER BY n DESC LIMIT 30`, since, siteCond(site)+hostCond(hosts), cookieOK)
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
        WHERE date_created > %s%s
          AND phase IN ('bv_captcha_only','bv_pow_then_captcha')
          AND ja4_verdict %s
        GROUP BY ip_address, ja4_verdict ORDER BY n DESC LIMIT 30`, d.NowMinusMinutes(hours*60), siteCond(site)+hostCond(hosts), botIn)
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

func JSErrors(ctx context.Context, d *db.DB, site string, hosts []string, hours int) ([]JSErrorRow, error) {
	errMsg := jsonExtract(d, "payload_json", "$.error_msg")
	stmt := fmt.Sprintf(`
        SELECT ip_address, user_agent, flags, %s AS err, date_created
        FROM unmask_event
        WHERE date_created > %s%s AND phase='error'
        ORDER BY id DESC LIMIT 30`, errMsg, d.NowMinusMinutes(hours*60), siteCond(site)+hostCond(hosts))
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
// `unmask-admin aggregate` → AggregateServeKind).  Scanning the large, growing
// unmask_event table on every dashboard load was the page's dominant latency;
// the pre-aggregation moves that cost to the hourly cron.  Falls back to a
// live scan when a host filter is active (unmask_aggregate has no host
// dimension) or when the aggregate table has not been populated yet.
func DailyServeByKind(ctx context.Context, d *db.DB, site string, hosts []string, days int, botVerdicts []string) ([]DailyKindBucket, []DailyTotal, error) {
	t0 := time.Now()
	defer func() {
		if elapsed := time.Since(t0); elapsed > 500*time.Millisecond {
			log.Printf("DailyServeByKind: %v elapsed (slow)", elapsed)
		}
	}()
	if len(hosts) == 0 {
		daily, totals, err := dailyServeByKindAgg(ctx, d, site, days)
		if err != nil {
			log.Printf("DailyServeByKind: aggregate read failed, falling back to scan: %v", err)
		} else if len(daily) > 0 || len(totals) > 0 {
			return daily, totals, nil
		}
	}
	return dailyServeByKindScan(ctx, d, site, hosts, days, botVerdicts)
}

// dailyServeByKindAgg reads the pre-aggregated rows AggregateServeKind wrote
// into unmask_aggregate for this site.  Returns empty slices (no error) when
// the aggregate job has not populated serve_* rows yet, so the caller can fall
// back to a live scan.
func dailyServeByKindAgg(ctx context.Context, d *db.DB, site string, days int) ([]DailyKindBucket, []DailyTotal, error) {
	if site == "" {
		site = "default"
	}
	sinceDate := d.NowMinusMinutes(days * 24 * 60)
	// bucket_key is "<site>|<suffix>"; match this site's rows only.
	// DATE() wraps bucket_date so the driver returns a plain "YYYY-MM-DD"
	// string — a bare DATE column comes back as a time.Time and would render
	// as "2026-05-20 00:00:00 +0000 UTC" in the per-day table.
	stmt := fmt.Sprintf(`
        SELECT DATE(bucket_date), bucket_kind, bucket_key, cnt
        FROM unmask_aggregate
        WHERE bucket_kind IN ('serve_kind', 'serve_total')
          AND bucket_date > DATE(%s)
          AND bucket_key LIKE ?`, sinceDate)
	rows, err := d.QueryContext(ctx, stmt, site+"|%")
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	type dkKey struct {
		date string
		kind int
	}
	byDateKind := map[dkKey]int{}
	type totAcc struct{ req, uniq int }
	byTotal := map[string]*totAcc{}
	for rows.Next() {
		var dRaw any
		var kind, key string
		var cnt int
		if err := rows.Scan(&dRaw, &kind, &key, &cnt); err != nil {
			return nil, nil, err
		}
		date := scalarString(dRaw)
		// key = "<site>|<suffix>"; take the suffix after the last '|'.
		suffix := key
		if i := strings.LastIndexByte(key, '|'); i >= 0 {
			suffix = key[i+1:]
		}
		switch kind {
		case "serve_kind":
			k, err := strconv.Atoi(suffix)
			if err != nil {
				continue
			}
			byDateKind[dkKey{date, k}] += cnt
		case "serve_total":
			t := byTotal[date]
			if t == nil {
				t = &totAcc{}
				byTotal[date] = t
			}
			if suffix == "uniqip" {
				t.uniq += cnt
			} else {
				t.req += cnt
			}
		}
	}
	if err := rows.Err(); err != nil {
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
	totalKeys := make([]string, 0, len(byTotal))
	for k := range byTotal {
		totalKeys = append(totalKeys, k)
	}
	sort.Strings(totalKeys)
	totals := make([]DailyTotal, 0, len(totalKeys))
	for _, date := range totalKeys {
		t := byTotal[date]
		totals = append(totals, DailyTotal{Date: date, Req: t.req, UniqIPs: t.uniq})
	}
	return daily, totals, nil
}

// dailyServeByKindScan is the live-scan fallback.  Two scans, each producing a
// small result set: query A groups by (date, verdict, ua-prefix) — deliberately
// NOT by ip_address (including ip yields ~200k rows on a busy 30-day window) —
// and query B groups by date only for COUNT(*) + COUNT(DISTINCT ip_address).
func dailyServeByKindScan(ctx context.Context, d *db.DB, site string, hosts []string, days int, botVerdicts []string) ([]DailyKindBucket, []DailyTotal, error) {
	since := d.NowMinusMinutes(days * 24 * 60)
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

	// Query A — kind buckets.  Grouped by (date, verdict, ua-prefix), NOT by
	// ip_address (see the function doc): a few thousand rows instead of ~200k.
	stmtA := fmt.Sprintf(`
        SELECT DATE(date_created) AS d,
               COALESCE(ja4_verdict, '') AS verdict,
               COALESCE(SUBSTR(user_agent, 1, 80), '') AS ua,
               COUNT(*) AS n
        FROM unmask_event
        WHERE phase='serve' AND date_created > %s AND %s%s
        GROUP BY DATE(date_created), ja4_verdict, SUBSTR(user_agent, 1, 80)`,
		since, notRL, cond)
	rowsA, err := d.QueryContext(ctx, stmtA)
	if err != nil {
		return nil, nil, err
	}
	defer rowsA.Close()
	for rowsA.Next() {
		var dRaw any
		var verdict, ua string
		var n int
		if err := rowsA.Scan(&dRaw, &verdict, &ua, &n); err != nil {
			return nil, nil, err
		}
		date := scalarString(dRaw)
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
		byDateKind[dkKey{date, kind}] += n
	}
	if err := rowsA.Err(); err != nil {
		return nil, nil, err
	}
	rowsA.Close()

	// Query B — per-day totals.  Grouped by date only (~30 rows), so
	// COUNT(DISTINCT ip_address) is cheap to deliver despite a second scan.
	stmtB := fmt.Sprintf(`
        SELECT DATE(date_created) AS d,
               COUNT(*) AS req,
               COUNT(DISTINCT ip_address) AS uniq_ips
        FROM unmask_event
        WHERE phase='serve' AND date_created > %s AND %s%s
        GROUP BY DATE(date_created)`,
		since, notRL, cond)
	rowsB, err := d.QueryContext(ctx, stmtB)
	if err != nil {
		return nil, nil, err
	}
	defer rowsB.Close()
	totals := []DailyTotal{}
	for rowsB.Next() {
		var dRaw any
		var req, uniq int
		if err := rowsB.Scan(&dRaw, &req, &uniq); err != nil {
			return nil, nil, err
		}
		totals = append(totals, DailyTotal{Date: scalarString(dRaw), Req: req, UniqIPs: uniq})
	}
	if err := rowsB.Err(); err != nil {
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

	// total: sort by date asc
	sort.Slice(totals, func(i, j int) bool { return totals[i].Date < totals[j].Date })

	return daily, totals, nil
}

// AggregateServeKind scans phase='serve' events and writes per-day kind buckets
// and per-day totals into unmask_aggregate, so DailyServeByKind can read a few
// hundred pre-computed rows instead of scanning the whole event table on every
// dashboard load.  Called by `unmask-admin aggregate` (hourly cron).
//
// Rows written (UPSERT, so re-runs refresh the current day in place):
//   - bucket_kind='serve_kind',  bucket_key='<site>|<kind>'     cnt=request count
//   - bucket_kind='serve_total', bucket_key='<site>|req'        cnt=request count
//   - bucket_kind='serve_total', bucket_key='<site>|uniqip'     cnt=distinct IPs
func AggregateServeKind(ctx context.Context, d *db.DB, ngx settings.Nginx, days int) error {
	since := d.NowMinusMinutes(days * 24 * 60)
	jsonRL := jsonExtract(d, "payload_json", "$.rl")
	// exclude rate_limit serve hits (same rule as the live scan path).
	notRL := fmt.Sprintf("COALESCE(%s, '') NOT IN ('1', 1)", jsonRL)

	botSet := map[string]bool{}
	for _, v := range BotVerdictNames(ngx) {
		botSet[v] = true
	}
	type classifyKey struct {
		ua    string
		isBot bool
	}
	classifyCache := make(map[classifyKey]int, 256)

	// scan A — kind buckets per (date, site).
	stmtA := fmt.Sprintf(`
        SELECT DATE(date_created) AS d, site,
               COALESCE(ja4_verdict, '') AS verdict,
               COALESCE(SUBSTR(user_agent, 1, 80), '') AS ua,
               COUNT(*) AS n
        FROM unmask_event
        WHERE phase='serve' AND date_created > %s AND %s
        GROUP BY DATE(date_created), site, ja4_verdict, SUBSTR(user_agent, 1, 80)`,
		since, notRL)
	rowsA, err := d.QueryContext(ctx, stmtA)
	if err != nil {
		return err
	}
	type kindKey struct {
		date string
		site string
		kind int
	}
	kindAgg := map[kindKey]int{}
	for rowsA.Next() {
		var dRaw any
		var site, verdict, ua string
		var n int
		if err := rowsA.Scan(&dRaw, &site, &verdict, &ua, &n); err != nil {
			rowsA.Close()
			return err
		}
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
		kindAgg[kindKey{scalarString(dRaw), site, kind}] += n
	}
	if err := rowsA.Err(); err != nil {
		rowsA.Close()
		return err
	}
	rowsA.Close()

	// scan B — per (date, site) totals.
	stmtB := fmt.Sprintf(`
        SELECT DATE(date_created) AS d, site,
               COUNT(*) AS req,
               COUNT(DISTINCT ip_address) AS uniq_ips
        FROM unmask_event
        WHERE phase='serve' AND date_created > %s AND %s
        GROUP BY DATE(date_created), site`,
		since, notRL)
	rowsB, err := d.QueryContext(ctx, stmtB)
	if err != nil {
		return err
	}
	type totKey struct{ date, site string }
	type totVal struct{ req, uniq int }
	totAgg := map[totKey]totVal{}
	for rowsB.Next() {
		var dRaw any
		var site string
		var req, uniq int
		if err := rowsB.Scan(&dRaw, &site, &req, &uniq); err != nil {
			rowsB.Close()
			return err
		}
		totAgg[totKey{scalarString(dRaw), site}] = totVal{req, uniq}
	}
	if err := rowsB.Err(); err != nil {
		rowsB.Close()
		return err
	}
	rowsB.Close()

	upsert := `INSERT INTO unmask_aggregate (bucket_date, bucket_kind, bucket_key, cnt) VALUES (?, ?, ?, ?)`
	if d.Driver == db.DriverSQLite {
		upsert += ` ON CONFLICT(bucket_date, bucket_kind, bucket_key) DO UPDATE SET cnt = excluded.cnt`
	} else {
		upsert += ` ON DUPLICATE KEY UPDATE cnt = VALUES(cnt)`
	}
	for k, n := range kindAgg {
		key := k.site + "|" + strconv.Itoa(k.kind)
		if _, err := d.ExecContext(ctx, upsert, k.date, "serve_kind", key, n); err != nil {
			return err
		}
	}
	for k, v := range totAgg {
		if _, err := d.ExecContext(ctx, upsert, k.date, "serve_total", k.site+"|req", v.req); err != nil {
			return err
		}
		if _, err := d.ExecContext(ctx, upsert, k.date, "serve_total", k.site+"|uniqip", v.uniq); err != nil {
			return err
		}
	}
	return nil
}

// DailyPassByDay: aggregate all nginx requests from unmask_cookie_minute by
// date and return a stacked-bar list with 3 categories: white_pass / pow_pass /
// not_pass.
//
// Data source: nginx access_log syslog datagram → memory bucket → DB UPSERT.
// In environments where nginx-rendered.conf is not included in http {}, the
// table stays empty (= returns all zeros).
//
// Day boundaries use the server-local TZ (= SQLite 'localtime' /
// MariaDB DATE(FROM_UNIXTIME)). Uniq IP cannot be computed because the
// cookie_minute table has no IP column → DailyTotal.UniqIPs is left at 0
// (= per-IP detail is available via ip-popover / a separate card).
func DailyPassByDay(ctx context.Context, d *db.DB, site string, hosts []string, days int) ([]DailyKindBucket, []DailyTotal, error) {
	cutoffMin := ""
	dateExpr := ""
	if d.Driver == db.DriverSQLite {
		cutoffMin = fmt.Sprintf("(strftime('%%s', 'now', '-%d minutes') / 60)", days*24*60)
		dateExpr = `DATE(bucket_min * 60, 'unixepoch', 'localtime')`
	} else {
		cutoffMin = fmt.Sprintf("(UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL %d MINUTE)) DIV 60)", days*24*60)
		dateExpr = `DATE(FROM_UNIXTIME(bucket_min * 60))`
	}
	cond := ""
	if site != "" {
		cond = " AND site = '" + site + "'"
	}
	// kind/cnt normalized schema. Aggregate total / captcha / pow /
	// challenge_served in one CASE query. Even if a new kind ("signature" etc.)
	// is added later, we keep the current 3-way display (= pass / pow_pass /
	// not_pass) until dashboard requirements change.
	stmt := fmt.Sprintf(`
        SELECT %s AS d,
               COALESCE(SUM(CASE WHEN kind = 'total'            THEN cnt ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN kind = 'captcha'          THEN cnt ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN kind = 'pow'              THEN cnt ELSE 0 END), 0),
               COALESCE(SUM(CASE WHEN kind = 'challenge_served' THEN cnt ELSE 0 END), 0)
        FROM unmask_cookie_minute
        WHERE bucket_min > %s%s
        GROUP BY d
        ORDER BY d`, dateExpr, cutoffMin, cond)
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	daily := []DailyKindBucket{}
	totals := []DailyTotal{}
	for rows.Next() {
		var dRaw any
		var total, bv, bp, fc int
		if err := rows.Scan(&dRaw, &total, &bv, &bp, &fc); err != nil {
			return nil, nil, err
		}
		date := scalarString(dRaw)
		notPass := fc
		white := total - bv - bp - notPass
		if white < 0 {
			white = 0
		}
		// Drop 0-count buckets (= cleaner stacked bar on the chart)
		if white > 0 {
			daily = append(daily, DailyKindBucket{Date: date, Kind: KindWhitePass, Req: white})
		}
		if bv > 0 {
			daily = append(daily, DailyKindBucket{Date: date, Kind: KindCaptchaPass, Req: bv})
		}
		if bp > 0 {
			daily = append(daily, DailyKindBucket{Date: date, Kind: KindPoWPass, Req: bp})
		}
		if notPass > 0 {
			daily = append(daily, DailyKindBucket{Date: date, Kind: KindNotPass, Req: notPass})
		}
		totals = append(totals, DailyTotal{Date: date, Req: total, UniqIPs: 0})
	}
	if err := rows.Err(); err != nil {
		return nil, nil, err
	}
	return daily, totals, nil
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
	since := d.NowMinusMinutes(days * 24 * 60)
	stmt := fmt.Sprintf(`
        SELECT ip_address, COUNT(*) AS n
        FROM unmask_event
        WHERE date_created > %s%s AND phase='serve'
        GROUP BY ip_address`, since, siteCond(site)+hostCond(hosts))
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
        WHERE bucket_hour >= `+hourAgoExpr(d, days*24)+` AND bucket_kind = 'cc'
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
        WHERE bucket >= `+dateAgoExpr(d, days)+` AND bucket_kind = 'ccip'`)
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

func DailySeries(ctx context.Context, d *db.DB, days int) ([]DailyBucket, error) {
	stmt := fmt.Sprintf(`
        SELECT DATE(date_created) AS d, phase, COUNT(*) FROM unmask_event
        WHERE date_created > %s
        GROUP BY DATE(date_created), phase
        ORDER BY d`, d.NowMinusMinutes(days*24*60))
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	by := map[string]*DailyBucket{}
	var order []string
	for rows.Next() {
		var dsRaw any
		var phase string
		var cnt int
		if err := rows.Scan(&dsRaw, &phase, &cnt); err != nil {
			return nil, err
		}
		ds := scalarString(dsRaw)
		b, ok := by[ds]
		if !ok {
			b = &DailyBucket{Date: ds}
			by[ds] = b
			order = append(order, ds)
		}
		switch phase {
		case "serve":
			b.Serve = cnt
		case "load":
			b.Load = cnt
		case "pow_pass":
			b.PowPass = cnt
		case "captcha":
			b.Captcha = cnt
		case "bv_pow_only":
			b.BVPowOnly = cnt
		case "bv_captcha_only":
			b.BVCaptchaOnly = cnt
		case "bv_pow_then_captcha":
			b.BVPowThenCaptcha = cnt
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

func scalarString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case []byte:
		return string(s)
	}
	return fmt.Sprintf("%v", v)
}

// Pinger: dashboard health helper.
func Pinger(d *db.DB) error {
	return d.PingContext(context.Background())
}
