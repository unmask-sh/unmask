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
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/geoip"
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
// Empty list returns "IN ('')" (= no match). Dialect-independent.
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
	// Accept SQLite default format ("2006-01-02 15:04:05") and RFC3339
	// ("2006-01-02T15:04:05Z"). Treat as UTC when no TZ info is present
	// (= schema uses CURRENT_TIMESTAMP which is UTC).
	for _, layout := range []string{
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
func siteCond(site string) string {
	if site == "" {
		return ""
	}
	return " AND site = '" + site + "'"
}

// hostValRE: allowed chars for host filter values (= hostname / host id). Since
// it is embedded into SQL literally, restrict strictly to alnum + ._- only.
// Values containing anything else are ignored in hostCond (= SQL injection guard).
var hostValRE = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

// hostCond: SQL fragment for the host multi-select filter. Returns "" if empty
// or all-invalid (= all hosts). unmask_event has a host column (= identifies
// machine of origin in shared DB). Note: unmask_cookie_minute lacks a host
// column, so the host filter has no effect on CookieStatus / DailyPassByDay
// (= they remain aggregated across all hosts).
func hostCond(hosts []string) string {
	valid := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if hostValRE.MatchString(h) {
			valid = append(valid, "'"+h+"'")
		}
	}
	if len(valid) == 0 {
		return ""
	}
	return " AND host IN (" + strings.Join(valid, ",") + ")"
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
	stmt := fmt.Sprintf(`
        SELECT site,
               COUNT(*) AS n,
               SUM(CASE WHEN phase='serve' THEN 1 ELSE 0 END) AS n_serve,
               SUM(CASE WHEN phase='verify_ok' THEN 1 ELSE 0 END) AS n_verify,
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
type FunnelRow struct {
	Verdict     string  // free label. "ok" / "rate_limit" / "TOTAL" / preset / extra
	Serve       int     // count of challenge HTML deliveries
	ServeRL     int     // serves that came via ?_rl=1 (= rate-limit path)
	Load        int
	LoadUniq    int     // unique IPs in the load phase
	Silent      int     // = max(0, Serve - Load). Challenge served but JS never started
	Stealth     int     // load phase rows with flags=0 + verdict configured as bot/suspect
	PoW         int
	Captcha     int
	VerifyOK    int
	VerifyNG    int
	CookieErr   int
	JSError     int
	PowRate     float64 // PoW / Load
	CaptchaRate float64 // Captcha / Load
}

// Funnel returns one row per verdict in the fixed list plus a rate_limit row
// (= IP-joined for serves where payload.rl=1) and a TOTAL row.
//
// botVerdicts is the list of verdict names configured as action=bot or suspect
// in settings (= preset + extra merged). Used for stealth-count classification.
// An empty list disables the stealth concept (stealth=0 is always emitted).
func Funnel(ctx context.Context, d *db.DB, site string, hosts []string, hours int, botVerdicts []string, reg *nginxconf.VerdictRegistry) ([]FunnelRow, error) {
	since := d.NowMinusMinutes(hours * 60)

	// canon: normalization for ID-based linking. If the ID is known, snap to
	// the current preset name (= reflects renames). For unknown IDs (= NULL / 0)
	// try a registry name lookup, then fall back to the raw name. This merges
	// pre- and post-rename events with the same ID into one group. Unknown
	// names (= non-preset) stay as-is.
	canon := func(id int64, raw string) string {
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

	// A) base aggregation by verdict × phase. SELECT id too so canon can use it.
	stmt := fmt.Sprintf(`
        SELECT COALESCE(ja4_verdict, '(none)') AS v, ja4_verdict_id AS vid, phase, COUNT(*) AS n
        FROM unmask_event WHERE date_created > %s%s
        GROUP BY ja4_verdict, ja4_verdict_id, phase`, since, siteCond(site)+hostCond(hosts))
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	type vp struct{ verdict, phase string }
	byVP := map[vp]int{}
	for rows.Next() {
		var v, p string
		var vid sql.NullInt64
		var n int
		if err := rows.Scan(&v, &vid, &p, &n); err != nil {
			rows.Close()
			return nil, err
		}
		byVP[vp{canon(vid.Int64, v), p}] += n
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
	stmt2 := fmt.Sprintf(`
        SELECT COALESCE(ja4_verdict, '(none)') AS v, ja4_verdict_id AS vid,
               COUNT(DISTINCT ip_address) AS uniq_ip,
               SUM(CASE WHEN flags = 0 AND %s THEN 1 ELSE 0 END) AS stealth
        FROM unmask_event WHERE date_created > %s%s AND phase = 'load'
        GROUP BY ja4_verdict, ja4_verdict_id`, botFilter, since, siteCond(site)+hostCond(hosts))
	rows2, err := d.QueryContext(ctx, stmt2, botFilterArgs...)
	if err != nil {
		return nil, err
	}
	type loadAgg struct{ uniq, stealth int }
	loadByV := map[string]loadAgg{}
	for rows2.Next() {
		var v string
		var vid, u, st sql.NullInt64
		if err := rows2.Scan(&v, &vid, &u, &st); err != nil {
			rows2.Close()
			return nil, err
		}
		k := canon(vid.Int64, v)
		ex := loadByV[k]
		// Strictly, uniq IP should be re-computed with COUNT(DISTINCT) on the DB
		// side to avoid duplicates, but this approximation is good enough for the
		// rename-merge case (= unlikely the same IP hits both old and new names).
		loadByV[k] = loadAgg{ex.uniq + int(u.Int64), ex.stealth + int(st.Int64)}
	}
	rows2.Close()

	// C) per-verdict counts where phase=serve and payload.rl=1
	jsonRL := jsonExtract(d, "payload_json", "$.rl")
	stmt3 := fmt.Sprintf(`
        SELECT COALESCE(ja4_verdict, '(none)') AS v, ja4_verdict_id AS vid,
               SUM(CASE WHEN %s IN ('1', 1) THEN 1 ELSE 0 END) AS rl
        FROM unmask_event WHERE date_created > %s%s AND phase = 'serve'
        GROUP BY ja4_verdict, ja4_verdict_id`, jsonRL, since, siteCond(site)+hostCond(hosts))
	rows3, err := d.QueryContext(ctx, stmt3)
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
		rlByV[canon(vid.Int64, v)] += int(n.Int64)
	}
	rows3.Close()

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

	var out []FunnelRow
	total := FunnelRow{Verdict: "TOTAL"}
	for _, v := range order {
		row := FunnelRow{
			Verdict:   v,
			Serve:     byVP[vp{v, "serve"}],
			ServeRL:   rlByV[v],
			Load:      byVP[vp{v, "load"}],
			LoadUniq:  loadByV[v].uniq,
			Stealth:   loadByV[v].stealth,
			PoW:       byVP[vp{v, "pow"}],
			Captcha:   byVP[vp{v, "captcha"}],
			VerifyOK:  byVP[vp{v, "verify_ok"}],
			VerifyNG:  byVP[vp{v, "verify_ng"}],
			CookieErr: byVP[vp{v, "cookie_err"}],
			JSError:   byVP[vp{v, "error"}],
		}
		if row.Serve > row.Load {
			row.Silent = row.Serve - row.Load
		}
		if row.Load > 0 {
			row.PowRate = float64(row.PoW) / float64(row.Load)
			row.CaptchaRate = float64(row.Captcha) / float64(row.Load)
		}
		total.Serve += row.Serve
		total.ServeRL += row.ServeRL
		total.Load += row.Load
		total.Silent += row.Silent
		total.Stealth += row.Stealth
		total.PoW += row.PoW
		total.Captcha += row.Captcha
		total.VerifyOK += row.VerifyOK
		total.VerifyNG += row.VerifyNG
		total.CookieErr += row.CookieErr
		total.JSError += row.JSError
		out = append(out, row)
	}

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
		total.PowRate = float64(total.PoW) / float64(total.Load)
		total.CaptchaRate = float64(total.Captcha) / float64(total.Load)
	}
	out = append(out, total)
	return out, nil
}

func rateLimitFunnelRow(ctx context.Context, d *db.DB, site string, hosts []string, since string, botVerdicts []string) (FunnelRow, error) {
	jsonRL := jsonExtract(d, "payload_json", "$.rl")
	sc := siteCond(site)+hostCond(hosts)
	botIn, botArgs := inClause(botVerdicts)
	stmt := fmt.Sprintf(`
        SELECT
          SUM(CASE WHEN phase='serve' THEN 1 ELSE 0 END)     AS n_serve,
          SUM(CASE WHEN phase='load' THEN 1 ELSE 0 END)      AS n_load,
          SUM(CASE WHEN phase='load' AND flags=0 AND ja4_verdict `+botIn+` THEN 1 ELSE 0 END) AS n_stealth,
          SUM(CASE WHEN phase='pow' THEN 1 ELSE 0 END)       AS n_pow,
          SUM(CASE WHEN phase='captcha' THEN 1 ELSE 0 END)   AS n_captcha,
          SUM(CASE WHEN phase='verify_ok' THEN 1 ELSE 0 END) AS n_verify_ok,
          SUM(CASE WHEN phase='verify_ng' THEN 1 ELSE 0 END) AS n_verify_ng,
          SUM(CASE WHEN phase='cookie_err' THEN 1 ELSE 0 END) AS n_cookie_err,
          SUM(CASE WHEN phase='error' THEN 1 ELSE 0 END)     AS n_error
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
	var serve, load, stealth, pow, capt, vok, vng, ce, jse sql.NullInt64
	if err := row.Scan(&serve, &load, &stealth, &pow, &capt, &vok, &vng, &ce, &jse); err != nil {
		return r, err
	}
	r.Serve = int(serve.Int64)
	r.ServeRL = r.Serve
	r.Load = int(load.Int64)
	r.Stealth = int(stealth.Int64)
	r.PoW = int(pow.Int64)
	r.Captcha = int(capt.Int64)
	r.VerifyOK = int(vok.Int64)
	r.VerifyNG = int(vng.Int64)
	r.CookieErr = int(ce.Int64)
	r.JSError = int(jse.Int64)
	if r.Serve > r.Load {
		r.Silent = r.Serve - r.Load
	}
	if r.Load > 0 {
		r.PowRate = float64(r.PoW) / float64(r.Load)
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

func VerdictDistribution(ctx context.Context, d *db.DB, site string, hosts []string, hours int) ([]VerdictCount, error) {
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
	all := fixedVerdicts()
	seen := map[string]bool{}
	for _, v := range all {
		seen[v] = true
	}
	// Append unknown verdicts seen in the DB at the tail (= keeps the 0-row
	// policy while still covering unknowns).
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
	return out, nil
}

// CookieStatusRow: 4-way breakdown of cookie presence across all nginx requests.
//
// Data source: unmask_cookie_minute table (= aggregated from nginx access_log
// over a unix socket). If /etc/unmask/nginx-rendered.conf is not included in
// http {}, everything returns 0 (= the access_log directive never fires).
//
//   total          : all nginx-received requests
//   captcha_passed : _bv cookie HMAC verified OK (= bv=1)
//   pow_passed     : _br cookie present (= bv=0 & bp=1)
//   none           : neither cookie
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
			UA: truncate(ua.String, 50), LastSeen: ls.String, LastSeenTS: parseDateTimeToUnix(ls.String),
		})
	}
	return out, rows.Err()
}

// RLIPRow: phase=serve + payload.rl=1 aggregated per IP.
type RLIPRow struct {
	IP          string
	Count       int
	UA          string
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
			UA: truncate(ua.String, 60), LastSeen: ls.String, LastSeenTS: parseDateTimeToUnix(ls.String),
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
	IP           string
	Total        int
	Math         int
	Behavioral   int
	AvgScore     float64
	UA           string
	JA4          string
	LastSeen     string
	LastSeenTS   int64
	CountryCode  string
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
			JA4:        ja4.String,
			LastSeen:   ls.String,
			LastSeenTS: parseDateTimeToUnix(ls.String),
		})
	}
	return out, rows.Err()
}

// CookieFailRow: pow phase rows that contain cookie_set_ok=false.
type CookieFailRow struct {
	IP          string
	Count       int
	UA          string
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
        WHERE date_created > %s%s AND phase='pow' AND %s IN ('false', 0)
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
		out = append(out, CookieFailRow{IP: ipFromBytes(raw), Count: n, UA: truncate(ua.String, 50), LastSeen: ls.String, LastSeenTS: parseDateTimeToUnix(ls.String)})
	}
	return out, rows.Err()
}

// StealthRow: passed verify_ok but ja4_verdict is configured as bot/suspect.
// Full stealth-bot suspect.
type StealthRow struct {
	IP          string
	Verdict     string
	UA          string
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
        WHERE date_created > %s%s AND phase='verify_ok' AND ja4_verdict %s
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
			IP: ipFromBytes(raw), Verdict: v, UA: truncate(ua.String, 80),
			Count: n, LastSeen: ls.String, LastSeenTS: parseDateTimeToUnix(ls.String),
		})
	}
	return out, rows.Err()
}

// JSErrorRow: a JS error carried in payload of the error phase.
type JSErrorRow struct {
	IP          string
	UA          string
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
			IP: ipFromBytes(raw), UA: truncate(ua.String, 80), Flags: fl,
			Error:  truncate(strings.Trim(errStr.String, `"`), 120),
			Date:   ds.String,
			DateTS: parseDateTimeToUnix(ds.String),
		})
	}
	return out, rows.Err()
}

// DailyBucket: daily trend series.
type DailyBucket struct {
	Date     string
	Serve    int
	Load     int
	PoW      int
	Captcha  int
	VerifyOK int
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

// DailyServeByKind: aggregate phase='serve' by date × ip × verdict × ua × rl,
// classify each row with classify.IsBot, and return per-(date × kind) request
// counts. Also returns per-day totals + uniq IP.
//
// Return:
//   - daily: list of (date, kind, req) for the stacked bar
//   - total: list of per-day req + uniq IP
//
// On high-traffic sites the event cardinality is high
// (= tens of thousands of ip × verdict × ua combinations) and the Go classify
// loop hits the 8s timeout. Mitigation: aggregate UA on the SQL side using
// verdict + truncated UA prefix, which compresses the distinct-combination
// count. UA prefix is enough for classification (= same UA pattern always lands
// in the same category).
func DailyServeByKind(ctx context.Context, d *db.DB, site string, hosts []string, days int, botVerdicts []string) ([]DailyKindBucket, []DailyTotal, error) {
	t0 := time.Now()
	defer func() {
		if elapsed := time.Since(t0); elapsed > 500*time.Millisecond {
			log.Printf("DailyServeByKind: %v elapsed (slow)", elapsed)
		}
	}()
	since := d.NowMinusMinutes(days * 24 * 60)
	jsonRL := jsonExtract(d, "payload_json", "$.rl")
	// Truncate UA to 80 chars before grouping (= compresses cardinality.
	// Grouping by full UA can yield tens of thousands of distinct rows; the
	// 80-char prefix collapses same-UA families into one row).
	stmt := fmt.Sprintf(`
        SELECT DATE(date_created) AS d,
               ip_address,
               COALESCE(ja4_verdict, '') AS verdict,
               COALESCE(SUBSTR(user_agent, 1, 80), '') AS ua,
               CASE WHEN %s IN ('1', 1) THEN 1 ELSE 0 END AS is_rl,
               COUNT(*) AS n
        FROM unmask_event
        WHERE phase='serve' AND date_created > %s%s
        GROUP BY DATE(date_created), ip_address, ja4_verdict, SUBSTR(user_agent, 1, 80), is_rl`,
		jsonRL, since, siteCond(site)+hostCond(hosts))
	// No ORDER BY (= Go side re-sorts by date/kind, so SQLite's
	// "USE TEMP B-TREE FOR ORDER BY" would be wasted work).
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	type dkKey struct {
		date string
		kind int
	}
	byDateKind := map[dkKey]int{}
	type totalAcc struct {
		req      int
		uniqIPs  map[string]bool
	}
	byTotal := map[string]*totalAcc{}
	dateSeen := map[string]bool{}

	// classify cache (= same (ua, isJA4Bot) tuple always maps to the same kind).
	// Memoize because calling IsBot per row across tens of thousands of rows
	// runs a regex with 600 alternations each time, which is heavy.
	// Verdict name → action lookup is a single-pass through botSet.
	botSet := map[string]bool{}
	for _, v := range botVerdicts {
		botSet[v] = true
	}
	type classifyKey struct {
		ua    string
		isBot bool
	}
	classifyCache := make(map[classifyKey]int, 256)

	for rows.Next() {
		var dRaw any
		var ipPacked []byte
		var verdict, ua string
		var isRL int
		var n int
		if err := rows.Scan(&dRaw, &ipPacked, &verdict, &ua, &isRL, &n); err != nil {
			return nil, nil, err
		}
		date := scalarString(dRaw)
		dateSeen[date] = true

		// rate_limit hits are a signal orthogonal to the bot-type breakdown,
		// so they are excluded here and shown in a dedicated rate_limit card.
		if isRL == 1 {
			continue
		}
		isBot := botSet[verdict]
		ck := classifyKey{ua, isBot}
		var kind int
		if v, ok := classifyCache[ck]; ok {
			kind = v
		} else {
			action := ""
			if isBot {
				action = "bot"
			}
			kind = int(classify.IsBot(ua, action))
			classifyCache[ck] = kind
		}
		byDateKind[dkKey{date, kind}] += n

		ipKey := string(ipPacked)
		t, ok := byTotal[date]
		if !ok {
			t = &totalAcc{uniqIPs: map[string]bool{}}
			byTotal[date] = t
		}
		t.req += n
		t.uniqIPs[ipKey] = true
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

	// total: sort by date asc
	totalKeys := make([]string, 0, len(byTotal))
	for k := range byTotal {
		totalKeys = append(totalKeys, k)
	}
	sort.Strings(totalKeys)
	totals := make([]DailyTotal, 0, len(totalKeys))
	for _, date := range totalKeys {
		t := byTotal[date]
		totals = append(totals, DailyTotal{Date: date, Req: t.req, UniqIPs: len(t.uniqIPs)})
	}

	return daily, totals, nil
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

// CountriesByServe: aggregate phase='serve' per IP → geoip lookup → return
// per-country req / uniq IP aggregates. Returns an empty list when geoip.Reader
// is empty (= mmdb not configured / failed to load), so callers know not to
// show the country chart.
func CountriesByServe(ctx context.Context, d *db.DB, gip *geoip.Reader, site string, hosts []string, days, limit int) ([]CountryRow, error) {
	if gip == nil || !gip.Loaded() {
		return nil, nil
	}
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
		case "pow":
			b.PoW = cnt
		case "captcha":
			b.Captcha = cnt
		case "verify_ok":
			b.VerifyOK = cnt
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
