// Package dashboard: ダッシュボード用の集計クエリ群.
//
// 本家 (= <internal-codebase>/lib/Tool/Controller/Admin/BotChallengeDebug.pm) の
// 構成に揃える: 1) ファネル (verdict 別) 2) cookie 通過 3) flags 分布
// 4) JA4 verdict 分布 5) JA4 hit 判定 6) reload ループ 7) CAPTCHA 失敗 IP
// 8) cookie_set_ok=false 9) stealth 突破 10) JS error 11) 30日推移
package dashboard

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/unmask-sh/unmask/admin/internal/classify"
	"github.com/unmask-sh/unmask/admin/internal/db"
)

// Range は 1d / 7d / 30d. 不正値は 1d.
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
// 空 string → "" (= 全 site 集計).
//
// SQL injection 防止: 呼び出し側で必ず site を validate (= [a-z0-9-]{1,32}) してから
// 渡すこと. handlers.pickSite が regex で弾くので、 ここでは literal 連結する.
func siteCond(site string) string {
	if site == "" {
		return ""
	}
	return " AND site = '" + site + "'"
}

// SiteSummary: /admin/ 一覧用の site 別サマリー.
type SiteSummary struct {
	Site     string
	Events   int
	Serve    int
	Verify   int
	UniqIP   int
	LastSeen string
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
		by[s.Site] = s
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// "default" は常に list に出す
	if _, ok := by["default"]; !ok {
		by["default"] = SiteSummary{Site: "default"}
	}
	out := make([]SiteSummary, 0, len(by))
	for _, v := range by {
		out = append(out, v)
	}
	sort.SliceStable(out, func(i, j int) bool {
		// default を先頭に, あとは event 数 desc
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

// fixedVerdicts: nginx の ja4-verdict.map に載せている主要 verdict + ok / (none).
// 0 件でも常時表示する.
var fixedVerdicts = []string{
	"bot_chrome_fake_h1",
	"bot_chrome_fake_noalpn",
	"bot_h1_18_12",
	"bot_h1_44_12",
	"bot_noalpn_311",
	"bot_noalpn_521",
	"bot_tls12_a",
	"bot_tls12_b",
	"bot_tls12_c",
	"suspect_h1",
	"ok",
	"(none)",
}

// keyFlags: load phase の flags 列で常時表示する代表値.
var keyFlags = []int{0, 1, 2, 4, 8, 16, 3, 5, 9, 17, 31}

// FunnelRow: 1 行 = 1 verdict (= JA4 verdict + 集約済みカテゴリ).
type FunnelRow struct {
	Verdict     string  // "ok" / "bot_chrome_fake_h1" / "rate_limit" / "TOTAL" / ...
	Serve       int     // challenge HTML が配信された数
	ServeRL     int     // ?_rl=1 (= rate-limit 経由) 経由の serve
	Load        int
	LoadUniq    int     // load phase の unique IP
	Stealth     int     // load phase で flags=0 + bot_*
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
func Funnel(ctx context.Context, d *db.DB, site string, hours int) ([]FunnelRow, error) {
	since := d.NowMinusMinutes(hours * 60)

	// A) verdict × phase の base 集計
	stmt := fmt.Sprintf(`
        SELECT COALESCE(ja4_verdict, '(none)') AS v, phase, COUNT(*) AS n
        FROM unmask_event WHERE date_created > %s%s
        GROUP BY ja4_verdict, phase`, since, siteCond(site))
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	type vp struct{ verdict, phase string }
	byVP := map[vp]int{}
	for rows.Next() {
		var v, p string
		var n int
		if err := rows.Scan(&v, &p, &n); err != nil {
			rows.Close()
			return nil, err
		}
		byVP[vp{v, p}] = n
	}
	rows.Close()

	// B) verdict × phase=load の uniq IP, stealth (= flags=0 + bot_*) 集計
	stmt2 := fmt.Sprintf(`
        SELECT COALESCE(ja4_verdict, '(none)') AS v,
               COUNT(DISTINCT ip_address) AS uniq_ip,
               SUM(CASE WHEN flags = 0 AND ja4_verdict LIKE 'bot_%%' THEN 1 ELSE 0 END) AS stealth
        FROM unmask_event WHERE date_created > %s%s AND phase = 'load'
        GROUP BY ja4_verdict`, since, siteCond(site))
	rows2, err := d.QueryContext(ctx, stmt2)
	if err != nil {
		return nil, err
	}
	type loadAgg struct{ uniq, stealth int }
	loadByV := map[string]loadAgg{}
	for rows2.Next() {
		var v string
		var u, st sql.NullInt64
		if err := rows2.Scan(&v, &u, &st); err != nil {
			rows2.Close()
			return nil, err
		}
		loadByV[v] = loadAgg{int(u.Int64), int(st.Int64)}
	}
	rows2.Close()

	// C) phase=serve で payload.rl=1 だった verdict 別件数
	jsonRL := jsonExtract(d, "payload_json", "$.rl")
	stmt3 := fmt.Sprintf(`
        SELECT COALESCE(ja4_verdict, '(none)') AS v,
               SUM(CASE WHEN %s IN ('1', 1) THEN 1 ELSE 0 END) AS rl
        FROM unmask_event WHERE date_created > %s%s AND phase = 'serve'
        GROUP BY ja4_verdict`, jsonRL, since, siteCond(site))
	rows3, err := d.QueryContext(ctx, stmt3)
	if err != nil {
		return nil, err
	}
	rlByV := map[string]int{}
	for rows3.Next() {
		var v string
		var n sql.NullInt64
		if err := rows3.Scan(&v, &n); err != nil {
			rows3.Close()
			return nil, err
		}
		rlByV[v] = int(n.Int64)
	}
	rows3.Close()

	// D) verdict 一覧 = fixed list 順 + DB に出てきた未知 verdict (= 末尾に名前順で追加).
	// 本家と同じく fixedVerdicts の declaration order を維持する.
	seen := map[string]bool{}
	order := append([]string{}, fixedVerdicts...)
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
		if row.Load > 0 {
			row.PowRate = float64(row.PoW) / float64(row.Load)
			row.CaptchaRate = float64(row.Captcha) / float64(row.Load)
		}
		total.Serve += row.Serve
		total.ServeRL += row.ServeRL
		total.Load += row.Load
		total.Stealth += row.Stealth
		total.PoW += row.PoW
		total.Captcha += row.Captcha
		total.VerifyOK += row.VerifyOK
		total.VerifyNG += row.VerifyNG
		total.CookieErr += row.CookieErr
		total.JSError += row.JSError
		out = append(out, row)
	}

	// rate_limit 行: serves で rl=1 だった IP の全 phase 遷移を IP join で集計
	rlRow, err := rateLimitFunnelRow(ctx, d, site, since)
	if err == nil {
		out = append([]FunnelRow{rlRow}, out...)
	}

	// total の uniq は別 SQL (= 同 IP が verdict 横断でカウントされないよう)
	row := d.QueryRowContext(ctx, fmt.Sprintf(
		`SELECT COUNT(DISTINCT ip_address) FROM unmask_event WHERE date_created > %s%s AND phase = 'load'`,
		since, siteCond(site)))
	_ = row.Scan(&total.LoadUniq)
	if total.Load > 0 {
		total.PowRate = float64(total.PoW) / float64(total.Load)
		total.CaptchaRate = float64(total.Captcha) / float64(total.Load)
	}
	out = append(out, total)
	return out, nil
}

func rateLimitFunnelRow(ctx context.Context, d *db.DB, site, since string) (FunnelRow, error) {
	jsonRL := jsonExtract(d, "payload_json", "$.rl")
	sc := siteCond(site)
	stmt := fmt.Sprintf(`
        SELECT
          SUM(CASE WHEN phase='serve' THEN 1 ELSE 0 END)     AS n_serve,
          SUM(CASE WHEN phase='load' THEN 1 ELSE 0 END)      AS n_load,
          SUM(CASE WHEN phase='load' AND flags=0 AND ja4_verdict LIKE 'bot_%%' THEN 1 ELSE 0 END) AS n_stealth,
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
	row := d.QueryRowContext(ctx, stmt)
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
	if r.Load > 0 {
		r.PowRate = float64(r.PoW) / float64(r.Load)
		r.CaptchaRate = float64(r.Captcha) / float64(r.Load)
	}
	return r, nil
}

// VerdictCount: JA4 verdict 別件数 + uniq IP.
type VerdictCount struct {
	Verdict string
	Count   int
	UniqIP  int
}

func VerdictDistribution(ctx context.Context, d *db.DB, site string, hours int) ([]VerdictCount, error) {
	stmt := fmt.Sprintf(`
        SELECT COALESCE(ja4_verdict, '(none)') AS v,
               COUNT(*) AS cnt,
               COUNT(DISTINCT ip_address) AS uniq
        FROM unmask_event WHERE date_created > %s%s
        GROUP BY ja4_verdict`, d.NowMinusMinutes(hours*60), siteCond(site))
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
	all := append([]string{}, fixedVerdicts...)
	seen := map[string]bool{}
	for _, v := range all {
		seen[v] = true
	}
	// DB に出ている未知 verdict も末尾に追加 (= 0 件項目原則は維持しつつ unknown もカバー).
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
	// 件数 desc → verdict alpha の sort. ただし 0 件は declaration 順で末尾に流れる.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return false
	})
	return out, nil
}

// CookieStatusRow: load phase での _bv / _br cookie 持参状況.
type CookieStatusRow struct {
	Kind  string // "bv=valid" / "bv=invalid" / "bv=none" / "br=set" 等
	Count int
}

func CookieStatus(ctx context.Context, d *db.DB, site string, hours int) ([]CookieStatusRow, error) {
	since := d.NowMinusMinutes(hours * 60)
	stmt := fmt.Sprintf(`
        SELECT
          SUM(CASE WHEN cookie_bv IS NULL OR cookie_bv = '' THEN 1 ELSE 0 END) AS bv_none,
          SUM(CASE WHEN cookie_bv IS NOT NULL AND cookie_bv <> '' THEN 1 ELSE 0 END) AS bv_set,
          SUM(CASE WHEN cookie_br IS NULL OR cookie_br = '' THEN 1 ELSE 0 END) AS br_none,
          SUM(CASE WHEN cookie_br IS NOT NULL AND cookie_br <> '' THEN 1 ELSE 0 END) AS br_set
        FROM unmask_event WHERE date_created > %s%s AND phase='load'`, since, siteCond(site))
	row := d.QueryRowContext(ctx, stmt)
	var bvN, bvS, brN, brS sql.NullInt64
	if err := row.Scan(&bvN, &bvS, &brN, &brS); err != nil {
		return nil, err
	}
	return []CookieStatusRow{
		{"_bv 無し (= 初回 / 期限切れ)", int(bvN.Int64)},
		{"_bv 有り (= 過去通過済)", int(bvS.Int64)},
		{"_br 無し (= 初回 reload)", int(brN.Int64)},
		{"_br 有り (= reload 経験あり)", int(brS.Int64)},
	}, nil
}

// FlagsRow: flags ビット分布 (load phase).
type FlagsRow struct {
	Flags  int
	Bin    string // 5 桁 bit 表記
	Count  int
	UniqIP int
	Note   string
}

// flag bit 解説 (= 本家 BotChallengeDebug.pm $flags_help と揃える).
var flagsNotes = map[int]string{
	0:  "正常 (= 全 check pass)",
	1:  "navigator.webdriver=true",
	2:  "navigator.plugins.length=0",
	4:  "screen 0x0 (= headless 確実)",
	8:  "navigator.languages 空",
	16: "window.chrome 欠落 (= Chrome 名乗りなのに API なし)",
	3:  "1+2 (= webdriver + no plugins)",
	5:  "1+4 (= webdriver + 0x0 screen)",
	9:  "1+8",
	17: "1+16",
	31: "全部 (1|2|4|8|16) — 完全 headless",
}

func FlagsDistribution(ctx context.Context, d *db.DB, site string, hours int) ([]FlagsRow, error) {
	stmt := fmt.Sprintf(`
        SELECT flags, COUNT(*) AS n, COUNT(DISTINCT ip_address) AS uniq
        FROM unmask_event WHERE date_created > %s%s AND phase='load'
        GROUP BY flags`, d.NowMinusMinutes(hours*60), siteCond(site))
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

// JA4HitRow: load phase の payload_json.ja4_hit 別件数.
type JA4HitRow struct {
	Kind   string // "ja4_hit" / "normal" / "unknown"
	Count  int
	UniqIP int
}

func JA4HitBreakdown(ctx context.Context, d *db.DB, site string, hours int) ([]JA4HitRow, error) {
	since := d.NowMinusMinutes(hours * 60)
	hitExpr := jsonExtract(d, "payload_json", "$.ja4_hit")
	stmt := fmt.Sprintf(`
        SELECT
          CASE
            WHEN %s IN ('1', 1) THEN 'ja4_hit'
            WHEN %s IN ('0', 0) THEN 'normal'
            ELSE 'unknown'
          END AS kind,
          COUNT(*) AS n,
          COUNT(DISTINCT ip_address) AS uniq
        FROM unmask_event WHERE date_created > %s%s AND phase='load'
        GROUP BY kind`, hitExpr, hitExpr, since, siteCond(site))
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	by := map[string]JA4HitRow{}
	for rows.Next() {
		var v JA4HitRow
		if err := rows.Scan(&v.Kind, &v.Count, &v.UniqIP); err != nil {
			return nil, err
		}
		by[v.Kind] = v
	}
	out := make([]JA4HitRow, 0, 3)
	for _, k := range []string{"ja4_hit", "normal", "unknown"} {
		if r, ok := by[k]; ok {
			out = append(out, r)
		} else {
			out = append(out, JA4HitRow{Kind: k})
		}
	}
	return out, nil
}

// ReloadLoopRow: 同 IP の load phase で reload_count >= 2.
type ReloadLoopRow struct {
	IP        string
	Count     int
	MaxReload int
	MaxFlags  int
	UA        string
	LastSeen  string
}

func ReloadLoops(ctx context.Context, d *db.DB, site string, hours int) ([]ReloadLoopRow, error) {
	stmt := fmt.Sprintf(`
        SELECT ip_address, COUNT(*) AS n, MAX(reload_count) AS max_rc,
               MAX(flags) AS max_flags, MAX(user_agent) AS ua, MAX(date_created) AS last_seen
        FROM unmask_event WHERE date_created > %s%s AND phase='load' AND reload_count >= 1
        GROUP BY ip_address
        HAVING max_rc >= 2 OR n >= 3
        ORDER BY max_rc DESC, n DESC LIMIT 50`, d.NowMinusMinutes(hours*60), siteCond(site))
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
			UA: truncate(ua.String, 50), LastSeen: ls.String,
		})
	}
	return out, rows.Err()
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
}

func VerifyNGRanking(ctx context.Context, d *db.DB, site string, hours, limit int) ([]VerifyNGRow, error) {
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
        GROUP BY ip_address ORDER BY total DESC LIMIT ?`, method, method, score, since, siteCond(site))
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
			AvgScore: avg.Float64,
			UA:       truncate(ua.String, 50),
			JA4:      ja4.String,
			LastSeen: ls.String,
		})
	}
	return out, rows.Err()
}

// CookieFailRow: pow phase で cookie_set_ok=false が含まれるもの.
type CookieFailRow struct {
	IP       string
	Count    int
	UA       string
	LastSeen string
}

func CookieSetFails(ctx context.Context, d *db.DB, site string, hours int) ([]CookieFailRow, error) {
	since := d.NowMinusMinutes(hours * 60)
	cookieOK := jsonExtract(d, "payload_json", "$.cookie_set_ok")
	stmt := fmt.Sprintf(`
        SELECT ip_address, COUNT(*) AS n, MAX(user_agent) AS ua, MAX(date_created) AS ls
        FROM unmask_event
        WHERE date_created > %s%s AND phase='pow' AND %s IN ('false', 0)
        GROUP BY ip_address ORDER BY n DESC LIMIT 30`, since, siteCond(site), cookieOK)
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
		out = append(out, CookieFailRow{IP: ipFromBytes(raw), Count: n, UA: truncate(ua.String, 50), LastSeen: ls.String})
	}
	return out, rows.Err()
}

// StealthRow: verify_ok 通過したのに ja4_verdict=bot_*. 完全 stealth bot 容疑.
type StealthRow struct {
	IP       string
	Verdict  string
	UA       string
	Count    int
	LastSeen string
}

func StealthPassed(ctx context.Context, d *db.DB, site string, hours int) ([]StealthRow, error) {
	stmt := fmt.Sprintf(`
        SELECT ip_address, COALESCE(ja4_verdict,'(none)') AS v,
               MAX(user_agent) AS ua, COUNT(*) AS n, MAX(date_created) AS ls
        FROM unmask_event
        WHERE date_created > %s%s AND phase='verify_ok' AND ja4_verdict LIKE 'bot_%%'
        GROUP BY ip_address, ja4_verdict ORDER BY n DESC LIMIT 30`, d.NowMinusMinutes(hours*60), siteCond(site))
	rows, err := d.QueryContext(ctx, stmt)
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
			Count: n, LastSeen: ls.String,
		})
	}
	return out, rows.Err()
}

// JSErrorRow: error phase に payload に乗ってくる JS エラー.
type JSErrorRow struct {
	IP       string
	UA       string
	Flags    int
	Error    string
	Date     string
}

func JSErrors(ctx context.Context, d *db.DB, site string, hours int) ([]JSErrorRow, error) {
	errMsg := jsonExtract(d, "payload_json", "$.error_msg")
	stmt := fmt.Sprintf(`
        SELECT ip_address, user_agent, flags, %s AS err, date_created
        FROM unmask_event
        WHERE date_created > %s%s AND phase='error'
        ORDER BY id DESC LIMIT 30`, errMsg, d.NowMinusMinutes(hours*60), siteCond(site))
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
			Error: truncate(strings.Trim(errStr.String, `"`), 120),
			Date:  ds.String,
		})
	}
	return out, rows.Err()
}

// DailyBucket: 日次推移系列.
type DailyBucket struct {
	Date     string
	Serve    int
	Load     int
	PoW      int
	Captcha  int
	VerifyOK int
}

// is_bot kind: classify.Category と同値 (= 0/1/2/4/5/6) + 99 = rate_limit (= 100r/min 超過).
const KindRateLimit = 99

// DailyKindBucket: 日付 × is_bot kind 別の req 数.  本家 _build_serve_30d と同じ集計軸.
type DailyKindBucket struct {
	Date string
	Kind int
	Req  int
}

// DailyTotal: 日別合計 (req + uniq IP).
type DailyTotal struct {
	Date    string
	Req     int
	UniqIPs int
}

// DailyServeByKind: phase='serve' を date × ip × verdict × ua × rl で集計し、
// 各行を classify.IsBot で分類して date × kind 別 req 数を返す.
// 同時に日別合計 + uniq IP も返す.  本家 BotChallengeDebug._build_serve_30d 相当.
//
// 戻り値:
//   - daily: stacked bar 用の (date, kind, req) リスト
//   - total: 日別 req + uniq IP リスト
func DailyServeByKind(ctx context.Context, d *db.DB, site string, days int) ([]DailyKindBucket, []DailyTotal, error) {
	since := d.NowMinusMinutes(days * 24 * 60)
	jsonRL := jsonExtract(d, "payload_json", "$.rl")
	stmt := fmt.Sprintf(`
        SELECT DATE(date_created) AS d,
               ip_address,
               COALESCE(ja4_verdict, '') AS verdict,
               COALESCE(user_agent, '') AS ua,
               CASE WHEN %s IN ('1', 1) THEN 1 ELSE 0 END AS is_rl,
               COUNT(*) AS n
        FROM unmask_event
        WHERE phase='serve' AND date_created > %s%s
        GROUP BY DATE(date_created), ip_address, ja4_verdict, user_agent, is_rl
        ORDER BY d`, jsonRL, since, siteCond(site))
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

		var kind int
		if isRL == 1 {
			kind = KindRateLimit
		} else {
			kind = int(classify.IsBot(ua, verdict))
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

// ---- legacy: phase 別 daily series (= 既存 chart 用. 段階廃止予定) ----

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

// jsonExtract returns a SQL fragment that extracts a JSON path. SQLite と
// MariaDB は呼び出し名 / 引用記号が違う.
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

// Pinger: dashboard 用 health helper.
func Pinger(d *db.DB) error {
	return d.PingContext(context.Background())
}
