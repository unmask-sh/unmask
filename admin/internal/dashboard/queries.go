// Package dashboard: ダッシュボード用の集計クエリ群.
//
// 大半は (verdict, phase) で GROUP BY する単純な集計.
// 過去 N 日 default 7 日で絞り込む.
package dashboard

import (
	"context"
	"database/sql"
	"fmt"
	"net"

	"github.com/unmask-sh/unmask/admin/internal/db"
)

// FunnelRow: 1 行 = 1 verdict (= JA4 verdict + 集約済みカテゴリ).
//
// challenge phase の累積件数を verdict 別に並べる.  Mojolicious 版 dashboard と
// 同じカラム並びを保つ.
type FunnelRow struct {
	Verdict      string  // "ok", "bot_chrome_fake_h1", "rate_limit_total", "TOTAL", ...
	Serve        int     // challenge HTML が配信された数
	RL           int     // ?_rl=1 (= rate-limit 経由) でやってきた数
	Load         int     // JS 起動した数
	PoW          int     // PoW 完走した数
	Captcha      int     // CAPTCHA 表示までいった数
	VerifyOK     int     // _bv 発行成功
	VerifyNG     int     // 失敗
	CookieErr    int     // cookie が読めず loop 検知
	JSError      int     // 例外捕捉
	Silent       int     // serve したのに JS load せず (= bot で JS 走らなかった)
	PowRate      float64 // PoW / Load
	CaptchaRate  float64 // Captcha / Load
}

// Funnel returns one row per ja4_verdict observed in the last `days` days,
// plus a TOTAL row aggregating everything.
func Funnel(ctx context.Context, d *db.DB, days int) ([]FunnelRow, error) {
	stmt := fmt.Sprintf(`
        SELECT COALESCE(ja4_verdict, '(none)') AS verdict, phase, COUNT(*) AS cnt
        FROM unmask_event
        WHERE date_created > %s
        GROUP BY ja4_verdict, phase
    `, d.NowMinusMinutes(days*24*60))

	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	byVerdict := map[string]*FunnelRow{}
	for rows.Next() {
		var verdict, phase string
		var cnt int
		if err := rows.Scan(&verdict, &phase, &cnt); err != nil {
			return nil, err
		}
		fr, ok := byVerdict[verdict]
		if !ok {
			fr = &FunnelRow{Verdict: verdict}
			byVerdict[verdict] = fr
		}
		switch phase {
		case "serve":
			fr.Serve += cnt
		case "load":
			fr.Load += cnt
		case "pow":
			fr.PoW += cnt
		case "captcha":
			fr.Captcha += cnt
		case "verify_ok":
			fr.VerifyOK += cnt
		case "verify_ng":
			fr.VerifyNG += cnt
		case "cookie_err":
			fr.CookieErr += cnt
		case "error":
			fr.JSError += cnt
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// silent = serve - load (= 配信したのに JS が動かなかった = bot 確実)
	// 比率列を埋めて、 verdict 名でソート.
	var out []FunnelRow
	total := FunnelRow{Verdict: "TOTAL"}
	for _, fr := range byVerdict {
		fr.Silent = fr.Serve - fr.Load
		if fr.Silent < 0 {
			fr.Silent = 0
		}
		if fr.Load > 0 {
			fr.PowRate = float64(fr.PoW) / float64(fr.Load)
			fr.CaptchaRate = float64(fr.Captcha) / float64(fr.Load)
		}
		total.Serve += fr.Serve
		total.Load += fr.Load
		total.PoW += fr.PoW
		total.Captcha += fr.Captcha
		total.VerifyOK += fr.VerifyOK
		total.VerifyNG += fr.VerifyNG
		total.CookieErr += fr.CookieErr
		total.JSError += fr.JSError
		total.Silent += fr.Silent
		out = append(out, *fr)
	}
	if total.Load > 0 {
		total.PowRate = float64(total.PoW) / float64(total.Load)
		total.CaptchaRate = float64(total.Captcha) / float64(total.Load)
	}
	out = append(out, total)
	return out, nil
}

type VerdictCount struct {
	Verdict string
	Count   int
}

// VerdictDistribution: 直近 days 日の JA4 verdict 別件数 (= challenge serve に関わらず全 event).
func VerdictDistribution(ctx context.Context, d *db.DB, days int) ([]VerdictCount, error) {
	stmt := fmt.Sprintf(`
        SELECT COALESCE(ja4_verdict, '(none)') AS v, COUNT(*) AS cnt
        FROM unmask_event
        WHERE date_created > %s
        GROUP BY ja4_verdict
        ORDER BY cnt DESC
    `, d.NowMinusMinutes(days*24*60))
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []VerdictCount
	for rows.Next() {
		var v VerdictCount
		if err := rows.Scan(&v.Verdict, &v.Count); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

type IPCount struct {
	IP    string
	Count int
}

// CaptchaFailIPs: verify_ng が多い IP. 直近 days 日.
func CaptchaFailIPs(ctx context.Context, d *db.DB, days, limit int) ([]IPCount, error) {
	stmt := fmt.Sprintf(`
        SELECT ip_address, COUNT(*) AS cnt
        FROM unmask_event
        WHERE phase = 'verify_ng' AND date_created > %s
        GROUP BY ip_address
        ORDER BY cnt DESC
        LIMIT ?
    `, d.NowMinusMinutes(days*24*60))
	rows, err := d.QueryContext(ctx, stmt, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IPCount
	for rows.Next() {
		var raw []byte
		var cnt int
		if err := rows.Scan(&raw, &cnt); err != nil {
			return nil, err
		}
		out = append(out, IPCount{IP: ipFromBytes(raw), Count: cnt})
	}
	return out, rows.Err()
}

// DailySeries: 直近 days 日の serve / load / pow / captcha / verify_ok の日次系列.
type DailyBucket struct {
	Date     string
	Serve    int
	Load     int
	PoW      int
	Captcha  int
	VerifyOK int
}

func DailySeries(ctx context.Context, d *db.DB, days int) ([]DailyBucket, error) {
	var dateExpr string
	if d.Driver == db.DriverSQLite {
		dateExpr = "DATE(date_created)"
	} else {
		dateExpr = "DATE(date_created)"
	}
	stmt := fmt.Sprintf(`
        SELECT %s AS d, phase, COUNT(*) FROM unmask_event
        WHERE date_created > %s
        GROUP BY %s, phase
        ORDER BY d
    `, dateExpr, d.NowMinusMinutes(days*24*60), dateExpr)
	rows, err := d.QueryContext(ctx, stmt)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	by := map[string]*DailyBucket{}
	var order []string
	for rows.Next() {
		var ds string
		var phase string
		var cnt int
		var dsRaw any
		if err := rows.Scan(&dsRaw, &phase, &cnt); err != nil {
			return nil, err
		}
		switch v := dsRaw.(type) {
		case string:
			ds = v
		case []byte:
			ds = string(v)
		default:
			ds = fmt.Sprintf("%v", v)
		}
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

func ipFromBytes(b []byte) string {
	switch len(b) {
	case 4:
		return net.IP(b).To4().String()
	case 16:
		return net.IP(b).To16().String()
	}
	return ""
}

// Pinger is a tiny helper to confirm the dashboard can read the DB.
func Pinger(d *db.DB) error {
	return d.PingContext(context.Background())
}

// Suppress "imported and not used" warning for sql in case future helpers
// drop direct usage.
var _ = sql.ErrNoRows
