//go:build stress

package aitools

// The second stress: the Ask AI tools themselves, as the model calls them,
// each under a deadline that lands anywhere in its work (the chat gives a
// tool 30 s; here the deadlines are short so interrupts are frequent), beside
// batched writes rolled back by deadlines and a pool that recycles its
// connections.  Built with -tags libc.memgrind the libc allocator panics on a
// double free or a free of memory it did not hand out.  Not part of the suite:
//
//	UNMASK_STRESS_SECONDS=240 UNMASK_STRESS_ROWS=300000 \
//	  go test -tags 'stress libc.memgrind' -run TestStressTools -v -timeout 2h ./internal/aitools

import (
	"context"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/live"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

const stressInsert = `INSERT INTO unmask_event
        (site, host, scheme, port, ip_address, user_agent, ja4, ja4_verdict, ja4_verdict_id, phase, flags, reload_count,
         cookie_bv, cookie_br, payload_json, ref_id, date_created)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`

type stressRow struct {
	ip      []byte
	ua, ja4 string
	phase   string
	payload string
	at      time.Time
}

func stressMake(r *rand.Rand, at time.Time) stressRow {
	phases := []string{"serve", "serve", "serve", "load", "load", "bv_pow_only", "abandon", "bv_captcha_only", "bv_pow_then_captcha"}
	uas := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
		"python-requests/2.31",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
		"curl/8.4.0",
		"Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
	}
	ja4s := []string{"t13d1516h2_8daaf6152771_b0da82dd1658", "t13d1516h2_8daaf6152771_02713d6af862", "t12d600600_c4ee5c5f8f6f_e3b0c44298fc", "t13d1517h2_5b57614c22b0_3d5424432f57"}
	reasons := []string{"", "", "", "rate_limit", "honeypot", "ua_target", "asn"}
	pl := `{"path":"/p/` + strconv.Itoa(r.Intn(500)) + `","chmode":"pow_only"`
	if rs := reasons[r.Intn(len(reasons))]; rs != "" {
		pl += `,"force_reason":"` + rs + `"`
	}
	pl += "}"
	return stressRow{
		ip: []byte{10, byte(r.Intn(40)), byte(r.Intn(256)), byte(r.Intn(256))}, ua: uas[r.Intn(len(uas))], ja4: ja4s[r.Intn(len(ja4s))],
		phase: phases[r.Intn(len(phases))], payload: pl, at: at,
	}
}

// stressWrite writes rows the way the flusher does: one transaction, one
// prepared statement, a row per exec, rolled back when the context ends.
func stressWrite(ctx context.Context, d *db.DB, rows []stressRow) error {
	tx, err := d.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	stmt, err := tx.PrepareContext(ctx, stressInsert)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range rows {
		if _, err := stmt.ExecContext(ctx, "s1", "h1", "https", 443, e.ip, e.ua, e.ja4, "", nil, e.phase, 0, 0, "", "", e.payload, nil, e.at.UTC().Format("2006-01-02 15:04:05.000")); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func TestStressTools(t *testing.T) {
	secs, _ := strconv.Atoi(os.Getenv("UNMASK_STRESS_SECONDS"))
	if secs <= 0 {
		secs = 60
	}
	rows, _ := strconv.Atoi(os.Getenv("UNMASK_STRESS_ROWS"))
	if rows <= 0 {
		rows = 300000
	}
	memAuditStart()
	dir := t.TempDir()
	conn, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "s.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := db.Migrate(conn); err != nil {
		t.Fatal(err)
	}
	seed := rand.New(rand.NewSource(1))
	now := time.Now().UTC()
	batch := make([]stressRow, 0, 5000)
	t0 := time.Now()
	for i := 0; i < rows; i++ {
		batch = append(batch, stressMake(seed, now.Add(-time.Duration(seed.Int63n(int64(48*time.Hour))))))
		if len(batch) == cap(batch) || i == rows-1 {
			if err := stressWrite(context.Background(), conn, batch); err != nil {
				t.Fatal(err)
			}
			batch = batch[:0]
		}
	}
	t.Logf("seeded %d rows in %v", rows, time.Since(t0).Round(time.Second))
	for i := 0; i < 20; i++ {
		if err := conn.Gorm.Create(&db.Ban{IP: "203.0.113." + strconv.Itoa(i), JA4: "", Source: "honeypot", Reason: "wp-login", BannedAt: now.Unix(), Action: "deny", Scope: "ip_only"}).Error; err != nil {
			t.Fatal(err)
		}
	}
	lv := live.New()
	lv.Hit(now, "JP", live.Of(live.Requests, live.Pass))
	s := settings.Settings{}
	s.DB.Driver = "sqlite"
	s.AIAdvisor = settings.AIAdvisorConfig{Provider: "openai", Model: "gpt-x"}
	deps := Deps{DB: conn, Settings: func() settings.Settings { return s }, Live: lv, Version: "0.0.0-stress", Loc: time.FixedZone("JST", 9*3600)}

	conn.SetConnMaxLifetime(300 * time.Millisecond)
	conn.SetMaxIdleConns(2)

	stop := time.Now().Add(time.Duration(secs) * time.Second)
	var ok, dead, other, writes, wfail atomic.Int64
	var wg sync.WaitGroup
	calls := []struct {
		name string
		args map[string]any
	}{
		{"overview", map[string]any{"window_hours": float64(24)}},
		{"overview", map[string]any{"window_hours": float64(168)}},
		{"top", map[string]any{"kind": "ip", "window_hours": float64(24)}},
		{"top", map[string]any{"kind": "ja4", "window_hours": float64(48)}},
		{"top", map[string]any{"kind": "ua", "window_hours": float64(6)}},
		{"events", map[string]any{"limit": float64(200), "window_hours": float64(24)}},
		{"events", map[string]any{"ua": "Chrome", "window_hours": float64(48)}},
		{"events", map[string]any{"reason": "rate_limit", "window_hours": float64(24)}},
		{"events", map[string]any{"ja4": "8daaf6152771", "phase": "serve", "window_hours": float64(12)}},
		{"events_count", map[string]any{"window_hours": float64(24)}},
		{"events_count", map[string]any{"window_hours": float64(168), "ua": "Chrome"}},
		{"events_count", map[string]any{"window_hours": float64(48), "reason": "rate_limit"}},
		{"events_count", map[string]any{"window_hours": float64(6), "ja4": "8daaf6152771", "phase": "serve,load"}},
		{"lookup_ip", map[string]any{"ip": "10.3.4.5"}},
		{"bans", map[string]any{"limit": float64(50)}},
		{"live_now", map[string]any{}},
		{"settings_summary", map[string]any{}},
	}
	timeouts := []time.Duration{time.Millisecond, 3 * time.Millisecond, 10 * time.Millisecond, 30 * time.Millisecond, 100 * time.Millisecond, 300 * time.Millisecond, 5 * time.Second}
	caller := func(id int) {
		defer wg.Done()
		r := rand.New(rand.NewSource(int64(id)))
		for time.Now().Before(stop) {
			c := calls[r.Intn(len(calls))]
			ctx, cancel := context.WithTimeout(context.Background(), timeouts[r.Intn(len(timeouts))])
			_, err := deps.Run(ctx, c.name, c.args)
			switch {
			case err == nil:
				ok.Add(1)
			case ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded):
				dead.Add(1)
			default:
				other.Add(1)
				t.Logf("%s: %v", c.name, err)
			}
			cancel()
		}
	}
	writer := func(id int) {
		defer wg.Done()
		r := rand.New(rand.NewSource(100 + int64(id)))
		for time.Now().Before(stop) {
			n := 50 + r.Intn(400)
			evs := make([]stressRow, n)
			for i := range evs {
				evs[i] = stressMake(r, time.Now().UTC())
			}
			to := time.Duration(1+r.Intn(40)) * time.Millisecond
			if r.Intn(4) == 0 {
				to = 5 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), to)
			if err := stressWrite(ctx, conn, evs); err != nil {
				wfail.Add(1)
			} else {
				writes.Add(int64(n))
			}
			cancel()
		}
	}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go caller(i)
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go writer(i)
	}
	wg.Wait()
	var n int64
	if err := conn.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM unmask_event`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	t.Logf("%ds: tools ok=%d deadline=%d other=%d; writes=%d rows (%d batches rolled back); table now %d rows", secs, ok.Load(), dead.Load(), other.Load(), writes.Load(), wfail.Load(), n)
	_ = events.PackIP // the events package stays linked for its init (phases)
}
