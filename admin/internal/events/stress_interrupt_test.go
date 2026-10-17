//go:build stress

package events

// A stress of what kanagawa's daemon was doing when it died (2026-10-18
// 02:38:59: SIGSEGV in the page cache's free as a read transaction began,
// reached from an AI tool's CountHourly): scans of a large event table that
// context deadlines interrupt at every stage, beside batched writes rolled
// back by deadlines, a full count cut short, readers cancelled mid-page, and a
// pool that recycles its connections.  Built with -tags libc.memgrind the libc
// allocator audits every free and panics on a double free, or a free of
// memory it did not hand out, naming both callers.  Not part of the suite:
//
//	UNMASK_STRESS_SECONDS=120 UNMASK_STRESS_ROWS=300000 \
//	  go test -tags 'stress libc.memgrind' -run TestStressInterruptedScans -v -timeout 2h ./internal/events

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
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func TestStressInterruptedScans(t *testing.T) {
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
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(dir, "s.sqlite")})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}

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
	mk := func(r *rand.Rand, at time.Time) *Event {
		pl := map[string]any{"path": "/p/" + strconv.Itoa(r.Intn(500)), "chmode": "pow_only"}
		if rs := reasons[r.Intn(len(reasons))]; rs != "" {
			pl["force_reason"] = rs
		}
		return &Event{
			Site: "s1", Host: "h1", Scheme: "https", Port: 443,
			IPPacked:  []byte{10, byte(r.Intn(40)), byte(r.Intn(256)), byte(r.Intn(256))},
			UserAgent: uas[r.Intn(len(uas))], JA4: ja4s[r.Intn(len(ja4s))],
			Phase: phases[r.Intn(len(phases))], Payload: pl, OccurredAt: at,
		}
	}

	// Seed: rows spread over the last two days.
	seed := rand.New(rand.NewSource(1))
	now := time.Now().UTC()
	batch := make([]*Event, 0, 5000)
	t0 := time.Now()
	for i := 0; i < rows; i++ {
		batch = append(batch, mk(seed, now.Add(-time.Duration(seed.Int63n(int64(48*time.Hour))))))
		if len(batch) == cap(batch) || i == rows-1 {
			if err := insertBulk(context.Background(), d, batch); err != nil {
				t.Fatal(err)
			}
			batch = batch[:0]
		}
	}
	t.Logf("seeded %d rows in %v", rows, time.Since(t0).Round(time.Second))

	// The pool recycles its connections quickly, so closes race with the
	// deadlines' interrupts as well.
	d.SetConnMaxLifetime(300 * time.Millisecond)
	d.SetMaxIdleConns(2)

	stop := time.Now().Add(time.Duration(secs) * time.Second)
	var ok, dead, other, writes, wfail, pages, counts atomic.Int64
	var wg sync.WaitGroup
	loc := time.FixedZone("JST", 9*3600)
	hours := []int{1, 6, 24, 48, 168}
	timeouts := []time.Duration{time.Millisecond, 3 * time.Millisecond, 10 * time.Millisecond, 30 * time.Millisecond, 100 * time.Millisecond, 300 * time.Millisecond, 5 * time.Second}
	judge := func(ctx context.Context, err error, who string, id int) {
		switch {
		case err == nil:
			ok.Add(1)
		case ctx.Err() != nil || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled):
			dead.Add(1)
		default:
			other.Add(1)
			t.Logf("%s %d: %v", who, id, err)
		}
	}

	// CountHourly under every filter shape the AI tool passes, with deadlines
	// that land in the prepare, the first step, the middle of the scan and
	// after the end.
	reader := func(id int) {
		defer wg.Done()
		r := rand.New(rand.NewSource(int64(id)))
		for time.Now().Before(stop) {
			var ua, reason, ja4, phase string
			switch r.Intn(5) {
			case 0:
				ua = "Chrome"
			case 1:
				reason = "rate_limit"
			case 2:
				ja4 = "8daaf6152771"
			case 3:
				phase = "serve,load"
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeouts[r.Intn(len(timeouts))])
			_, err := CountHourly(ctx, d, "", ja4, ua, phase, reason, "", nil, hours[r.Intn(len(hours))]*60, loc)
			judge(ctx, err, "count-hourly", id)
			cancel()
		}
	}
	// Batches written the way the flusher writes them, most with a deadline
	// that ends the transaction partway (rolled back).
	writer := func(id int) {
		defer wg.Done()
		r := rand.New(rand.NewSource(100 + int64(id)))
		for time.Now().Before(stop) {
			n := 50 + r.Intn(400)
			evs := make([]*Event, n)
			for i := range evs {
				evs[i] = mk(r, time.Now().UTC())
			}
			to := time.Duration(1+r.Intn(40)) * time.Millisecond
			if r.Intn(4) == 0 {
				to = 5 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), to)
			if err := insertBulk(ctx, d, evs); err != nil {
				wfail.Add(1)
			} else {
				writes.Add(int64(n))
			}
			cancel()
		}
	}
	// A page of rows cancelled from another goroutine while it is being read.
	pager := func(id int) {
		defer wg.Done()
		r := rand.New(rand.NewSource(200 + int64(id)))
		for time.Now().Before(stop) {
			ctx, cancel := context.WithCancel(context.Background())
			after := time.Duration(r.Intn(3000)) * time.Microsecond
			go func() { time.Sleep(after); cancel() }()
			rs, err := d.QueryContext(ctx, `SELECT id, ip_address, user_agent, payload_json FROM unmask_event WHERE user_agent LIKE ? ORDER BY id DESC LIMIT 200`, "%Chrome%")
			if err == nil {
				for rs.Next() {
					var rid int64
					var ip []byte
					var ua, pl string
					_ = rs.Scan(&rid, &ip, &ua, &pl)
				}
				rs.Close()
				pages.Add(1)
			}
			cancel()
		}
	}
	// The retention tab's count of the whole table under its short budget.
	counter := func(id int) {
		defer wg.Done()
		r := rand.New(rand.NewSource(300 + int64(id)))
		for time.Now().Before(stop) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Duration(1+r.Intn(50))*time.Millisecond)
			var n int64
			err := d.QueryRowContext(ctx, `SELECT COUNT(*) FROM unmask_event`).Scan(&n)
			if err == nil {
				counts.Add(1)
			} else {
				judge(ctx, err, "count", id)
			}
			cancel()
		}
	}
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go reader(i)
	}
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go writer(i)
	}
	wg.Add(2)
	go pager(0)
	go counter(0)
	wg.Wait()

	var n int64
	if err := d.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM unmask_event`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	t.Logf("%ds: count-hourly ok=%d deadline=%d other=%d; writes=%d rows (%d batches rolled back); pages=%d; full counts done=%d; table now %d rows",
		secs, ok.Load(), dead.Load(), other.Load(), writes.Load(), wfail.Load(), pages.Load(), counts.Load(), n)
	if other.Load() > 0 {
		t.Errorf("%d reads failed with something other than their deadline", other.Load())
	}
}
