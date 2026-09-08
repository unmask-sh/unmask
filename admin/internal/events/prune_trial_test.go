package events

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestPruneTrial is a scale trial, not a unit test: it seeds a file-backed
// database with UNMASK_PRUNE_TRIAL_ROWS rows (most of them past the window),
// then prunes while a second goroutine inserts at the rate of a busy install
// and counts the inserts that hit the busy timeout.  Skipped unless
// UNMASK_PRUNE_TRIAL=1.  Prints the chunk sizes it settled on, the longest
// lock hold and the insert failures -- the numbers the pacing exists for.
//
//	UNMASK_PRUNE_TRIAL=1 UNMASK_PRUNE_TRIAL_ROWS=2000000 go test ./internal/events/ -run TestPruneTrial -v -timeout 2h
func TestPruneTrial(t *testing.T) {
	if os.Getenv("UNMASK_PRUNE_TRIAL") != "1" {
		t.Skip("set UNMASK_PRUNE_TRIAL=1 to run the scale trial")
	}
	rows := 1000000
	if v, err := strconv.Atoi(os.Getenv("UNMASK_PRUNE_TRIAL_ROWS")); err == nil && v > 0 {
		rows = v
	}
	dir := os.Getenv("UNMASK_PRUNE_TRIAL_DIR")
	if dir == "" {
		dir = t.TempDir()
	}
	path := filepath.Join(dir, "trial.sqlite")
	os.Remove(path)
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: path})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}

	// Seed: rows spread over 20 days, realistic widths (a 180-byte UA, a
	// 300-byte payload), 20,000 per transaction.
	t0 := time.Now()
	ua := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0 -- padded to the width of a long desktop user agent string........"
	payload := `{"bt":"dl9jumvdjqa5.1zucixxgtow4t.5b4967e22ec134c0","ch_mode":"pow_then_captcha","force_reason":"ja4_bot","orig_path":"/some/article/path/that/is/long/enough/12345","ref":"a9e2e76a88285ebe","referer":"https://example.invalid/section/","rl":0,"test":0,"pad":"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}`
	span := 20 * 24 * time.Hour
	base := time.Now().UTC().Add(-span)
	for done := 0; done < rows; {
		tx, err := d.Begin()
		if err != nil {
			t.Fatal(err)
		}
		st, err := tx.Prepare(`INSERT INTO unmask_event (site,host,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created) VALUES ('www.example','edge',?,?,'t13d1516h2_8daaf6152771_e5627efa2ab1','',0,'serve',0,0,'','',?,?)`)
		if err != nil {
			t.Fatal(err)
		}
		n := 20000
		if rows-done < n {
			n = rows - done
		}
		for i := 0; i < n; i++ {
			k := done + i
			ts := base.Add(time.Duration(float64(span) * float64(k) / float64(rows)))
			ip := []byte{byte(10 + k%200), byte(k >> 16), byte(k >> 8), byte(k)}
			if _, err := st.Exec(ip, ua, payload, ts.Format("2006-01-02 15:04:05.000")); err != nil {
				t.Fatal(err)
			}
		}
		st.Close()
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		done += n
	}
	st, _ := os.Stat(path)
	t.Logf("seeded %d rows in %v, file %.1f MB", rows, time.Since(t0).Round(time.Second), float64(st.Size())/1e6)

	// The concurrent writer: ~50 single-row inserts per second, like a node
	// recording ~3,000 events a minute through the batcher, each with the
	// 5 s busy timeout of the pool.  Counts failures and the slowest insert.
	var inserts, failures int64
	var slowest int64 // nanoseconds
	stop := make(chan struct{})
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		tick := time.NewTicker(20 * time.Millisecond)
		defer tick.Stop()
		i := 0
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				i++
				ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
				s := time.Now()
				_, err := d.ExecContext(ctx, `INSERT INTO unmask_event (site,host,ip_address,user_agent,phase,payload_json,date_created) VALUES ('www.example','edge',?,?,'serve',?,?)`,
					[]byte{192, 0, byte(i >> 8), byte(i)}, ua, payload, time.Now().UTC().Format("2006-01-02 15:04:05.000"))
				cancel()
				took := time.Since(s).Nanoseconds()
				for {
					cur := atomic.LoadInt64(&slowest)
					if took <= cur || atomic.CompareAndSwapInt64(&slowest, cur, took) {
						break
					}
				}
				if err != nil {
					atomic.AddInt64(&failures, 1)
				} else {
					atomic.AddInt64(&inserts, 1)
				}
			}
		}
	}()

	var chunks int
	var longest time.Duration
	var lastDeleted int64
	last := time.Now()
	sizes := map[int]int{}
	prev := time.Now()
	res, err := PruneOldEventsOpts(context.Background(), d, 7, PruneOptions{Progress: func(r PruneResult) {
		chunks++
		n := int(r.Deleted - lastDeleted)
		lastDeleted = r.Deleted
		sizes[n]++
		if d := time.Since(prev); d > longest {
			longest = d
		}
		prev = time.Now()
		if time.Since(last) > 15*time.Second {
			last = time.Now()
			t.Logf("  %d rows deleted, %d chunks, inserts ok=%d failed=%d slowest=%v", r.Deleted, r.Chunks, atomic.LoadInt64(&inserts), atomic.LoadInt64(&failures), time.Duration(atomic.LoadInt64(&slowest)).Round(time.Millisecond))
		}
	}})
	close(stop)
	<-writerDone
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	st, _ = os.Stat(path)
	wal, _ := os.Stat(path + "-wal")
	var walSize int64
	if wal != nil {
		walSize = wal.Size()
	}
	t.Logf("pruned %d rows in %d chunks, %v (busy retries %d); chunk sizes seen: %s; longest chunk-to-chunk gap %v",
		res.Deleted, res.Chunks, res.Elapsed.Round(time.Second), res.BusyRetries, fmtSizes(sizes), longest.Round(time.Millisecond))
	t.Logf("concurrent writer: %d inserts ok, %d failed, slowest insert %v; file %.1f MB, wal %.1f MB",
		atomic.LoadInt64(&inserts), atomic.LoadInt64(&failures), time.Duration(atomic.LoadInt64(&slowest)).Round(time.Millisecond), float64(st.Size())/1e6, float64(walSize)/1e6)
	if atomic.LoadInt64(&failures) > 0 {
		t.Errorf("%d inserts failed during the paced prune", atomic.LoadInt64(&failures))
	}
}

func fmtSizes(m map[int]int) string {
	// bucket by 500s to keep the line short
	b := map[int]int{}
	for n, c := range m {
		b[(n/500)*500] += c
	}
	s := ""
	for k := 0; k <= 20000; k += 500 {
		if b[k] > 0 {
			s += fmt.Sprintf("%d-%d:%d ", k, k+499, b[k])
		}
	}
	return s
}
