package nginxlog

import "testing"

// The access-log counters are flushed once a minute.  While a schema update
// holds the write lock a flush would wait out the busy timeout and fail, so
// it stands back: what was counted stays in memory, goes on counting, and
// is written by the first flush after the lock is free -- nothing counted
// during the update is lost, and nothing is counted twice.
func TestFlushStandsBackWhileWritesAreHeld(t *testing.T) {
	r, d := cookieIPReader(t)
	total := func() int {
		var n int
		if err := d.QueryRow(`SELECT COALESCE(SUM(cnt), 0) FROM unmask_cookie_ip_minute`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	d.HoldWrites(true)
	r.bumpCookieIP("s1", "1.2.3.4", "t13d_a", "UA-A", "pow")
	r.bumpCookieIP("s1", "1.2.3.4", "t13d_a", "UA-A", "pow")
	r.flushOnce(true)
	if got := total(); got != 0 {
		t.Fatalf("%d written while writes were held", got)
	}
	if len(r.cookieIPBuckets) == 0 {
		t.Fatal("the flush that stood back threw the counters away")
	}
	// Still counting.
	r.bumpCookieIP("s1", "1.2.3.4", "t13d_a", "UA-A", "pow")

	d.HoldWrites(false)
	r.flushOnce(true)
	if got := total(); got != 3 {
		t.Fatalf("after the hold: %d written, want the 3 counted during it", got)
	}
	r.flushOnce(true)
	if got := total(); got != 3 {
		t.Fatalf("a second flush wrote again: %d", got)
	}
}
