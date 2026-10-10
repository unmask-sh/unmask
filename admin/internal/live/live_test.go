package live

import (
	"testing"
	"time"
)

func TestHitAndSnapshotWindows(t *testing.T) {
	c := New()
	base := time.Unix(1_800_000_000, 0)
	// 3 requests now, 2 of them passes from JP; 1 serve 30 s ago; 4 requests
	// 90 s ago (in the previous window); 1 request 400 s ago (out of the ring).
	c.Hit(base, "JP", Of(Requests, Pass))
	c.Hit(base, "JP", Of(Requests, Pass))
	c.Hit(base, "", Of(Requests))
	c.Hit(base.Add(-30*time.Second), "US", Of(Requests, Serve))
	for i := 0; i < 4; i++ {
		c.Hit(base.Add(-90*time.Second), "DE", Of(Requests))
	}
	c.Hit(base.Add(-400*time.Second), "FR", Of(Requests))

	sn := c.Snapshot(base)
	if sn.At != base.Unix()+1 {
		t.Errorf("At = %d, want %d", sn.At, base.Unix()+1)
	}
	if sn.Last[Requests] != 4 || sn.Last[Pass] != 2 || sn.Last[Serve] != 1 {
		t.Errorf("last window: requests=%d pass=%d serve=%d, want 4/2/1", sn.Last[Requests], sn.Last[Pass], sn.Last[Serve])
	}
	if sn.Prev[Requests] != 4 || sn.Prev[Serve] != 0 {
		t.Errorf("previous window: requests=%d serve=%d, want 4/0", sn.Prev[Requests], sn.Prev[Serve])
	}
	var total uint32
	for _, v := range sn.Series[Requests] {
		total += v
	}
	if total != 8 {
		t.Errorf("series total = %d, want 8 (the 400 s old hit is outside the ring)", total)
	}
	if sn.Series[Requests][Buckets-1] != 3 {
		t.Errorf("newest bucket = %d, want 3", sn.Series[Requests][Buckets-1])
	}
	if sn.Series[Serve][Buckets-1-30/Step] != 1 {
		t.Errorf("the serve 30 s ago is not in its bucket: %v", sn.Series[Serve])
	}
	if jp := sn.Countries["JP"]; jp.N != 2 || jp.Pass != 2 {
		t.Errorf("JP = %+v, want n=2 pass=2", jp)
	}
	if us := sn.Countries["US"]; us.N != 1 || us.Serve != 1 {
		t.Errorf("US = %+v, want n=1 serve=1", us)
	}
	if _, ok := sn.Countries["DE"]; ok {
		t.Error("DE is 90 s old and must not be in the window's countries")
	}
	if _, ok := sn.Countries[""]; ok {
		t.Error("an unknown country must not become a key")
	}
	if sn.TPS != 3.0/Step || sn.Peak != 4.0/Step || sn.Avg != 8.0/Span {
		t.Errorf("tps=%v peak=%v avg=%v", sn.TPS, sn.Peak, sn.Avg)
	}
	if sn.LastLine != base.Unix() {
		t.Errorf("LastLine = %d, want %d", sn.LastLine, base.Unix())
	}
}

func TestSlotReuseDropsTheOldSecond(t *testing.T) {
	c := New()
	base := time.Unix(1_800_000_000, 0)
	c.Hit(base, "JP", Of(Requests))
	// Span seconds later the same slot is written again: the old count must
	// not leak into the new second, and the old country map must be gone.
	later := base.Add(Span * time.Second)
	c.Hit(later, "US", Of(Requests, Deny))
	sn := c.Snapshot(later)
	if sn.Last[Requests] != 1 || sn.Last[Deny] != 1 {
		t.Errorf("last = %v, want one request, one deny", sn.Last)
	}
	if _, ok := sn.Countries["JP"]; ok {
		t.Error("the country of the overwritten second survived the reuse")
	}
	// Read as of the old time: the slot now holds the new second, so the old
	// one reads as empty rather than as the new count.
	old := c.Snapshot(base)
	if old.Last[Requests] != 0 {
		t.Errorf("a stale read returned %d requests, want 0", old.Last[Requests])
	}
}

func TestObserveEvent(t *testing.T) {
	c := New()
	now := time.Unix(1_800_000_000, 0)
	c.ObserveEvent(now, "bv_pow_only", "JP", false)
	c.ObserveEvent(now, "bv_captcha_only", "", false)
	c.ObserveEvent(now, "bv_pow_then_captcha", "", false)
	c.ObserveEvent(now, "serve", "US", true)
	c.ObserveEvent(now, "serve", "US", false) // an ordinary serve: the access log counts it
	c.ObserveEvent(now, "load", "", false)
	sn := c.Snapshot(now)
	if sn.Last[Solve] != 3 || sn.Last[RateLimit] != 1 || sn.Last[Requests] != 0 || sn.Last[Serve] != 0 {
		t.Errorf("last = %v, want 3 solves, 1 rate-limit, nothing else", sn.Last)
	}
	if sn.LastLine != 0 {
		t.Error("events must not count as the access-log feed being alive")
	}
}

func TestNilCounterIsInert(t *testing.T) {
	var c *Counter
	c.Hit(time.Now(), "JP", Of(Requests))
	c.ObserveEvent(time.Now(), "serve", "", true)
	sn := c.Snapshot(time.Now())
	if sn.Last[Requests] != 0 || len(sn.Countries) != 0 {
		t.Errorf("nil counter read %+v", sn)
	}
}

func TestMask(t *testing.T) {
	m := Of(Requests, Deny)
	if !m.Has(Requests) || !m.Has(Deny) || m.Has(Pass) {
		t.Errorf("mask %b", m)
	}
	if len(Names) != int(NumKinds) || Names[RateLimit] != "rate_limit" {
		t.Errorf("names %v", Names)
	}
}
