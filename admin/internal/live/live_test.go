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
	c.ObserveEvent(now, "bv_pow_only", "JP", nil)
	c.ObserveEvent(now, "bv_captcha_only", "", nil)
	c.ObserveEvent(now, "bv_pow_then_captcha", "", nil)
	c.ObserveEvent(now, "serve", "US", map[string]any{"rl": 1})
	c.ObserveEvent(now, "serve", "US", nil) // an ordinary serve: the access log counts it
	c.ObserveEvent(now, "load", "", nil)
	sn := c.Snapshot(now)
	if sn.Last[Solve] != 3 || sn.Last[RateLimit] != 1 || sn.Last[Requests] != 0 || sn.Last[Serve] != 0 {
		t.Errorf("last = %v, want 3 solves, 1 rate-limit, nothing else", sn.Last)
	}
	if sn.LastLine != 0 {
		t.Error("events must not count as the access-log feed being alive")
	}
}

// Only an ordinary visitor's abandoned proof-of-work counts as walking away:
// the dashboard's narrowing, so a CAPTCHA a targeted client never solves stays
// counted as stopped.
func TestObserveEventAbandon(t *testing.T) {
	c := New()
	now := time.Unix(1_800_000_000, 0)
	c.ObserveEvent(now, "abandon", "JP", map[string]any{"chmode": "pow_only"})
	c.ObserveEvent(now, "abandon", "JP", map[string]any{"chmode": "pow_only", "force_reason": "none"})
	c.ObserveEvent(now, "abandon", "JP", map[string]any{"chmode": "captcha_only"})
	c.ObserveEvent(now, "abandon", "JP", map[string]any{"chmode": "pow_only", "force_reason": "asn"})
	if got := c.Snapshot(now).Last[Abandon]; got != 2 {
		t.Errorf("abandons = %d, want 2 (the unruled proof-of-work only)", got)
	}
}

// A country's challenged and denied requests split into what nobody cleared
// (blocked) and what a person cleared or walked away from (people).
func TestCountryBlockedAndPeople(t *testing.T) {
	c := New()
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < 10; i++ {
		c.Hit(now, "CN", Of(Requests, Serve))
	}
	c.Hit(now, "CN", Of(Requests, Deny))
	c.Hit(now, "CN", Of(Requests, Pass))
	for i := 0; i < 3; i++ {
		c.ObserveEvent(now, "bv_pow_only", "CN", nil)
	}
	c.ObserveEvent(now, "abandon", "CN", map[string]any{"chmode": "pow_only"})
	sn := c.Snapshot(now)
	for name, x := range map[string]Country{"last minute": sn.Countries["CN"], "thirty minutes": sn.Countries30["CN"]} {
		if x.Blocked != 7 || x.People != 4 || x.Pass != 1 || x.N != 12 {
			t.Errorf("%s: %+v, want 11 met a challenge or a deny, 4 of them people, 7 blocked", name, x)
		}
	}
	// More solves than challenges (two logs read at different moments): the
	// people never outnumber what met a challenge, and blocked never goes
	// below zero.
	c2 := New()
	c2.Hit(now, "US", Of(Requests, Serve))
	c2.ObserveEvent(now, "bv_pow_only", "US", nil)
	c2.ObserveEvent(now, "bv_pow_only", "US", nil)
	if x := c2.Snapshot(now).Countries["US"]; x.Blocked != 0 || x.People != 1 {
		t.Errorf("US = %+v, want blocked 0, people 1", x)
	}
}

// Deny pages, by reason and by the rule that matched, over the thirty
// minutes; a minute that has left the window takes its refusals with it.
func TestRefusals(t *testing.T) {
	c := New()
	now := time.Unix(1_800_000_000, 0)
	for i := 0; i < 3; i++ {
		c.ObserveEvent(now, "serve", "US", map[string]any{"deny": 1, "force_reason": "asn_deny", "deny_rule": "16509"})
	}
	c.ObserveEvent(now, "serve", "US", map[string]any{"deny": 1, "force_reason": "asn_deny", "deny_rule": "14061"})
	c.ObserveEvent(now, "serve", "", map[string]any{"deny": 1, "force_reason": "banned", "ban": 1})
	c.ObserveEvent(now, "serve", "", map[string]any{"deny": float64(1)})    // no reason recorded
	c.ObserveEvent(now, "serve", "", map[string]any{"force_reason": "asn"}) // a challenge, not a deny
	c.ObserveEvent(now.Add(-31*time.Minute), "serve", "", map[string]any{"deny": 1, "force_reason": "geo_deny", "deny_rule": "CN"})
	sn := c.Snapshot(now)
	want := map[string]uint32{"asn_deny": 4, "banned": 1, "axis_deny": 1}
	if len(sn.Refused30) != len(want) {
		t.Errorf("refused = %v, want %v", sn.Refused30, want)
	}
	for k, n := range want {
		if sn.Refused30[k] != n {
			t.Errorf("refused[%s] = %d, want %d", k, sn.Refused30[k], n)
		}
	}
	if r := sn.Rules30["asn_deny"]; r["16509"] != 3 || r["14061"] != 1 || len(sn.Rules30) != 1 {
		t.Errorf("rules = %v, want the two AS numbers under asn_deny only", sn.Rules30)
	}
}

func TestNilCounterIsInert(t *testing.T) {
	var c *Counter
	c.Hit(time.Now(), "JP", Of(Requests))
	c.ObserveEvent(time.Now(), "serve", "", map[string]any{"rl": 1})
	c.Refuse(time.Now(), "banned", "")
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
	if len(Names) != int(NumKinds) || Names[RateLimit] != "rate_limit" || Names[Abandon] != "abandon" {
		t.Errorf("names %v", Names)
	}
}

// The minute ring: thirty one-minute buckets, the reading's own minute
// last, with the countries of those minutes; a hit older than the window
// is gone.
func TestMinuteRing(t *testing.T) {
	c := New()
	now := time.Unix(1_700_000_000, 0).Add(45 * time.Second) // 45 s into a minute
	c.Hit(now, "JP", Of(Requests, Pass))
	c.Hit(now.Add(-2*time.Minute), "JP", Of(Requests, Serve))
	c.Hit(now.Add(-29*time.Minute), "US", Of(Requests, Deny))
	c.Hit(now.Add(-31*time.Minute), "DE", Of(Requests))
	sn := c.Snapshot(now)
	if sn.PerMinute[Requests][Minutes-1] != 1 || sn.PerMinute[Requests][Minutes-3] != 1 || sn.PerMinute[Requests][0] != 1 {
		t.Errorf("per-minute requests: %v", sn.PerMinute[Requests])
	}
	if sn.Last30[Requests] != 3 || sn.Last30[Pass] != 1 || sn.Last30[Serve] != 1 || sn.Last30[Deny] != 1 {
		t.Errorf("last30: %v", sn.Last30)
	}
	if sn.Countries30["JP"].N != 2 || sn.Countries30["JP"].Serve != 1 || sn.Countries30["US"].Deny != 1 {
		t.Errorf("countries30: %v", sn.Countries30)
	}
	if _, ok := sn.Countries30["DE"]; ok {
		t.Error("a hit 31 minutes old is outside the window")
	}
	// The second ring's last minute is unchanged by the longer one.
	if sn.Last[Requests] != 1 || sn.Countries["JP"].N != 1 {
		t.Errorf("last minute: %v %v", sn.Last, sn.Countries)
	}
}
