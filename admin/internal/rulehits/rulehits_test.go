package rulehits

import (
	"testing"
	"time"
)

func TestRing(t *testing.T) {
	c := New()
	now := time.Unix(1_700_000_000, 0)
	c.Hit("cr1", now)
	c.Hit("cr1", now.Add(-2*time.Hour))
	c.Hit("cr2", now.Add(-23*time.Hour))
	c.Hit("cr2", now.Add(-25*time.Hour)) // outside the day
	st, since := c.Snapshot(now)
	if st["cr1"].Day != 2 || st["cr1"].Last != now.Unix() {
		t.Errorf("cr1: %+v", st["cr1"])
	}
	if st["cr2"].Day != 1 {
		t.Errorf("cr2: %+v", st["cr2"])
	}
	if since == 0 {
		t.Error("no start time")
	}
	var nilC *Counter
	nilC.Hit("x", now)
	if m, _ := nilC.Snapshot(now); len(m) != 0 {
		t.Error("a nil counter must read as empty")
	}
}
