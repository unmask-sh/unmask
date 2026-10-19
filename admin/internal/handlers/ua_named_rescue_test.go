package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/hll"
)

// The UA-filter tab's rows carry what the last day let through on each
// crawler's name alone, read from the reader's hourly aggregate.
func TestFillNamedRescue(t *testing.T) {
	h := newTestHandler(t)
	// The test handler's schema is hand-written (handlers_test.go); the
	// reader's hourly table comes from migration 0044, so create it here.
	if _, err := h.DB.ExecContext(context.Background(), `CREATE TABLE IF NOT EXISTS unmask_crawler_named_hourly (
		bucket_hour INTEGER NOT NULL, crawler VARCHAR(48) NOT NULL, cnt INTEGER NOT NULL DEFAULT 0, ips BLOB,
		PRIMARY KEY (bucket_hour, crawler))`); err != nil {
		t.Fatal(err)
	}
	var sk hll.Sketch
	sk.Add([]byte("203.0.113.9"))
	sk.Add([]byte("198.51.100.7"))
	hour := time.Now().Unix() / 3600
	for _, row := range []struct {
		hour int64
		cnt  int
	}{{hour, 5}, {hour - 3, 7}, {hour - 30, 1000}} { // the last is outside the day
		if _, err := h.DB.ExecContext(context.Background(),
			`INSERT INTO unmask_crawler_named_hourly (bucket_hour, crawler, cnt, ips) VALUES (?, 'PetalBot', ?, ?)`,
			row.hour, row.cnt, sk.Bytes()); err != nil {
			t.Fatal(err)
		}
	}
	v := buildUpstreamView(h.cfg().Nginx)
	h.fillNamedRescue(context.Background(), &v)
	found := false
	for _, g := range v.Groups {
		for _, r := range g.Rows {
			if r.Name != "PetalBot" {
				if r.NamedDay != 0 {
					t.Errorf("%s has a count it never earned: %d", r.Name, r.NamedDay)
				}
				continue
			}
			found = true
			if r.NamedDay != 12 {
				t.Errorf("PetalBot NamedDay = %d, want 12 (the day's rows only)", r.NamedDay)
			}
			if r.NamedIPs < 2 || r.NamedIPs > 3 {
				t.Errorf("PetalBot NamedIPs = %d, want 2", r.NamedIPs)
			}
		}
	}
	if !found {
		t.Fatal("PetalBot is not in the catalog view")
	}

	// The claim marker the daemon proxy sets.
	req := httptest.NewRequest(http.MethodGet, "/unmask/challenge/", nil)
	if namedRescueClaim(req) {
		t.Error("no header must read as no claim")
	}
	req.Header.Set("X-Unmask-Named-Rescue", "1")
	if !namedRescueClaim(req) {
		t.Error("the header must read as a claim")
	}
}
