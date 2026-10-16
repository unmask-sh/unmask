package events

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// CountHourly counts the window whole, under the filters FetchPaged pages
// by, and buckets it by the hour in the caller's zone.
func TestCountHourly(t *testing.T) {
	tmp, _ := os.MkdirTemp("", "cnt-*")
	defer os.RemoveAll(tmp)
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: filepath.Join(tmp, "t.db")})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	// Rows sit in the two hours before the top of the current one, so they
	// fall in two buckets however late in the hour the test runs, and inside
	// a three-hour window however early.
	h0 := time.Now().UTC().Truncate(time.Hour)
	ins := func(ip []byte, ja4, phase string, at time.Time) {
		t.Helper()
		if _, err := d.Exec(`INSERT INTO unmask_event
			(site,host,scheme,port,ip_address,user_agent,ja4,ja4_verdict,ja4_verdict_id,phase,flags,reload_count,cookie_bv,cookie_br,payload_json,date_created)
			VALUES ('','','',0,?,'UA',?,'',0,?,0,0,'','','{"force_reason":"rate_limit"}',?)`,
			ip, ja4, phase, at.Format("2006-01-02 15:04:05.000")); err != nil {
			t.Fatal(err)
		}
	}
	a := []byte{10, 0, 0, 1}
	b := []byte{10, 0, 0, 2}
	ins(a, "t13d_x", "serve", h0.Add(-90*time.Minute))
	ins(a, "t13d_x", "load", h0.Add(-89*time.Minute))
	ins(b, "t13d_y", "serve", h0.Add(-85*time.Minute))
	ins(a, "t13d_x", "bv_pow_only", h0.Add(-30*time.Minute))
	ins(b, "t13d_y", "serve", h0.Add(-20*time.Minute))
	ins(a, "t13d_x", "serve", h0.Add(-10*time.Hour)) // outside the window

	ctx := context.Background()
	loc := time.FixedZone("JST", 9*3600)
	c, err := CountHourly(ctx, d, "", "", "", "", "", "", nil, 180, loc)
	if err != nil {
		t.Fatal(err)
	}
	if c.Total != 5 || c.Phases["serve"] != 3 || c.Phases["load"] != 1 || c.Phases["bv_pow_only"] != 1 || c.DistinctIPs != 2 {
		t.Errorf("window: %+v", c)
	}
	if len(c.Hours) != 2 {
		t.Fatalf("hours: %+v", c.Hours)
	}
	first, second := c.Hours[0], c.Hours[1]
	if first.Phases["serve"] != 2 || first.Phases["load"] != 1 || first.DistinctIPs != 2 {
		t.Errorf("earlier hour: %+v", first)
	}
	if second.Phases["bv_pow_only"] != 1 || second.Phases["serve"] != 1 || second.DistinctIPs != 2 {
		t.Errorf("later hour: %+v", second)
	}
	// Labels are the bucket's start in the caller's zone, oldest first.
	if want := h0.Add(-2 * time.Hour).In(loc).Format(time.RFC3339); first.Hour != want {
		t.Errorf("earlier hour labelled %q, want %q", first.Hour, want)
	}
	if want := h0.Add(-time.Hour).In(loc).Format(time.RFC3339); second.Hour != want {
		t.Errorf("later hour labelled %q, want %q", second.Hour, want)
	}

	// The filters are FetchPaged's: a fingerprint, a phase, a reason.
	c2, err := CountHourly(ctx, d, "", "t13d_x", "", "", "", "", nil, 180, loc)
	if err != nil {
		t.Fatal(err)
	}
	if c2.Total != 3 || c2.DistinctIPs != 1 {
		t.Errorf("ja4 filter: %+v", c2)
	}
	rows, err := FetchPaged(ctx, d, "", "t13d_x", "", "", "", "", "", nil, 180, 100, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != c2.Total {
		t.Errorf("the count (%d) and the page (%d) must agree on the window", c2.Total, len(rows))
	}
	c3, err := CountHourly(ctx, d, "", "", "", "serve", "rate_limit", "", nil, 180, loc)
	if err != nil {
		t.Fatal(err)
	}
	if c3.Total != 3 || c3.Phases["serve"] != 3 || len(c3.Phases) != 1 {
		t.Errorf("phase and reason filter: %+v", c3)
	}
}
