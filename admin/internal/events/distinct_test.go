package events

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestDistinctHostsAndSites pins the loose-index-scan rewrite: the picker
// helpers must return the DISTINCT non-empty values in ascending order, with
// duplicates collapsed, exactly like the old plain-DISTINCT query.
func TestDistinctHostsAndSites(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	ins := func(site, host string) {
		if err := Insert(ctx, d, &Event{Site: site, Host: host, IPPacked: PackIP("10.0.0.1"), Phase: "serve", OccurredAt: now}); err != nil {
			t.Fatal(err)
		}
	}
	// Deliberately out of order + with duplicates so the test proves both the
	// DISTINCT collapse and the ascending order.
	ins("bbb.example", "h2")
	ins("aaa.example", "h1")
	ins("bbb.example", "h1") // duplicate site AND duplicate host
	ins("ccc.example", "h2")

	sites, err := DistinctSites(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(sites, ","); got != "aaa.example,bbb.example,ccc.example" {
		t.Errorf("DistinctSites = %q, want ascending distinct aaa,bbb,ccc", got)
	}
	hosts, err := DistinctHosts(ctx, d)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(hosts, ","); got != "h1,h2" {
		t.Errorf("DistinctHosts = %q, want ascending distinct h1,h2", got)
	}
}

// TestDistinctEmptyTable: the recursive-CTE anchor's MIN over no rows is NULL,
// which must terminate the recursion and yield an empty slice (not loop / not
// error).
func TestDistinctEmptyTable(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if hosts, err := DistinctHosts(ctx, d); err != nil || len(hosts) != 0 {
		t.Errorf("empty DistinctHosts = %v err=%v, want [] nil", hosts, err)
	}
	if sites, err := DistinctSites(ctx, d); err != nil || len(sites) != 0 {
		t.Errorf("empty DistinctSites = %v err=%v, want [] nil", sites, err)
	}
}
