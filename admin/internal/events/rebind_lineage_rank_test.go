package events

import (
	"context"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// One solve carried across many addresses is the shape this ranking exists to
// surface, and it is invisible in every other view: each request is a genuine
// pass on a valid credential, so only the aggregate -- how many distinct
// addresses ONE lineage reached -- separates a crawler fleet from a commuter.
func TestRankByRebindLineage(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	add := func(phase Phase, lineage, ip string) {
		t.Helper()
		pkt := PackIP(ip)
		if pkt == nil {
			t.Fatalf("unpackable ip %q", ip)
		}
		if err := Insert(context.Background(), d, &Event{
			Site: "default", IPPacked: pkt, Phase: string(phase),
			Payload: map[string]any{"lineage": lineage},
		}); err != nil {
			t.Fatal(err)
		}
	}

	// A crawler: one solve, re-bound onto four addresses, and the cap starting
	// to refuse it.
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"} {
		add(PhaseBVRebind, "fleet-lineage", ip)
	}
	add(PhaseBVRebindReject, "fleet-lineage", "203.0.113.5")
	add(PhaseBVRebindReject, "fleet-lineage", "203.0.113.6")

	// A commuter: more re-binds, but only between two networks.  Higher
	// volume, lower interest -- the ordering must not put it on top.
	for i := 0; i < 6; i++ {
		ip := "198.51.100.1"
		if i%2 == 1 {
			ip = "198.51.100.2"
		}
		add(PhaseBVRebind, "phone-lineage", ip)
	}

	// A lineage that never actually re-bound anywhere: refusals only.
	add(PhaseBVRebindReject, "refused-lineage", "192.0.2.9")

	rows, err := RankByRebindLineage(ctx, d, 0, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 lineages (the refusal-only one is not travel), got %d: %+v", len(rows), rows)
	}
	if rows[0].Lineage != "fleet-lineage" {
		t.Errorf("ranking must lead with the widest spread, not the busiest: got %q", rows[0].Lineage)
	}
	if rows[0].IPs != 4 || rows[0].Rebinds != 4 || rows[0].Rejects != 2 {
		t.Errorf("fleet row = %+v, want IPs=4 Rebinds=4 Rejects=2", rows[0])
	}
	if rows[1].IPs != 2 || rows[1].Rebinds != 6 {
		t.Errorf("commuter row = %+v, want IPs=2 Rebinds=6", rows[1])
	}
	if rows[0].LastSeen == "" {
		t.Error("last-seen must be populated; an operator needs to know if this is live or history")
	}
}

// The cap counters live outside the event log so they survive retention
// pruning, and a missing reading must degrade to "unknown" rather than
// blanking the ranking beside it.
func TestRebindLineageCaps(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec("INSERT INTO unmask_rebind_lineage (lineage, host, `count`, window_start, window_count, updated_at) VALUES ('a','h',9,100,3,100)"); err != nil {
		t.Fatal(err)
	}
	caps := RebindLineageCaps(context.Background(), d, []string{"a", "absent"})
	if got := caps["a"]; got != [2]int{9, 3} {
		t.Errorf("caps[a] = %v, want [9 3]", got)
	}
	if _, ok := caps["absent"]; ok {
		t.Error("a lineage with no cap row must be absent from the map, not zero-valued")
	}
	if len(RebindLineageCaps(context.Background(), d, nil)) != 0 {
		t.Error("no lineages asked for -> no query, empty map")
	}
}
