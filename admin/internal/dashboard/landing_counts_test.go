package dashboard

import (
	"context"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The rollup has to return the same numbers the raw scan does.
//
// Moving the landing page off unmask_event is a change of SOURCE, not of
// meaning: the whole point is that an operator sees the identical figure,
// arrived at without reading a day of events.  So this builds a set of events
// whose correct answers are known by construction, runs the aggregator over
// them, and checks the rollup agrees -- including the cases where it must
// decline and let the scan answer.
func TestLandingCountsMatchTheRawDefinition(t *testing.T) {
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	now := time.Now().UTC().Format("2006-01-02 15:04:05")

	add := func(site, phase, payload string) {
		t.Helper()
		if _, err := d.Exec(`INSERT INTO unmask_event
			(site, host, ip_address, phase, flags, reload_count, payload_json, date_created)
			VALUES (?, 'h', x'01020304', ?, 0, 0, ?, ?)`, site, phase, payload, now); err != nil {
			t.Fatal(err)
		}
	}

	// Three serves, two loads, one bv_pow_only.
	add("a.example", "serve", `{}`)
	add("a.example", "serve", `{}`)
	add("b.example", "serve", `{}`)
	add("a.example", "load", `{"chmode":"pow_only"}`)                            // unruled, transparent
	add("b.example", "load", `{"force_reason":"ua_target","chmode":"pow_only"}`) // a rule named it
	add("a.example", "bv_pow_only", `{}`)
	// One abandon that counts, one that a rule caused, one on the wrong chain.
	add("a.example", "abandon", `{"chmode":"pow_only"}`)
	add("a.example", "abandon", `{"force_reason":"ja4_bot","chmode":"pow_only"}`)
	add("a.example", "abandon", `{"chmode":"captcha_only"}`)

	// AggregateHourly sets the package-level hourlyReady on success; reset it
	// on exit so a later test that means to exercise the raw-scan path is not
	// silently handed the aggregate one (the convention every other aggregate
	// test in this package follows).
	defer hourlyReady.Store(false)
	if err := AggregateHourly(ctx, d, nil); err != nil {
		t.Fatalf("aggregate: %v", err)
	}
	if !HourlyAggReady() {
		t.Fatal("the aggregator reported no completed pass; the fast path would never engage")
	}

	t.Run("per-phase counts", func(t *testing.T) {
		for _, c := range []struct {
			phases []string
			want   int
		}{
			{[]string{"serve"}, 3},
			{[]string{"load"}, 2},
			{[]string{"bv_pow_only"}, 1},
			{[]string{"load", "abandon"}, 5},
			{[]string{"nothing_like_this"}, 0},
		} {
			got, ok := PhaseCount(ctx, d, c.phases, "", nil, 24)
			if !ok {
				t.Fatalf("%v: the rollup declined when it should have answered", c.phases)
			}
			if got != c.want {
				t.Errorf("%v = %d, want %d", c.phases, got, c.want)
			}
		}
	})

	t.Run("the abandon population excludes rule-targeted and other chains", func(t *testing.T) {
		// Of three loads/abandons on the transparent chain, only the ones no
		// rule named count -- one load, one abandon.  This is the filter that
		// took a node's abandon rate from 99.2% to 4.8%; reading it from the
		// rollup must not quietly widen it again.
		if got, ok := UnruledPoWCount(ctx, d, "load", "", nil, 24); !ok || got != 1 {
			t.Errorf("load = %d (ok=%v), want 1", got, ok)
		}
		if got, ok := UnruledPoWCount(ctx, d, "abandon", "", nil, 24); !ok || got != 1 {
			t.Errorf("abandon = %d (ok=%v), want 1", got, ok)
		}
	})

	t.Run("declines what it cannot answer", func(t *testing.T) {
		// The rollup carries no site or host dimension, so a filtered view has
		// to fall through to the scan.  Answering from the install-wide total
		// would report another site's traffic as this one's.
		if _, ok := PhaseCount(ctx, d, []string{"serve"}, "a.example", nil, 24); ok {
			t.Error("a site filter must decline, not answer install-wide")
		}
		if _, ok := PhaseCount(ctx, d, []string{"serve"}, "", []string{"h"}, 24); ok {
			t.Error("a host filter must decline")
		}
		if _, ok := UnruledPoWCount(ctx, d, "load", "a.example", nil, 24); ok {
			t.Error("a site filter must decline on the abandon population too")
		}
		if _, ok := PhaseCount(ctx, d, nil, "", nil, 24); ok {
			t.Error("no phases asked for is not a zero answer")
		}
	})
}
