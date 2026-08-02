package events

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func asnTestDB(t *testing.T) *db.DB {
	t.Helper()
	d, err := db.Open(settings.DB{Driver: "sqlite", SQLitePath: t.TempDir() + "/s.sqlite"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	if err := db.Migrate(d); err != nil {
		t.Fatal(err)
	}
	return d
}

// The shape this ranking exists for: one network contributes many addresses
// that each make a couple of requests, while a single noisy IP makes far more
// requests on its own.  Ordering by requests would bury the network; ordering
// by distinct IPs surfaces it, which is the whole point.
func TestRankByASNOrdersByDistinctIPs(t *testing.T) {
	d := asnTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()

	// 50 addresses in AS100, 2 requests each = 100 requests.
	for i := 0; i < 50; i++ {
		for j := 0; j < 2; j++ {
			if err := Insert(ctx, d, &Event{
				IPPacked: PackIP(fmt.Sprintf("10.0.%d.%d", i/250, i%250)), Phase: "serve", OccurredAt: now,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	// One address in AS200 making 500 requests -- louder, but it is one host.
	for j := 0; j < 500; j++ {
		if err := Insert(ctx, d, &Event{
			IPPacked: PackIP("203.0.113.9"), Phase: "serve", OccurredAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	resolve := func(ip string) (uint, string) {
		if strings.HasPrefix(ip, "10.0.") {
			return 100, "Rented Hosting Inc"
		}
		return 200, "Loud Single Host"
	}
	got, err := RankByASN(ctx, d, 60, 10, resolve)
	if err != nil {
		t.Fatalf("RankByASN: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 networks, got %d: %+v", len(got), got)
	}
	if got[0].ASN != 100 {
		t.Fatalf("the 50-address network must rank first, got AS%d (%d IPs) ahead of AS%d",
			got[0].ASN, got[0].IPs, got[1].ASN)
	}
	if got[0].IPs != 50 || got[0].Count != 100 {
		t.Errorf("AS100: want 50 IPs / 100 req, got %d / %d", got[0].IPs, got[0].Count)
	}
	if got[0].Org != "Rented Hosting Inc" {
		t.Errorf("org not carried through: %q", got[0].Org)
	}
	if got[1].IPs != 1 || got[1].Count != 500 {
		t.Errorf("AS200: want 1 IP / 500 req, got %d / %d", got[1].IPs, got[1].Count)
	}
}

// A missing / silent mmdb must not make traffic disappear from the ranking:
// the rows fold into one "unknown" bucket (ASN 0) so the totals still add up
// and the operator can see that the lookup, not the traffic, is absent.
func TestRankByASNFoldsUnresolvedIntoUnknown(t *testing.T) {
	d := asnTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 3; i++ {
		if err := Insert(ctx, d, &Event{
			IPPacked: PackIP(fmt.Sprintf("198.51.100.%d", i)), Phase: "serve", OccurredAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}

	for _, tc := range []struct {
		name    string
		resolve func(string) (uint, string)
	}{
		{"nil resolver", nil},
		{"resolver answers 0", func(string) (uint, string) { return 0, "" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RankByASN(ctx, d, 60, 10, tc.resolve)
			if err != nil {
				t.Fatalf("RankByASN: %v", err)
			}
			if len(got) != 1 || got[0].ASN != 0 {
				t.Fatalf("want a single unknown bucket, got %+v", got)
			}
			if got[0].IPs != 3 || got[0].Count != 3 {
				t.Errorf("unknown bucket must keep the totals: got %d IPs / %d req", got[0].IPs, got[0].Count)
			}
		})
	}
}

// Same scale guard as TestRankByIPPinsDateIndex, and it matters more here: the
// ranking key is computed after the query, so no LIMIT can be pushed down and
// every distinct IP in the window is read.  Unpinned, SQLite walks the whole
// (ip_address, date_created) index instead of seeking the window -- measured on
// a 6.6M-row production DB over 24h: 0.36s pinned vs 48s unpinned.
func TestRankByASNPinsDateIndex(t *testing.T) {
	d := asnTestDB(t)
	ctx := context.Background()
	if err := Insert(ctx, d, &Event{IPPacked: PackIP("10.0.0.1"), Phase: "serve", OccurredAt: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	win := dateCreatedWindow(ctx, d, 60)
	plan := planOf(t, d, `SELECT ip_address, COUNT(*) AS c FROM unmask_event`+eventDateHint(d, win)+
		` WHERE `+win+` GROUP BY ip_address`)
	if !strings.Contains(plan, "idx_unmask_event_date") {
		t.Fatalf("query must be pinned to the date index, plan was:\n%s", plan)
	}
}

func TestRankByASNLimits(t *testing.T) {
	d := asnTestDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	for i := 0; i < 12; i++ {
		if err := Insert(ctx, d, &Event{
			IPPacked: PackIP(fmt.Sprintf("192.0.2.%d", i)), Phase: "serve", OccurredAt: now,
		}); err != nil {
			t.Fatal(err)
		}
	}
	// One AS per address, so the limit is what decides the row count.
	resolve := func(ip string) (uint, string) {
		var last uint
		fmt.Sscanf(ip, "192.0.2.%d", &last)
		return 1000 + last, "net"
	}
	got, err := RankByASN(ctx, d, 60, 5, resolve)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Fatalf("want the limit honored (5), got %d", len(got))
	}
}
