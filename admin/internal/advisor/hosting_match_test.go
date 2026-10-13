package advisor

import (
	"context"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/relay"
)

// TestHostingMatchSparesPrivateRelay: the hosting-network signals read the
// same catalog as the ASN tab, so the Akamai networks Apple's iCloud Private
// Relay leaves from are not a hosting network to the advisor either -- while
// Linode, named after Akamai in DB-IP, still is.
func TestHostingMatchSparesPrivateRelay(t *testing.T) {
	if hp := hostingMatch(36183, "Akamai Technologies, Inc."); hp != "" {
		t.Errorf("AS36183 (the relay) is a hosting network to the advisor: %q", hp)
	}
	if hp := hostingMatch(20940, "Akamai International B.V."); hp != "" {
		t.Errorf("AS20940 (the relay) is a hosting network to the advisor: %q", hp)
	}
	if hp := hostingMatch(63949, "Akamai Technologies, Inc."); hp == "" {
		t.Error("AS63949 (Linode) is no longer a hosting network to the advisor")
	}
	if hp := hostingMatch(0, ""); hp != "" {
		t.Errorf("an unknown network matched %q", hp)
	}
}

// TestNominatedRelayDropped: the model may name a relay's shared address from
// the ranking (the pool row says relay), but it never becomes a candidate --
// a ban would shut out everyone leaving from it.
func TestNominatedRelayDropped(t *testing.T) {
	pool := Pool{IPs: []PoolIP{
		{IP: "172.224.226.5", Requests: 900, Serves: 600, Relay: "iCloud Private Relay"},
		{IP: "198.51.100.30", Requests: 900, Serves: 600},
	}}
	res := Result{Nominations: []Nomination{
		{Target: "172.224.226.5", Type: "ip", Priority: "high", Reasoning: "volume"},
		{Target: "198.51.100.30", Type: "ip", Priority: "high", Reasoning: "volume"},
	}}
	rows, reviews := NominatedRows(res, pool)
	if len(rows) != 1 || rows[0].Target != "198.51.100.30" {
		t.Fatalf("rows = %+v, want only the address that is not a relay's", rows)
	}
	if _, ok := reviews["172.224.226.5"]; ok {
		t.Error("the relay address kept a review")
	}
}

// TestRelayAddressNotACandidate: an address the relay list names never
// becomes an engine candidate, however it hammers -- as a private address
// never does.  The same traffic from an address outside the list does.
func TestRelayAddressNotACandidate(t *testing.T) {
	t.Setenv("UNMASK_TEST_GEO_OVERRIDE", "172.224.226.5:BN,203.0.113.10:BN")
	gip := ipgeo.Open("", "")
	defer gip.Close()
	tb, err := relay.Parse([]byte(`{"schemaVersion":1,"generatedAt":"2026-10-13T00:00:00Z","relays":{"apple-private-relay":{"countries":{"JP":["172.224.226.0/27"]}}}}`))
	if err != nil {
		t.Fatal(err)
	}
	relay.Set(tb)
	defer relay.Set(nil)

	d := newTestDB(t)
	for _, ip := range []string{"172.224.226.5", "203.0.113.10"} {
		for i := 0; i < 6; i++ {
			insertEvent(t, d, ip, "t13d_bot", "serve", "curl/8", "")
		}
	}
	cands, err := Candidates(context.Background(), d, gip, Exclusions{}, Options{MinServes: 5, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, c := range cands {
		if c.Type == "ip" {
			got = append(got, c.Target)
		}
	}
	if len(got) != 1 || got[0] != "203.0.113.10" {
		t.Errorf("ip candidates = %v, want only 203.0.113.10", got)
	}
}
