package ipgeo

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/relay"
)

// realMMDB returns the first readable database of the kind, or skips (present
// in development, absent in bare CI).
func realMMDB(t *testing.T, paths ...string) string {
	t.Helper()
	for _, p := range paths {
		if f, err := os.Open(p); err == nil {
			f.Close()
			return p
		}
	}
	t.Skip("no readable mmdb")
	return ""
}

func useRelay(t *testing.T, countries map[string][]string) {
	t.Helper()
	b, _ := json.Marshal(relay.Doc{SchemaVersion: 1, GeneratedAt: "2026-10-13T00:00:00Z",
		Relays: map[string]relay.Entry{"apple-private-relay": {Countries: countries}}})
	tb, err := relay.Parse(b)
	if err != nil {
		t.Fatal(err)
	}
	relay.Set(tb)
	t.Cleanup(func() { relay.Set(nil) })
}

// TestRelayCountryLines: a relay prefix is written with the relay's country
// wherever a country rule would see it -- the relay's country ruled, or the
// database's -- and more specifically than the database's network, so it
// wins in nginx's geo block.  (8.8.0.0/17 is US in the databases.)
func TestRelayCountryLines(t *testing.T) {
	path := realMMDB(t, "/var/lib/unmask/ipgeo/dbip-country.mmdb", "/usr/share/GeoIP/GeoLite2-Country.mmdb")
	useRelay(t, map[string][]string{"JP": {"8.8.8.0/27"}})
	for _, c := range []struct {
		codes      []string
		want, deny []string
	}{
		{[]string{"US"}, []string{"    8.8.8.0/27 JP;\n"}, nil},              // out of the US rule
		{[]string{"JP"}, []string{"    8.8.8.0/27 JP;\n"}, []string{" US;"}}, // into the JP rule
		{[]string{"DE"}, nil, []string{"8.8.8.0/27"}},                        // neither: no line
	} {
		got, err := GeoCIDRsForCountries(path, c.codes)
		if err != nil {
			t.Fatal(err)
		}
		for _, w := range c.want {
			if !strings.Contains(got, w) {
				t.Errorf("%v: no %q", c.codes, strings.TrimSpace(w))
			}
		}
		for _, d := range c.deny {
			if strings.Contains(got, d) {
				t.Errorf("%v: %q should not be there", c.codes, d)
			}
		}
	}

	// A relay prefix larger than the database's networks: every network
	// inside it carries the relay's country, the prefix itself too.
	useRelay(t, map[string][]string{"JP": {"8.0.0.0/8"}})
	got, err := GeoCIDRsForCountries(path, []string{"US"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "    8.0.0.0/8 JP;\n") {
		t.Error("the relay prefix has no line of its own")
	}
	for _, line := range strings.Split(got, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "8.") && strings.HasSuffix(line, " US;") {
			t.Errorf("a network inside the relay prefix kept the database's country: %s", line)
			break
		}
	}
}

// TestRelayASNLines: a network rule leaves the relay's addresses alone -- a
// relay prefix inside a ruled network gets the empty value, one that is the
// whole network takes it out of the block.  (8.8.8.0/24 is AS15169.)
func TestRelayASNLines(t *testing.T) {
	path := realMMDB(t, "/var/lib/unmask/ipgeo/dbip-asn.mmdb", "/usr/share/GeoIP/GeoLite2-ASN.mmdb")
	targets := []ASNTarget{{ASN: 15169, Value: "AS15169"}}

	useRelay(t, map[string][]string{"JP": {"8.8.8.0/27"}})
	got, err := CIDRsForASNTargets(path, targets)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got, "    8.8.8.0/27 \"\";\n") || !strings.Contains(got, "    8.8.8.0/24 \"AS15169\";\n") {
		t.Errorf("the relay /27 inside AS15169's /24 is not taken out of it")
	}
	rate, err := ASNRateCIDRs(path, targets)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(rate, "    8.8.8.0/27 \"\";\n") {
		t.Error("the rate zone still counts the relay /27")
	}

	useRelay(t, map[string][]string{"JP": {"8.8.8.0/24"}})
	got, err = CIDRsForASNTargets(path, targets)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(got, "8.8.8.0/24") {
		t.Error("a database network that is all relay is still in the block")
	}
}

// TestLookupInfoRelay: the lookups that place a visitor take the relay's
// country, keep the database's in CountryDB and drop its city; switched off,
// the database answers alone.
func TestLookupInfoRelay(t *testing.T) {
	path := realMMDB(t, "/var/lib/unmask/ipgeo/dbip-country.mmdb", "/usr/share/GeoIP/GeoLite2-Country.mmdb", "/usr/share/GeoIP/GeoLite2-City.mmdb")
	r := Open(path, "")
	defer r.Close()
	useRelay(t, map[string][]string{"JP": {"8.8.8.0/27"}})
	got := r.LookupInfo("8.8.8.8")
	if got.Country != "JP" || got.CountryDB != "US" || got.Relay != "apple-private-relay" || got.City != "" || got.HasCoords {
		t.Errorf("8.8.8.8 = %+v, want JP from the relay, US kept as CountryDB, no city", got)
	}
	if r.Lookup("8.8.8.8") != "JP" {
		t.Error("Lookup (the per-country charts) does not take the relay's country")
	}
	if other := r.LookupInfo("8.8.4.4"); other.Country != "US" || other.Relay != "" {
		t.Errorf("an address the relay does not list changed: %+v", other)
	}
	relay.SetOff(func() bool { return true })
	defer relay.SetOff(nil)
	if off := r.LookupInfo("8.8.8.8"); off.Country != "US" || off.Relay != "" {
		t.Errorf("switched off, the relay still answers: %+v", off)
	}
}
