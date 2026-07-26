package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// countryMMDB returns a country mmdb the walk can actually READ, or skips: the
// geo rate zones only render when the CIDR walk resolves (keyed on
// $unmask_country), so the populated case needs a real, readable DB -- present
// in dev, skipped in bare CI.  (A path can exist but be permission-denied --
// dev2's /var/lib/unmask copy is root-owned -- so probe with an actual walk.)
func countryMMDB(t *testing.T) string {
	t.Helper()
	for _, p := range []string{
		"/var/lib/unmask/ipgeo/dbip-country.mmdb",
		"/usr/share/GeoIP/GeoLite2-Country.mmdb",
		"/home/apps/uic/data/runtime/geo/GeoLite2-Country.mmdb",
	} {
		if body, err := ipgeo.GeoCIDRsForCountries(p, []string{"BR"}); err == nil && strings.Contains(body, " BR;") {
			return p
		}
	}
	t.Skip("no readable country mmdb available")
	return ""
}

// TestBuildRenderDataGeoRateGuard: a RatePerMin>0 country with no country mmdb
// yields no rate zone (the CIDR walk is skipped, so $unmask_country would never
// resolve) -- degrade safely rather than emit a dead zone.
func TestBuildRenderDataGeoRateGuard(t *testing.T) {
	rate := 60
	s := settings.Settings{}
	s.Nginx.Geo = settings.GeoConfig{
		Rules: []settings.GeoRule{{Country: "BR", Action: settings.GeoActionDeny, RatePerMin: &rate, Enabled: true}},
	}
	d, err := buildRenderData(s, t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if len(d.GeoRateZones) != 0 {
		t.Errorf("no mmdb -> want 0 geo rate zones, got %d", len(d.GeoRateZones))
	}
}

// TestBuildRenderDataGeoRate pins the split with a real country mmdb: a
// rate-mode country leaves the immediate-action map but stays in the CIDR walk
// (so $unmask_country resolves it) and materializes as a georate_<i> zone
// keyed on $unmask_country with the crawler/bypass exemption.
func TestBuildRenderDataGeoRate(t *testing.T) {
	mmdb := countryMMDB(t)
	rate := 60
	s := settings.Settings{}
	s.IPGeo.MMDBPath = mmdb
	s.Nginx.Geo = settings.GeoConfig{
		Rules: []settings.GeoRule{
			{Country: "CN", Action: settings.GeoActionDeny, Enabled: true},                    // immediate
			{Country: "BR", Action: settings.GeoActionDeny, RatePerMin: &rate, Enabled: true}, // rate zone
		},
	}
	d, err := buildRenderData(s, t.TempDir(), "test")
	if err != nil {
		t.Fatal(err)
	}
	var haveCN, haveBR bool
	for _, g := range d.GeoRules {
		switch g.Country {
		case "CN":
			haveCN = true
		case "BR":
			haveBR = true
		}
	}
	if !haveCN || haveBR {
		t.Errorf("GeoRules = %+v, want CN present and BR absent (BR is rate-mode)", d.GeoRules)
	}
	if !strings.Contains(d.GeoCIDRs, " BR;") || !strings.Contains(d.GeoCIDRs, " CN;") {
		t.Error("both countries must be in the $unmask_country CIDR walk")
	}
	if len(d.GeoRateZones) != 1 {
		t.Fatalf("GeoRateZones = %+v, want exactly the BR zone", d.GeoRateZones)
	}
	if z := d.GeoRateZones[0]; z.Country != "BR" || z.RequestsPerMin != 60 || z.Burst != 60 || z.ZoneName != "georate_0" {
		t.Errorf("zone = %+v, want BR@60 georate_0", z)
	}

	// The emitted http.inc / protect.inc carry the zone: key map exact-matches
	// the country off the shared $unmask_country, with the crawler/bypass drop.
	httpInc := renderHTTPInc(t, func(s *settings.Settings) {
		s.IPGeo.MMDBPath = mmdb
		s.Nginx.Geo = settings.GeoConfig{Rules: []settings.GeoRule{
			{Country: "BR", Action: settings.GeoActionDeny, RatePerMin: &rate, Enabled: true},
		}}
	})
	for _, want := range []string{
		`map "$is_search_bot:$is_bypass_ip:$unmask_country" $georate_0_key`,
		`"0:0:BR" "BR";`,
		`limit_req_zone $georate_0_key zone=georate_0:10m rate=60r/m;`,
	} {
		if !strings.Contains(httpInc, want) {
			t.Errorf("http.inc missing %q", want)
		}
	}
}
