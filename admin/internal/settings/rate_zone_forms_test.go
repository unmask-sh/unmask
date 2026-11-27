package settings

import "testing"

// TestResolveZonesAllHoldsAZoneAgainstEveryForm: a zone applies when one of
// its patterns matches the request's URI in any of the forms handed over,
// and a zone without patterns applies as it always did.
func TestResolveZonesAllHoldsAZoneAgainstEveryForm(t *testing.T) {
	rl := RateLimitConfig{Zones: []RateZone{
		{Name: "login", PathPatterns: []string{`^/wp-login\.php`}, RequestsPerMin: 5},
		{Name: "everywhere", RequestsPerMin: 50},
	}}
	names := func(path string, also ...string) (out []string) {
		for _, z := range rl.ResolveZonesAll(path, "", also...) {
			out = append(out, z.Name)
		}
		return out
	}
	has := func(list []string, name string) bool {
		for _, n := range list {
			if n == name {
				return true
			}
		}
		return false
	}
	if got := names("/wp-login%2Ephp"); has(got, "login") {
		t.Errorf("the URI as sent alone is on the zone's paths: %v", got)
	}
	if got := names("/wp-login%2Ephp", "/wp-login.php"); !has(got, "login") {
		t.Errorf("the routed form did not put the request on the zone's paths: %v", got)
	}
	if got := names("/blog/", "", "/blog/"); has(got, "login") {
		t.Errorf("/blog/ is on the zone's paths: %v", got)
	}
	// The zone without patterns: once, whatever the forms.
	for _, got := range [][]string{names("/blog/"), names("/blog/", "/blog/", "")} {
		n := 0
		for _, name := range got {
			if name == "everywhere" {
				n++
			}
		}
		if n != 1 {
			t.Errorf("the all-paths zone applies %d times: %v", n, got)
		}
	}
}
