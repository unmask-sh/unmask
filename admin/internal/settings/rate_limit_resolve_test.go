package settings

import (
	"reflect"
	"testing"
)

// TestRateLimitResolveZonesEmpty: empty config -> empty slice.
func TestRateLimitResolveZonesEmpty(t *testing.T) {
	var c RateLimitConfig
	if got := c.ResolveZones("shop.example.com"); len(got) != 0 {
		t.Fatalf("empty: want [], got %+v", got)
	}
}

// TestRateLimitResolveZonesAllSites: empty Site applies to every host.
func TestRateLimitResolveZonesAllSites(t *testing.T) {
	z := RateZone{Name: "api", RequestsPerMin: 100, PathPatterns: []string{"/api/"}}
	c := RateLimitConfig{Zones: []RateZone{z}}
	for _, site := range []string{"", "shop.example.com", "blog.example.com"} {
		got := c.ResolveZones(site)
		if !reflect.DeepEqual(got, []RateZone{z}) {
			t.Fatalf("site=%q: want [z], got %+v", site, got)
		}
	}
}

// TestRateLimitResolveZonesSiteSpecific: non-empty Site filters exact match.
func TestRateLimitResolveZonesSiteSpecific(t *testing.T) {
	shop := RateZone{Name: "shop_api", RequestsPerMin: 200, Site: "shop.example.com"}
	c := RateLimitConfig{Zones: []RateZone{shop}}
	if got := c.ResolveZones("shop.example.com"); !reflect.DeepEqual(got, []RateZone{shop}) {
		t.Fatalf("shop: want [shop], got %+v", got)
	}
	if got := c.ResolveZones("blog.example.com"); len(got) != 0 {
		t.Fatalf("blog: want [], got %+v", got)
	}
}

// TestRateLimitResolveZoneMatch: ResolveZone(path, site) returns the first
// matching zone (= PathPatterns + Site both match), else Default.
func TestRateLimitResolveZoneMatch(t *testing.T) {
	c := RateLimitConfig{
		Default: RateLimitValues{RequestsPerMin: 100, Burst: 50},
		Zones: []RateZone{
			{Name: "shop_api", RequestsPerMin: 200, PathPatterns: []string{"/api/"}, Site: "shop.example.com"},
			{Name: "blog_strict", RequestsPerMin: 30, PathPatterns: []string{"/api/"}, Site: "blog.example.com"},
			{Name: "api", RequestsPerMin: 50, PathPatterns: []string{"/api/"}},
		},
	}
	if got := c.ResolveZone("/api/v1", "shop.example.com"); got.RequestsPerMin != 200 {
		t.Fatalf("shop /api/: want 200, got %d", got.RequestsPerMin)
	}
	if got := c.ResolveZone("/api/v1", "blog.example.com"); got.RequestsPerMin != 30 {
		t.Fatalf("blog /api/: want 30, got %d", got.RequestsPerMin)
	}
	if got := c.ResolveZone("/api/v1", "other.example.com"); got.RequestsPerMin != 50 {
		t.Fatalf("other /api/: want 50 (default zone), got %d", got.RequestsPerMin)
	}
	if got := c.ResolveZone("/", "shop.example.com"); got.RequestsPerMin != 100 {
		t.Fatalf("shop /: want 100 (install default), got %d", got.RequestsPerMin)
	}
}

// TestRateLimitValuesHelpers: ResolvedWindowSec / ResolvedChallengeMode
// fallback behaviour on the value record.
func TestRateLimitValuesHelpers(t *testing.T) {
	v := RateLimitValues{}
	if got := v.ResolvedWindowSec(); got != 60 {
		t.Fatalf("WindowSec=0: want 60, got %d", got)
	}
	if got := v.ResolvedChallengeMode(); got != RateChallengePoWThenCaptcha {
		t.Fatalf("ChallengeMode empty: want pow_then_captcha, got %q", got)
	}
	v = RateLimitValues{WindowSec: 30, ChallengeMode: RateChallengePoWOnly}
	if got := v.ResolvedWindowSec(); got != 30 {
		t.Fatalf("WindowSec=30: want 30, got %d", got)
	}
	if got := v.ResolvedChallengeMode(); got != RateChallengePoWOnly {
		t.Fatalf("ChallengeMode=pow_only: want pow_only, got %q", got)
	}
}
