package settings

import (
	"reflect"
	"testing"
)

// RateLimitConfig.Resolve: per-site Default-zone overrides merge field-by-field
// over the default; sites without an override entry get the default unchanged;
// zero-value fields inherit; BurstSet distinguishes "inherit" from "explicit 0".
// Zones / Key are install-wide and never touched.  The returned value never
// carries the Overrides map -- callers must not re-resolve.
func TestRateLimitResolve(t *testing.T) {
	base := RateLimitConfig{
		Default: RateZone{
			Name:           "unmask_rate",
			RequestsPerMin: 100,
			Burst:          50,
			WindowSec:      60,
			ChallengeMode:  "pow_then_captcha",
		},
		Zones: []RateZone{
			{Name: "api", RequestsPerMin: 30, Burst: 10, WindowSec: 60, PathPatterns: []string{"/api/"}},
		},
		Key: "ip",
		Overrides: map[string]RateLimitOverride{
			"shop.example.com": {
				RequestsPerMin: 200,
				ChallengeMode:  "captcha_only",
			},
			"blog.example.com": {
				Burst:    0,
				BurstSet: true, // explicit zero override
			},
			"empty.example.com": {},
			"window.example.com": {
				WindowSec: 30,
			},
			"inheritburst.example.com": {
				Burst: 999, // BurstSet=false -> inherit (= the 999 is ignored)
			},
		},
	}

	cases := []struct {
		name             string
		site             string
		wantRPM          int
		wantBurst        int
		wantWindow       int
		wantChainMode    string
	}{
		{name: "no site -> default", site: "", wantRPM: 100, wantBurst: 50, wantWindow: 60, wantChainMode: "pow_then_captcha"},
		{name: "undeclared -> default", site: "api.example.com", wantRPM: 100, wantBurst: 50, wantWindow: 60, wantChainMode: "pow_then_captcha"},
		{name: "shop: rpm + chMode override", site: "shop.example.com", wantRPM: 200, wantBurst: 50, wantWindow: 60, wantChainMode: "captcha_only"},
		{name: "blog: explicit burst 0", site: "blog.example.com", wantRPM: 100, wantBurst: 0, wantWindow: 60, wantChainMode: "pow_then_captcha"},
		{name: "empty entry -> default", site: "empty.example.com", wantRPM: 100, wantBurst: 50, wantWindow: 60, wantChainMode: "pow_then_captcha"},
		{name: "window-only override", site: "window.example.com", wantRPM: 100, wantBurst: 50, wantWindow: 30, wantChainMode: "pow_then_captcha"},
		{name: "BurstSet=false ignores value", site: "inheritburst.example.com", wantRPM: 100, wantBurst: 50, wantWindow: 60, wantChainMode: "pow_then_captcha"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := base.Resolve(tc.site)
			if got.Default.RequestsPerMin != tc.wantRPM {
				t.Errorf("RPM = %d, want %d", got.Default.RequestsPerMin, tc.wantRPM)
			}
			if got.Default.Burst != tc.wantBurst {
				t.Errorf("Burst = %d, want %d", got.Default.Burst, tc.wantBurst)
			}
			if got.Default.WindowSec != tc.wantWindow {
				t.Errorf("WindowSec = %d, want %d", got.Default.WindowSec, tc.wantWindow)
			}
			if got.Default.ChallengeMode != tc.wantChainMode {
				t.Errorf("ChallengeMode = %q, want %q", got.Default.ChallengeMode, tc.wantChainMode)
			}
			// Zones / Key are install-wide.
			if !reflect.DeepEqual(got.Zones, base.Zones) {
				t.Errorf("Zones should be inherited verbatim")
			}
			if got.Key != base.Key {
				t.Errorf("Key should be inherited verbatim")
			}
			if got.Overrides != nil {
				t.Errorf("Overrides leaked into resolved value")
			}
		})
	}
}

// Default.Name is not exposed in the override -- a per-site override never
// renames the limit_req zone (= the nginx render still uses a single zone
// name).  Confirm Resolve carries Default.Name through unchanged.
func TestRateLimitResolveNamePreserved(t *testing.T) {
	base := RateLimitConfig{
		Default: RateZone{Name: "unmask_rate", RequestsPerMin: 100, Burst: 50},
		Overrides: map[string]RateLimitOverride{
			"shop.example.com": {RequestsPerMin: 200},
		},
	}
	if got := base.Resolve("shop.example.com").Default.Name; got != "unmask_rate" {
		t.Errorf("Default.Name = %q, want %q (zone name is install-wide)", got, "unmask_rate")
	}
}
