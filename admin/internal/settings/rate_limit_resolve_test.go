package settings

import "testing"

// TestRateLimitResolveUndeclared: undeclared site -> Default verbatim.
func TestRateLimitResolveUndeclared(t *testing.T) {
	cfg := RateLimitConfig{
		Default: RateLimitValues{
			Name:           "unmask_rate",
			RequestsPerMin: 100,
			Burst:          50,
			WindowSec:      60,
			ChallengeMode:  RateChallengePoWThenCaptcha,
		},
	}
	if got := cfg.Resolve("blog.example.com"); got != cfg.Default {
		t.Fatalf("undeclared: want %+v, got %+v", cfg.Default, got)
	}
}

// TestRateLimitResolveDeclared: declared site -> Sites[site] verbatim
// (= every field comes from the entry, not Default).
func TestRateLimitResolveDeclared(t *testing.T) {
	shop := RateLimitValues{
		Name:           "unmask_rate_shop",
		RequestsPerMin: 200,
		Burst:          80,
		WindowSec:      60,
		ChallengeMode:  RateChallengePoWOnly,
	}
	cfg := RateLimitConfig{
		Default: RateLimitValues{
			Name:           "unmask_rate",
			RequestsPerMin: 100,
			Burst:          50,
			WindowSec:      60,
			ChallengeMode:  RateChallengePoWThenCaptcha,
		},
		Sites: map[string]RateLimitValues{"shop.example.com": shop},
	}
	if got := cfg.Resolve("shop.example.com"); got != shop {
		t.Fatalf("declared: want %+v, got %+v", shop, got)
	}
}

// TestRateLimitResolveEmptyEntry: empty entry -> zero value (no field-level
// merge).  This is the v2 contract: an entry exists or it does not.
func TestRateLimitResolveEmptyEntry(t *testing.T) {
	cfg := RateLimitConfig{
		Default: RateLimitValues{
			Name:           "unmask_rate",
			RequestsPerMin: 100,
			Burst:          50,
		},
		Sites: map[string]RateLimitValues{"empty.example.com": {}},
	}
	got := cfg.Resolve("empty.example.com")
	if got != (RateLimitValues{}) {
		t.Fatalf("empty entry: want zero, got %+v", got)
	}
}

// TestRateLimitResolveZoneSiteFallback: when no Zone PathPatterns match, the
// per-site default record wins.
func TestRateLimitResolveZoneSiteFallback(t *testing.T) {
	cfg := RateLimitConfig{
		Default: RateLimitValues{
			Name:           "unmask_rate",
			RequestsPerMin: 100,
			Burst:          50,
		},
		Sites: map[string]RateLimitValues{
			"shop.example.com": {
				Name:           "unmask_rate_shop",
				RequestsPerMin: 200,
				Burst:          80,
			},
		},
	}
	got := cfg.ResolveZone("/somewhere/", "shop.example.com")
	if got.RequestsPerMin != 200 || got.Name != "unmask_rate_shop" {
		t.Fatalf("shop fallback: want shop default, got %+v", got)
	}
	got = cfg.ResolveZone("/somewhere/", "blog.example.com")
	if got.RequestsPerMin != 100 || got.Name != "unmask_rate" {
		t.Fatalf("blog fallback: want install default, got %+v", got)
	}
}

// TestRateLimitResolveZonePathWins: matching path zone overrides site default.
func TestRateLimitResolveZonePathWins(t *testing.T) {
	cfg := RateLimitConfig{
		Default: RateLimitValues{
			Name:           "unmask_rate",
			RequestsPerMin: 100,
		},
		Zones: []RateZone{
			{
				Name:           "unmask_rate_api",
				RequestsPerMin: 500,
				PathPatterns:   []string{"/api/"},
			},
		},
	}
	got := cfg.ResolveZone("/api/v2/health", "shop.example.com")
	if got.Name != "unmask_rate_api" || got.RequestsPerMin != 500 {
		t.Fatalf("path zone: want api zone, got %+v", got)
	}
}

// TestRateLimitValuesHelpers: ResolvedWindowSec / ResolvedChallengeMode
// fallback behavior on the v2 value record.
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
