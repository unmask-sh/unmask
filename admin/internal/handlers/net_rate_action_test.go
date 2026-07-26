package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/ipgeo"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestNetRateOverageAction pins the native rate-overage per-rule action
// resolution (#3): given only a client IP, it re-derives the ASN/country and
// returns the matched rate-mode rule's action -- ASN wins over geo when both
// match, and a non-matching client gets "".  The override env seeds the IP's
// country + ASN so no real mmdb is needed.
func TestNetRateOverageAction(t *testing.T) {
	// 203.0.113.10 -> country BR, ASN 16509; 198.51.100.20 -> country JP only.
	t.Setenv("UNMASK_TEST_GEO_OVERRIDE", "203.0.113.10:BR:16509,198.51.100.20:JP")
	gip := ipgeo.Open("", "") // no files; overrides drive both country + asn
	h := &Handler{IPGeo: gip}

	r60 := 60
	cfg := settings.Settings{}
	cfg.Nginx.Asn = settings.AsnConfig{
		Rules: []settings.AsnRule{
			{ASN: 16509, Action: settings.RateChallengeDeny, RatePerMin: &r60, Enabled: true}, // rate rule, deny action
		},
	}
	cfg.Nginx.Geo = settings.GeoConfig{
		Rules: []settings.GeoRule{
			{Country: "BR", Action: settings.RateChallengeCaptchaOnly, RatePerMin: &r60, Enabled: true}, // also matches the BR client
			{Country: "JP", Action: settings.RateChallengePoWOnly, RatePerMin: &r60, Enabled: true},
		},
	}

	// BR + AS16509 client: ASN rule (deny) wins over the geo BR rule (captcha).
	if got := h.netRateOverageAction("203.0.113.10", cfg); got != settings.RateChallengeDeny {
		t.Errorf("BR/AS16509 client: got %q, want deny (ASN rule wins)", got)
	}
	// JP client with no ASN rule: falls to the geo JP rate rule.
	if got := h.netRateOverageAction("198.51.100.20", cfg); got != settings.RateChallengePoWOnly {
		t.Errorf("JP client: got %q, want pow_only (geo rule)", got)
	}
	// A client matching no rate-mode rule -> "" (leave the base chMode).
	if got := h.netRateOverageAction("192.0.2.99", cfg); got != "" {
		t.Errorf("unmatched client: got %q, want empty", got)
	}
	// A rate rule with NO effective rate (action-only) is not a rate zone, so
	// it must not surface here.  (RateRules already excludes it; this pins that
	// the overage resolver rides RateRules, not ResolveRule.)
	cfg.Nginx.Asn = settings.AsnConfig{
		Rules: []settings.AsnRule{{ASN: 16509, Action: settings.RateChallengeDeny, Enabled: true}}, // rate 0
	}
	cfg.Nginx.Geo = settings.GeoConfig{}
	if got := h.netRateOverageAction("203.0.113.10", cfg); got != "" {
		t.Errorf("action-only (rate 0) rule must not resolve as a rate overage, got %q", got)
	}
}
