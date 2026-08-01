package handlers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/ratelimit"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The pairing per-zone keys exist for: a per-IP default plus a parallel
// all-paths JA4 zone.  Both must count every request -- first-match resolution
// would have let the JA4 zone swallow the default in forward-auth mode while
// native enforced both -- and each against its own key: rotating the IP must
// not reset the JA4 counter, rotating the JA4 must not reset the IP counter.
func TestAuthCheck_ParallelJA4Zone(t *testing.T) {
	const host = "shop.example.com"
	const ua = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36"

	newH := func() *Handler {
		h := &Handler{RateLimiter: ratelimit.New()}
		h.SetSettings(settings.Settings{
			Secret: settings.Secret{BVSecret: "test-secret"},
			RateLimit: settings.RateLimitConfig{
				Default: settings.RateLimitValues{Name: "unmask_rate", RequestsPerMin: 4, Burst: 0},
				Zones: []settings.RateZone{{
					Name:           "ja4_flood",
					Key:            settings.RateLimitKeyJA4,
					RequestsPerMin: 8,
					Burst:          0,
				}},
			},
		})
		return h
	}
	drive := func(h *Handler, ip, ja4 string) *http.Response {
		r := httptest.NewRequest(http.MethodGet, "/unmask/api/check", nil)
		r.Header.Set("X-Original-URI", "/page")
		r.Header.Set("X-Original-IP", ip)
		r.Header.Set("X-Original-Host", host)
		r.Header.Set("X-Client-JA4", ja4)
		r.Header.Set("User-Agent", ua)
		w := httptest.NewRecorder()
		h.AuthCheck(w, r)
		return w.Result()
	}

	t.Run("rotating IPs cannot dodge the JA4 zone", func(t *testing.T) {
		h := newH()
		const ja4 = "t13d1517h2_aaaa_bbbb"
		tripped := ""
		for i := 0; i < 30 && tripped == ""; i++ {
			// A fresh TEST-NET-1 IP every request: the per-IP default never
			// accumulates, so only the JA4 counter can trip.
			res := drive(h, fmt.Sprintf("192.0.2.%d", i+1), ja4)
			if res.Header.Get("X-Unmask-Action") == "challenge" {
				tripped = res.Header.Get("X-Unmask-Zone")
			}
		}
		if tripped != "ja4_flood" {
			t.Errorf("IP-rotating client with one JA4 should trip ja4_flood, got %q", tripped)
		}
	})

	t.Run("the per-IP default still counts alongside", func(t *testing.T) {
		h := newH()
		tripped := ""
		for i := 0; i < 30 && tripped == ""; i++ {
			// One IP, a fresh JA4 every request: only the default can trip.
			res := drive(h, "192.0.2.200", fmt.Sprintf("t13d1517h2_aaaa_%04d", i))
			if res.Header.Get("X-Unmask-Action") == "challenge" {
				tripped = res.Header.Get("X-Unmask-Zone")
			}
		}
		if tripped != "unmask_rate" {
			t.Errorf("single-IP client rotating JA4s should trip the default zone, got %q", tripped)
		}
	})

	t.Run("stable client trips the stricter limit first and reports it", func(t *testing.T) {
		h := newH()
		tripped := ""
		for i := 0; i < 30 && tripped == ""; i++ {
			res := drive(h, "192.0.2.201", "t13d1517h2_cccc_dddd")
			if res.Header.Get("X-Unmask-Action") == "challenge" {
				tripped = res.Header.Get("X-Unmask-Zone")
			}
		}
		// Default rpm 4 < ja4 zone rpm 8, so the default trips first even
		// though the JA4 zone is listed before it.
		if tripped != "unmask_rate" {
			t.Errorf("stable client should trip the tighter default first, got %q", tripped)
		}
	})
}

// A deny-mode zone trip must win the attribution over an earlier challenge
// trip in the same request: the hard cap cannot be reported (or enforced) as
// a recoverable challenge.
func TestAuthCheck_DenyTripOutranksChallengeTrip(t *testing.T) {
	h := &Handler{RateLimiter: ratelimit.New()}
	h.SetSettings(settings.Settings{
		Secret: settings.Secret{BVSecret: "test-secret"},
		RateLimit: settings.RateLimitConfig{
			Default: settings.RateLimitValues{Name: "unmask_rate", RequestsPerMin: 100, Burst: 50},
			Zones: []settings.RateZone{
				// Both match /api/; the challenge zone is listed first and has
				// the lower threshold, so it trips first.
				{Name: "api_soft", PathPatterns: []string{"/api/"}, RequestsPerMin: 2, ChallengeMode: settings.RateChallengePoWOnly},
				{Name: "api_cap", PathPatterns: []string{"/api/"}, RequestsPerMin: 4, ChallengeMode: settings.RateChallengeDeny},
			},
		},
	})
	var last *http.Response
	blocked := false
	for i := 0; i < 30 && !blocked; i++ {
		r := httptest.NewRequest(http.MethodGet, "/unmask/api/check", nil)
		r.Header.Set("X-Original-URI", "/api/v1/things")
		r.Header.Set("X-Original-IP", "203.0.113.77")
		r.Header.Set("X-Original-Host", "shop.example.com")
		r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0 Safari/537.36")
		w := httptest.NewRecorder()
		h.AuthCheck(w, r)
		last = w.Result()
		blocked = last.StatusCode == http.StatusForbidden
	}
	if !blocked {
		t.Fatal("the deny cap never fired; the soft zone is absorbing the flood")
	}
	if got := last.Header.Get("X-Unmask-Zone"); got != "api_cap" {
		t.Errorf("deny trip must own the attribution, got zone %q", got)
	}
	if got := last.Header.Get("X-Unmask-Action"); got != "block" {
		t.Errorf("deny trip must block, got %q", got)
	}
}

func TestResolveZonesAll(t *testing.T) {
	rl := settings.RateLimitConfig{
		Key:     settings.RateLimitKeyIP,
		Default: settings.RateLimitValues{Name: "unmask_rate", RequestsPerMin: 60},
		Zones: []settings.RateZone{
			{Name: "api", PathPatterns: []string{"/api/"}, RequestsPerMin: 30},
			{Name: "ja4_flood", Key: settings.RateLimitKeyJA4, RequestsPerMin: 600},
			{Name: "off", Disabled: true, RequestsPerMin: 1},
			{Name: "other_site", Site: "other.example.com", RequestsPerMin: 5},
		},
	}
	got := rl.ResolveZonesAll("/api/v1", "shop.example.com")
	names := []string{}
	for _, z := range got {
		names = append(names, z.Name+":"+z.Key)
	}
	want := []string{"api:ip", "ja4_flood:ja4", "unmask_rate:ip"}
	if len(names) != len(want) {
		t.Fatalf("zones = %v, want %v", names, want)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Errorf("zones[%d] = %q, want %q", i, names[i], want[i])
		}
	}
	// Off-path: only the all-paths zones + default.
	got = rl.ResolveZonesAll("/page", "shop.example.com")
	if len(got) != 2 || got[0].Name != "ja4_flood" || got[1].Name != "unmask_rate" {
		t.Errorf("off-path zones wrong: %+v", got)
	}
}

func TestZoneKeyResolved(t *testing.T) {
	rl := settings.RateLimitConfig{Key: settings.RateLimitKeyJA4}
	if k := rl.ZoneKeyResolved(settings.RateZone{}); k != settings.RateLimitKeyJA4 {
		t.Errorf("empty zone key must inherit the global (ja4), got %q", k)
	}
	if k := rl.ZoneKeyResolved(settings.RateZone{Key: "ip"}); k != settings.RateLimitKeyIP {
		t.Errorf("an explicit ip pin must survive a ja4 global, got %q", k)
	}
	if k := rl.ZoneKeyResolved(settings.RateZone{Key: "bogus"}); k != settings.RateLimitKeyJA4 {
		t.Errorf("an invalid zone key must fall back to the global, got %q", k)
	}
	if k := (settings.RateLimitConfig{}).ZoneKeyResolved(settings.RateZone{}); k != settings.RateLimitKeyIP {
		t.Errorf("all-default must resolve to ip, got %q", k)
	}
}

// The zone form round-trips the per-zone key: empty = inherit, a valid kind
// persists verbatim, and an unknown kind is rejected rather than silently
// dropped into "inherit".
func TestApplyRateLimitFormZoneKey(t *testing.T) {
	form := func(key string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=rate-limit",
			strings.NewReader(url.Values{
				"zone_0_name":   {"ja4_flood"},
				"zone_0_rpm":    {"600"},
				"zone_0_burst":  {"100"},
				"zone_0_window": {"60"},
				"zone_0_key":    {key},
				"zone_0_on":     {"1"},
			}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		_ = r.ParseForm()
		return r
	}
	var c settings.RateLimitConfig
	if err := applyRateLimitForm(&c, form("ja4")); err != nil {
		t.Fatalf("save: %v", err)
	}
	if len(c.Zones) != 1 || c.Zones[0].Key != "ja4" {
		t.Errorf("zones = %+v", c.Zones)
	}
	if err := applyRateLimitForm(&c, form("")); err != nil {
		t.Fatalf("save: %v", err)
	}
	if c.Zones[0].Key != "" {
		t.Errorf("empty key must persist as inherit, got %q", c.Zones[0].Key)
	}
	if err := applyRateLimitForm(&c, form("bogus")); err == nil {
		t.Error("an unknown key kind must be rejected")
	}
}
