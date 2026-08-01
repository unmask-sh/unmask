package nginxconf

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func renderHTTPWithZones(t *testing.T, rl settings.RateLimitConfig) string {
	t.Helper()
	return renderHTTPInc(t, func(s *settings.Settings) {
		s.Secret.BVSecret = "test-secret"
		s.RateLimit = rl
	})
}

// A zone with its own key kind gets a dedicated $rate_limit_key_<sfx> map and
// counts against it; zones on the global kind keep the plain map, and a
// config with no overrides emits no variant maps at all (byte-compatible with
// pre-per-zone-key renders).
func TestRenderPerZoneKeyVariants(t *testing.T) {
	base := settings.RateLimitConfig{
		Default: settings.RateLimitValues{Name: "unmask_rate", RequestsPerMin: 60, Burst: 20},
	}

	t.Run("no overrides -> no variant maps", func(t *testing.T) {
		rl := base
		rl.Zones = []settings.RateZone{{Name: "api", PathPatterns: []string{"/api/"}, RequestsPerMin: 30, Burst: 5}}
		conf := renderHTTPWithZones(t, rl)
		if strings.Contains(conf, "$rate_limit_key_ja4") || strings.Contains(conf, "$rate_limit_key_ipja4") {
			t.Error("a config with no per-zone keys must not emit variant maps")
		}
	})

	t.Run("all-paths ja4 zone counts against the ja4 variant", func(t *testing.T) {
		rl := base
		rl.Zones = []settings.RateZone{{Name: "ja4_flood", Key: "ja4", RequestsPerMin: 600, Burst: 100}}
		conf := renderHTTPWithZones(t, rl)
		if !strings.Contains(conf, "$rate_limit_key_ja4 {") {
			t.Error("ja4 variant map missing")
		}
		if !strings.Contains(conf, "limit_req_zone $rate_limit_key_ja4 zone=ja4_flood:10m rate=600r/m;") {
			t.Error("ja4 zone not declared against the variant key")
		}
		// The variant carries the JA4 expression and the same exemptions.
		i := strings.Index(conf, "$rate_limit_key_ja4 {")
		seg := conf[i : i+300]
		if !strings.Contains(seg, "default       $effective_ja4;") {
			t.Errorf("ja4 variant should count $effective_ja4:\n%s", seg)
		}
		// The default zone stays on the plain map with the global (ip) expr.
		if !strings.Contains(conf, "limit_req_zone $rate_limit_key zone=unmask_rate:10m rate=60r/m;") {
			t.Error("default zone left the plain key")
		}
	})

	t.Run("deny path zone with ja4 key uses the deny variant", func(t *testing.T) {
		rl := base
		rl.Zones = []settings.RateZone{{
			Name: "cap", Key: "ja4", PathPatterns: []string{"/api/"},
			RequestsPerMin: 300, Burst: 10, ChallengeMode: settings.RateChallengeDeny,
		}}
		conf := renderHTTPWithZones(t, rl)
		if !strings.Contains(conf, "$rate_limit_key_deny_ja4 {") {
			t.Error("deny ja4 variant map missing")
		}
		// The path-conditional key feeds the deny variant in.
		if !strings.Contains(conf, `"1" $rate_limit_key_deny_ja4;`) {
			t.Error("path zone's conditional key does not reference the deny ja4 variant")
		}
		// The deny variant must NOT carry the _bv exemption (4-field map is
		// the challenge one; deny maps key on 3 fields).
		i := strings.Index(conf, "$rate_limit_key_deny_ja4 {")
		head := conf[strings.LastIndex(conf[:i], "map "):i]
		if strings.Contains(head, "$bv_any_valid") {
			t.Error("deny variant must not exempt _bv holders")
		}
		// Only the deny variant is emitted -- the challenge-side ja4 map has
		// no consumer in this config.
		if strings.Contains(conf, "$rate_limit_key_ja4 {") {
			t.Error("unused challenge-side ja4 variant emitted")
		}
	})

	t.Run("ip pin on a ja4 global gets an ip variant", func(t *testing.T) {
		rl := base
		rl.Key = "ja4"
		rl.Zones = []settings.RateZone{{Name: "per_ip", Key: "ip", RequestsPerMin: 60, Burst: 10}}
		conf := renderHTTPWithZones(t, rl)
		if !strings.Contains(conf, "limit_req_zone $rate_limit_key_ip zone=per_ip:10m rate=60r/m;") {
			t.Error("ip-pinned zone should use the ip variant when the global is ja4")
		}
		i := strings.Index(conf, "$rate_limit_key_ip {")
		if i < 0 {
			t.Fatal("ip variant map missing")
		}
		if !strings.Contains(conf[i:i+300], "default       $unmask_client_net;") {
			t.Error("ip variant should count $unmask_client_net")
		}
	})
}
