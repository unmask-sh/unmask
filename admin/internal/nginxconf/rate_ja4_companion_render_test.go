package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func renderBothIncs(t *testing.T, mutate func(*settings.Settings)) (httpInc, protectInc string) {
	t.Helper()
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var s settings.Settings
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	if mutate != nil {
		mutate(&s)
	}
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	h, err := os.ReadFile(filepath.Join(dir, "http.inc"))
	if err != nil {
		t.Fatal(err)
	}
	p, err := os.ReadFile(filepath.Join(dir, "protect.inc"))
	if err != nil {
		t.Fatal(err)
	}
	return string(h), string(p)
}

// The built-in JA4 companion renders as a declared AND applied zone: declared
// in http.inc against the ja4 key variant, applied by protect.inc next to the
// default -- so enabling the toggle is all native mode needs.  Disabled (the
// default) leaves no trace.
func TestRenderJA4CompanionLimit(t *testing.T) {
	t.Run("disabled -> absent", func(t *testing.T) {
		httpInc, protectInc := renderBothIncs(t, nil)
		if strings.Contains(httpInc, settings.JA4LimitZoneName) ||
			strings.Contains(protectInc, settings.JA4LimitZoneName) {
			t.Error("the companion must not render while disabled")
		}
	})

	t.Run("enabled -> declared against the ja4 variant and applied", func(t *testing.T) {
		httpInc, protectInc := renderBothIncs(t, func(s *settings.Settings) {
			s.RateLimit.JA4Limit = settings.JA4LimitConfig{Enabled: true, RequestsPerMin: 600, Burst: 100}
		})
		if !strings.Contains(httpInc, "limit_req_zone $rate_limit_key_ja4 zone=unmask_rate_ja4:10m rate=600r/m;") {
			t.Error("companion not declared against the ja4 key variant")
		}
		if !strings.Contains(httpInc, "$rate_limit_key_ja4 {") {
			t.Error("ja4 key variant map missing")
		}
		if !strings.Contains(protectInc, "limit_req zone=unmask_rate_ja4 burst=100 nodelay;") {
			t.Error("companion is declared but never applied -- protect.inc must carry its limit_req")
		}
	})

	t.Run("ja4 global key + ja4 struct describe ONE row (the primary)", func(t *testing.T) {
		// key=ja4 and ja4_limit are two representations of the same axis, so
		// they merge into a single JA4 row -- which, being the only enabled
		// row, is the primary and renders as the classic default zone with
		// the struct's values.  No second zone, no variant map.
		httpInc, _ := renderBothIncs(t, func(s *settings.Settings) {
			s.RateLimit.Key = settings.RateLimitKeyJA4
			s.RateLimit.JA4Limit = settings.JA4LimitConfig{Enabled: true, RequestsPerMin: 600, Burst: 100}
		})
		if !strings.Contains(httpInc, "limit_req_zone $rate_limit_key zone=unmask_rate:10m rate=600r/m;") {
			t.Error("the merged JA4 row should render as the default zone with the struct's rate")
		}
		if strings.Contains(httpInc, "unmask_rate_ja4") {
			t.Error("no second JA4 zone may exist when JA4 is the primary axis")
		}
		if strings.Contains(httpInc, "$rate_limit_key_ja4 {") {
			t.Error("no variant map is needed when the primary key is already ja4")
		}
	})
}

// A no-path custom zone is now APPLIED by protect.inc, not merely declared.
// Forward-auth has always counted such zones; native declaring-without-
// applying was the same config enforcing on one wire and not the other.
func TestRenderNoPathZoneIsApplied(t *testing.T) {
	_, protectInc := renderBothIncs(t, func(s *settings.Settings) {
		s.RateLimit.Zones = []settings.RateZone{
			{Name: "everywhere", RequestsPerMin: 240, Burst: 40},
			{Name: "api_only", PathPatterns: []string{"/api/"}, RequestsPerMin: 30, Burst: 5},
		}
	})
	if !strings.Contains(protectInc, "limit_req zone=everywhere burst=40 nodelay;") {
		t.Error("no-path zone missing from protect.inc -- native mode would not enforce it")
	}
	if !strings.Contains(protectInc, "limit_req zone=api_only burst=5 nodelay;") {
		t.Error("path zone lost its limit_req")
	}
}
