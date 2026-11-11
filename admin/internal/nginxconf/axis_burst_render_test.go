package nginxconf

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// An axis row beside the primary one, enabled with its burst left at 0,
// rendered `burst=0` into protect.inc, and nginx refuses that ("invalid
// burst value").  It takes the axis's seed, as its rate does and as the
// primary row and the named zones do.
func TestAxisRowBurstZeroTakesTheSeed(t *testing.T) {
	var s settings.Settings
	dir := t.TempDir()
	s.Nginx.OutputDir = dir
	s.RateLimit.JA4Limit = settings.AxisLimitConfig{Enabled: true, RequestsPerMin: 600}
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("render: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "protect.inc"))
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	if regexp.MustCompile(`burst=0\b`).MatchString(out) {
		t.Errorf("protect.inc carries burst=0:\n%s", grepLines(out, "burst="))
	}
	want := "burst=" + strconv.Itoa(settings.AxisSeedBurst(settings.RateLimitKeyJA4)) + " "
	if !strings.Contains(grepLines(out, settings.AxisZoneName(settings.RateLimitKeyJA4)), want) {
		t.Errorf("the JA4 axis zone does not take its seed burst (%s):\n%s", want, grepLines(out, "burst="))
	}
}

func grepLines(s, sub string) string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if strings.Contains(ln, sub) {
			out = append(out, ln)
		}
	}
	return strings.Join(out, "\n")
}
