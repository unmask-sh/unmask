package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Every location that hands a request to the daemon names the difficulty the
// plugin verifies at for the host: the challenge page asks for that one, and
// the daemon's setting leads it until nginx reloads.
func TestServerIncHandsTheDaemonTheDifficultyNginxVerifiesAt(t *testing.T) {
	dir := t.TempDir()
	var s settings.Settings
	s.Nginx.OutputDir = dir
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "server.inc"))
	if err != nil {
		t.Fatal(err)
	}
	server := string(b)
	proxies := strings.Count(server, "proxy_set_header   X-Unmask-Local-Port $server_port;")
	named := strings.Count(server, "proxy_set_header   X-Unmask-Pow-Difficulty $unmask_pow_difficulty;")
	if proxies == 0 || named != proxies {
		t.Errorf("%d location(s) hand a request to the daemon and %d name the difficulty", proxies, named)
	}
	h, err := os.ReadFile(filepath.Join(dir, "http.inc"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(h), "map $host $unmask_pow_difficulty {") {
		t.Error("http.inc defines no $unmask_pow_difficulty for server.inc to hand on")
	}
}
