package nginxconf

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// bypassRenderSettings: a configuration whose ban file sits in a directory of
// its own (the module looks for bypass-ip.txt beside it), with the access log
// reaching the daemon so a render that changes something leaves the reload
// marker.
func bypassRenderSettings(t *testing.T) (settings.Settings, string, string) {
	t.Helper()
	root := t.TempDir()
	s, err := settings.LoadFromYAML("secret:\n  bv_secret: \"0123456789abcdef0123456789abcdef\"\n" +
		"nginx_log:\n  enabled: true\n  socket_path: " + filepath.Join(root, "log.sock") + "\n" +
		"community_bans:\n  subscribe_mode: \"off\"\n")
	if err != nil {
		t.Fatal(err)
	}
	outDir := filepath.Join(root, "out")
	banDir := filepath.Join(root, "ban")
	s.Nginx.OutputDir = outDir
	s.Nginx.Honeypot.BanFilePath = filepath.Join(banDir, "banned.txt")
	s.Nginx.BypassIPs = []string{"203.0.113.0/24", "198.51.100.7"}
	s.Nginx.StatsExcludeIPs = []string{"192.0.2.9"}
	return s, outDir, banDir
}

// The render writes the bypass list beside the ban file -- the rendered geo's
// own entries, operator rows and statistics exclusions included -- readable by
// nginx's workers, and leaves it alone when nothing in it changed.
func TestRenderWritesBypassRuntimeFile(t *testing.T) {
	s, outDir, banDir := bypassRenderSettings(t)
	if err := Render(s, outDir, "test"); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(banDir, BypassRuntimeFile)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("no bypass list beside the ban file: %v", err)
	}
	lines := map[string]bool{}
	for _, l := range strings.Split(string(b), "\n") {
		lines[l] = true
	}
	for _, want := range []string{"203.0.113.0/24", "198.51.100.7", "192.0.2.9"} {
		if !lines[want] {
			t.Errorf("bypass-ip.txt lacks %s:\n%.400s", want, b)
		}
	}
	if !strings.HasPrefix(string(b), "# Written by unmask") {
		t.Errorf("bypass-ip.txt has no header: %.120q", b)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Errorf("bypass-ip.txt mode %v, want 0644 (nginx's workers read it)", fi.Mode().Perm())
	}
	// Every rendered range is also in the static geo, for an older module.
	conf, err := os.ReadFile(filepath.Join(outDir, "http.inc"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"geo $unmask_bypass_ip_static {", "    203.0.113.0/24 1;", "map \"\" $unmask_bypass_ip_rt {",
		`map "$unmask_bypass_ip_rt:$unmask_bypass_ip_static" $is_bypass_ip {`} {
		if !strings.Contains(string(conf), want) {
			t.Errorf("http.inc lacks %q", want)
		}
	}

	// A second render of the same configuration does not rewrite the file.
	before, _ := os.Stat(path)
	if err := Render(s, outDir, "test"); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) || !before.ModTime().Equal(after.ModTime()) {
		t.Errorf("an unchanged list was written again (each worker would read it again)")
	}
}

// A ban file that names no directory gives the module no place to look, and
// the render writes no list.
func TestBypassRuntimePathNeedsADirectory(t *testing.T) {
	if got := BypassRuntimePath("banned.txt"); got != "" {
		t.Errorf("BypassRuntimePath(banned.txt) = %q, want \"\"", got)
	}
	if got := BypassRuntimePath("/var/lib/unmask/nginx/banned.txt"); got != "/var/lib/unmask/nginx/bypass-ip.txt" {
		t.Errorf("BypassRuntimePath = %q", got)
	}
	if err := writeBypassRuntimeFile("banned.txt", []string{"192.0.2.1"}); err != nil {
		t.Errorf("no directory is not an error: %v", err)
	}
}

// A change to the bypass ranges alone keeps the render id and raises neither
// the reload marker nor the substantive-change marker: the module reads them
// at run time.  A change nginx does have to load -- the statistics
// exclusions, which also feed $unmask_stats_excluded -- still does.
func TestBypassOnlyChangeNeedsNoReload(t *testing.T) {
	s, outDir, banDir := bypassRenderSettings(t)
	if err := Render(s, outDir, "test"); err != nil {
		t.Fatal(err)
	}
	id0, _ := RenderIDOnDisk(outDir)
	if id0 == "" {
		t.Fatal("no render id on disk")
	}
	_ = os.Remove(filepath.Join(outDir, ReloadNeededMarker))
	_ = os.Remove(filepath.Join(outDir, SubstantiveRenderMarker))

	s.Nginx.BypassIPs = append(s.Nginx.BypassIPs, "198.51.100.64/26")
	if err := Render(s, outDir, "test"); err != nil {
		t.Fatal(err)
	}
	if id, _ := RenderIDOnDisk(outDir); id != id0 {
		t.Errorf("a bypass-only change moved the render id %s -> %s", id0, id)
	}
	for _, m := range []string{ReloadNeededMarker, SubstantiveRenderMarker} {
		if _, err := os.Stat(filepath.Join(outDir, m)); err == nil {
			t.Errorf("a bypass-only change left %s", m)
		}
	}
	conf, _ := os.ReadFile(filepath.Join(outDir, "http.inc"))
	if !strings.Contains(string(conf), "    198.51.100.64/26 1;") {
		t.Errorf("the static geo was not brought up to date for an older module")
	}
	if b, _ := os.ReadFile(filepath.Join(banDir, BypassRuntimeFile)); !strings.Contains(string(b), "\n198.51.100.64/26\n") {
		t.Errorf("the run-time list lacks the new range")
	}

	s.Nginx.StatsExcludeIPs = append(s.Nginx.StatsExcludeIPs, "192.0.2.10")
	if err := Render(s, outDir, "test"); err != nil {
		t.Fatal(err)
	}
	if id, _ := RenderIDOnDisk(outDir); id == id0 {
		t.Errorf("a statistics-exclusion change kept the render id")
	}
	if _, err := os.Stat(filepath.Join(outDir, ReloadNeededMarker)); err != nil {
		t.Errorf("a change nginx has to load left no reload marker")
	}
	// The notice names what has to be loaded -- the statistics exclusions --
	// and not the static bypass geo, which changed with them.
	rec, ok := ReadRenderRecord(outDir)
	if !ok {
		t.Fatal("no render record")
	}
	stats := false
	for _, c := range rec.Changes {
		if strings.Contains(c.Block, "$unmask_bypass_ip_static") {
			t.Errorf("the reload notice names the static bypass geo: %+v", c)
		}
		stats = stats || strings.Contains(c.Block, "unmask_stats_excluded")
	}
	if !stats {
		t.Errorf("the reload notice does not name the statistics exclusions: %+v", rec.Changes)
	}
}

func TestMaskBypassStatic(t *testing.T) {
	a := "x\ngeo $unmask_bypass_ip_static {\n    default 0;\n    192.0.2.1 1;\n}\nmap y\n"
	b := "x\ngeo $unmask_bypass_ip_static {\n    default 0;\n    198.51.100.0/24 1;\n    192.0.2.1 1;\n}\nmap y\n"
	if maskBypassStatic(a) != maskBypassStatic(b) {
		t.Errorf("two renders that differ only in the static geo's entries mask differently")
	}
	c := strings.Replace(b, "map y", "map z", 1)
	if maskBypassStatic(a) == maskBypassStatic(c) {
		t.Errorf("a change outside the static geo was masked away")
	}
}
