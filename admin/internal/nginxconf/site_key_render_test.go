package nginxconf

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A per-site rule whose Site cannot key a host map -- quoted, ending in a
// backslash, a word nginx's map reserves -- broke the configuration: the
// quoted one applied to every host, the backslash failed `nginx -t`, and
// "default" was a second default.  The admin refuses such a Site; one
// hand-edited into config.yml is left out of the maps, with a warning, and
// the valid sites keep theirs.
func TestUnkeyableSitesAreLeftOut(t *testing.T) {
	dir := t.TempDir()
	var s settings.Settings
	s.Nginx.OutputDir = dir
	s.Nginx.BypassPaths.Paths = []settings.BypassPath{
		{Path: `^/feed/`, Site: "shop.example.com"},
		{Path: `^/a/`, Site: `"other.example.com"`},
		{Path: `^/b/`, Site: `other.example.com\`},
		{Path: `^/c/`, Site: "default"},
	}
	// The same in the other per-site lists.
	s.Nginx.Honeypot.URLs = []settings.HoneypotURL{{Path: `^/trap/`, Site: `"other.example.com"`}, {Path: `^/trap2/`, Site: "shop.example.com"}}
	s.Nginx.ProtectedPaths.Paths = []settings.ProtectedPath{{Path: `^/login/`, Site: "include"}, {Path: `^/admin/`, Site: "shop.example.com"}}
	s.Nginx.Geo.ExemptPaths = []settings.BypassPath{{Path: `^/geo/`, Site: `"other.example.com"`}}
	d, err := buildRenderData(s, dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{`"\"other.example.com\""`, `"other.example.com\\"`, `"default"`} {
		if !strings.Contains(d.siteWarning, w) {
			t.Errorf("the warning does not name %s: %s", w, d.siteWarning)
		}
	}
	if err := Render(s, dir, "test"); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "http.inc"))
	if err != nil {
		t.Fatal(err)
	}
	out := string(b)
	if !strings.Contains(out, `"shop.example.com" $unmask_bp_host_`) {
		t.Error("the valid site lost its rule")
	}
	for _, bad := range []string{`""other.example.com""`, `"other.example.com\"`, `"default" $unmask_bp_host_`, `"include" $unmask_pp_host_`} {
		if strings.Contains(out, bad) {
			t.Errorf("http.inc keys a host map with %s", bad)
		}
	}
	// A quoted site was widened to every host: its pattern is in no global
	// map either.
	for _, p := range []string{`^/a/`, `^/trap/`, `^/geo/`} {
		if strings.Contains(out, p) {
			t.Errorf("the pattern %s of an unkeyable site is still rendered", p)
		}
	}
	// Every per-site variable a map reads is defined by a map.
	for _, m := range regexp.MustCompile(`\$unmask_(?:hp|pp|bp|gx|ax)_host_[A-Za-z0-9_]+`).FindAllString(out, -1) {
		if !strings.Contains(out, " "+m+" {") {
			t.Errorf("%s is read but no map defines it", m)
		}
	}
}
