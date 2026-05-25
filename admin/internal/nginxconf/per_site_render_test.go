// Multi-site phase 2.2 tests: ensure buildRenderData lifts per-site
// Overrides[site] entries from BypassPathsConfig / ProtectedPathsConfig into
// the per-host map fragments http.conf.tmpl renders.
package nginxconf

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestBuildRenderDataPerSiteBypassPaths: a BypassPathsConfig with two sites
// in Overrides surfaces in BypassPathsPerHost (= Site-scoped rules) while
// the default Paths land in BypassPathsGlobal.
func TestBuildRenderDataPerSiteBypassPaths(t *testing.T) {
	s := settings.Settings{}
	s.Nginx.BypassPaths = settings.BypassPathsConfig{
		Paths: []settings.BypassPath{
			{Path: "^/api/health$"},
		},
		Overrides: map[string]settings.BypassPathsOverride{
			"shop.example.com": {
				Append: []settings.BypassPath{{Path: "^/api/v2/"}},
			},
			"blog.example.com": {
				Append: []settings.BypassPath{{Path: "^/rss/"}},
			},
			// empty override: should not produce a per-host map entry.
			"empty.example.com": {},
		},
	}
	d, err := buildRenderData(s, "/etc/unmask", "v0.1.0-test")
	if err != nil {
		t.Fatalf("buildRenderData: %v", err)
	}

	// Global = default-Paths only.
	if want := []string{"^/api/health$"}; !reflect.DeepEqual(d.BypassPathsGlobal, want) {
		t.Errorf("BypassPathsGlobal = %v, want %v", d.BypassPathsGlobal, want)
	}

	// Per-host: 2 entries (= shop + blog).  Sorted by host.
	if got := len(d.BypassPathsPerHost); got != 2 {
		t.Fatalf("BypassPathsPerHost len = %d, want 2 (got %+v)", got, d.BypassPathsPerHost)
	}
	if d.BypassPathsPerHost[0].Host != "blog.example.com" {
		t.Errorf("BypassPathsPerHost[0].Host = %q, want blog.example.com",
			d.BypassPathsPerHost[0].Host)
	}
	if d.BypassPathsPerHost[1].Host != "shop.example.com" {
		t.Errorf("BypassPathsPerHost[1].Host = %q, want shop.example.com",
			d.BypassPathsPerHost[1].Host)
	}
	if !reflect.DeepEqual(d.BypassPathsPerHost[0].Patterns, []string{"^/rss/"}) {
		t.Errorf("blog patterns = %v, want [^/rss/]", d.BypassPathsPerHost[0].Patterns)
	}
	if !reflect.DeepEqual(d.BypassPathsPerHost[1].Patterns, []string{"^/api/v2/"}) {
		t.Errorf("shop patterns = %v, want [^/api/v2/]", d.BypassPathsPerHost[1].Patterns)
	}
}

// TestBuildRenderDataPerSiteProtectedPaths_Append: a site Append on top of
// the default Paths produces a ProtectedPathsPerHost entry with the Append
// rule scoped to that host.  The default rule stays in
// ProtectedPathsGlobal.
func TestBuildRenderDataPerSiteProtectedPaths_Append(t *testing.T) {
	s := settings.Settings{}
	s.Nginx.ProtectedPaths = settings.ProtectedPathsConfig{
		Paths: []settings.ProtectedPath{
			{Path: "/admin/", Mode: "captcha"},
		},
		Overrides: map[string]settings.ProtectedPathsOverride{
			"shop.example.com": {
				Append: []settings.ProtectedPath{{Path: "/checkout/", Mode: "pow"}},
			},
		},
	}
	d, err := buildRenderData(s, "/etc/unmask", "v0.1.0-test")
	if err != nil {
		t.Fatalf("buildRenderData: %v", err)
	}

	// Global = default-Paths only.
	if got := len(d.ProtectedPathsGlobal); got != 1 || d.ProtectedPathsGlobal[0].Pattern != "/admin/" {
		t.Errorf("ProtectedPathsGlobal = %+v, want one /admin/ entry", d.ProtectedPathsGlobal)
	}

	// Per-host: 1 entry (shop) with the /checkout/ Append rule.
	if got := len(d.ProtectedPathsPerHost); got != 1 {
		t.Fatalf("ProtectedPathsPerHost len = %d, want 1 (got %+v)",
			got, d.ProtectedPathsPerHost)
	}
	h := d.ProtectedPathsPerHost[0]
	if h.Host != "shop.example.com" {
		t.Errorf("host = %q, want shop.example.com", h.Host)
	}
	if h.VarName != "shop_example_com" {
		t.Errorf("varName = %q, want shop_example_com", h.VarName)
	}
	if len(h.Rules) != 1 || h.Rules[0].Pattern != "/checkout/" || h.Rules[0].Mode != "pow" {
		t.Errorf("rules = %+v, want one {/checkout/, pow}", h.Rules)
	}

	// No disable entries (= no Remove diff).
	if got := len(d.ProtectedPathsDisablePerHost); got != 0 {
		t.Errorf("ProtectedPathsDisablePerHost = %+v, want empty",
			d.ProtectedPathsDisablePerHost)
	}
}

// TestBuildRenderDataPerSiteProtectedPaths_Remove: a site Remove of a
// default-global path produces a ProtectedPathsDisablePerHost entry whose
// Patterns contains the removed path.  The default rule stays in
// ProtectedPathsGlobal (= other sites still get gated; only the removing
// site is exempted via the dispatcher's disable signal).
func TestBuildRenderDataPerSiteProtectedPaths_Remove(t *testing.T) {
	s := settings.Settings{}
	s.Nginx.ProtectedPaths = settings.ProtectedPathsConfig{
		Paths: []settings.ProtectedPath{
			{Path: "/admin/", Mode: "captcha"},
		},
		Overrides: map[string]settings.ProtectedPathsOverride{
			"blog.example.com": {
				Remove: []string{"/admin/"},
			},
		},
	}
	d, err := buildRenderData(s, "/etc/unmask", "v0.1.0-test")
	if err != nil {
		t.Fatalf("buildRenderData: %v", err)
	}

	// Global retains /admin/.
	if got := len(d.ProtectedPathsGlobal); got != 1 || d.ProtectedPathsGlobal[0].Pattern != "/admin/" {
		t.Errorf("ProtectedPathsGlobal = %+v, want default /admin/ retained", d.ProtectedPathsGlobal)
	}

	// No Append rules for blog -> ProtectedPathsPerHost is empty.
	if got := len(d.ProtectedPathsPerHost); got != 0 {
		t.Errorf("ProtectedPathsPerHost = %+v, want empty", d.ProtectedPathsPerHost)
	}

	// One disable entry for blog.example.com with /admin/ pattern.
	if got := len(d.ProtectedPathsDisablePerHost); got != 1 {
		t.Fatalf("ProtectedPathsDisablePerHost len = %d, want 1 (got %+v)",
			got, d.ProtectedPathsDisablePerHost)
	}
	dh := d.ProtectedPathsDisablePerHost[0]
	if dh.Host != "blog.example.com" {
		t.Errorf("disable host = %q, want blog.example.com", dh.Host)
	}
	if !reflect.DeepEqual(dh.Patterns, []string{"/admin/"}) {
		t.Errorf("disable patterns = %v, want [/admin/]", dh.Patterns)
	}
}

// TestBuildRenderDataPerSiteProtectedPaths_AppendAndRemove: shop appends
// /checkout/ + blog removes /admin/.  Should produce both a perhost Append
// for shop AND a disable for blog, ordered by host.
func TestBuildRenderDataPerSiteProtectedPaths_AppendAndRemove(t *testing.T) {
	s := settings.Settings{}
	s.Nginx.ProtectedPaths = settings.ProtectedPathsConfig{
		Paths: []settings.ProtectedPath{
			{Path: "/admin/", Mode: "captcha"},
		},
		Overrides: map[string]settings.ProtectedPathsOverride{
			"shop.example.com": {
				Append: []settings.ProtectedPath{{Path: "/checkout/", Mode: "pow"}},
			},
			"blog.example.com": {
				Remove: []string{"/admin/"},
			},
		},
	}
	d, err := buildRenderData(s, "/etc/unmask", "v0.1.0-test")
	if err != nil {
		t.Fatalf("buildRenderData: %v", err)
	}

	// Append goes to shop only.
	if got := len(d.ProtectedPathsPerHost); got != 1 {
		t.Fatalf("ProtectedPathsPerHost len = %d, want 1 (got %+v)",
			got, d.ProtectedPathsPerHost)
	}
	if d.ProtectedPathsPerHost[0].Host != "shop.example.com" {
		t.Errorf("perhost[0].host = %q, want shop", d.ProtectedPathsPerHost[0].Host)
	}

	// Disable goes to blog only.
	if got := len(d.ProtectedPathsDisablePerHost); got != 1 {
		t.Fatalf("ProtectedPathsDisablePerHost len = %d, want 1 (got %+v)",
			got, d.ProtectedPathsDisablePerHost)
	}
	if d.ProtectedPathsDisablePerHost[0].Host != "blog.example.com" {
		t.Errorf("disable[0].host = %q, want blog", d.ProtectedPathsDisablePerHost[0].Host)
	}
}

// TestGatherSitesDeterministic: ensure gatherSites drops "" / whitespace /
// "default", trims, and returns sorted output.
func TestGatherSitesDeterministic(t *testing.T) {
	in := map[string]settings.BypassPathsOverride{
		"zz.example.com": {},
		"aa.example.com": {},
		"":               {},
		"   ":            {},
		"default":        {},
		"mm.example.com": {},
	}
	got := gatherSites(in)
	want := []string{"aa.example.com", "mm.example.com", "zz.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("gatherSites = %v, want %v", got, want)
	}
}

// TestRenderEndToEndProtectedPerHost: full Render() into a tmp dir; the
// produced http.inc contains the per-host map fragments.  This is the
// integration safety net so a template typo surfaces.
func TestRenderEndToEndProtectedPerHost(t *testing.T) {
	s := settings.Settings{}
	s.Nginx.OutputDir = t.TempDir()
	s.Secret.BVSecret = "test-secret"
	s.Nginx.ProtectedPaths = settings.ProtectedPathsConfig{
		Paths: []settings.ProtectedPath{
			{Path: "/admin/", Mode: "captcha"},
		},
		Overrides: map[string]settings.ProtectedPathsOverride{
			"shop.example.com": {
				Append: []settings.ProtectedPath{{Path: "/checkout/", Mode: "pow"}},
			},
			"blog.example.com": {
				Remove: []string{"/admin/"},
			},
		},
	}
	if err := Render(s, "", "v0.1.0-test"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	httpInc := mustReadFile(t, s.Nginx.OutputDir+"/native/http.inc")
	checks := []string{
		// Global map keeps /admin/.
		`map $request_uri $protected_mode_global`,
		`"~*/admin/" "captcha";`,
		// Shop's perhost map adds /checkout/.
		`map $request_uri $protected_mode_host_shop_example_com`,
		`"~*/checkout/" "pow";`,
		// Dispatcher selects per-host map for shop.
		`"shop.example.com" $protected_mode_host_shop_example_com;`,
		// Blog's disable map covers /admin/.
		`map $request_uri $protected_mode_disable_host_blog_example_com`,
		`"~*/admin/" "1";`,
		`"blog.example.com" $protected_mode_disable_host_blog_example_com;`,
		// Final combinator map landed.
		`map "$protected_mode_disable:$protected_mode_pre" $protected_mode`,
	}
	for _, want := range checks {
		if !strings.Contains(httpInc, want) {
			t.Errorf("http.inc missing fragment:\n  want substring: %s\n--- got (head) ---\n%s",
				want, headLines(httpInc, 200))
		}
	}
}

func mustReadFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}

func headLines(s string, n int) string {
	lines := strings.Split(s, "\n")
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
