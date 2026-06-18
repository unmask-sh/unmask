package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/events"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestStaticAssetsTipPatternsCompile guards against a typo in the
// nginxconf.BypassPathPresetGroups patterns that would silently disable the
// hunt-page tip (= compile() drops bad regex without error).
func TestStaticAssetsTipPatternsCompile(t *testing.T) {
	pats := compileStaticAssetsTipPatterns()
	if len(pats) < 3 {
		t.Fatalf("compileStaticAssetsTipPatterns returned %d patterns, want ≥3", len(pats))
	}
	mustMatch := []string{
		"/static/foo.css",
		"/assets/logo.png",
		"/favicon.ico",
		"/robots.txt",
	}
	for _, p := range mustMatch {
		hit := false
		for _, re := range pats {
			if re.MatchString(p) {
				hit = true
				break
			}
		}
		if !hit {
			t.Errorf("path %q did not match any static-assets preset pattern", p)
		}
	}
	mustNotMatch := []string{
		"/foo/static/bar", // ^/static/ is path-anchored.
		"/api/users",      // covered by api-paths preset, not static-assets.
		"",
	}
	for _, p := range mustNotMatch {
		for _, re := range pats {
			if re.MatchString(p) {
				t.Errorf("path %q unexpectedly matched a static-assets pattern", p)
			}
		}
	}
}

// TestBypassPathsPresetEnabled covers the inline slice scan used by the
// hunt-page tip to suppress the banner once the operator turns the preset on.
func TestBypassPathsPresetEnabled(t *testing.T) {
	off := settings.BypassPathsConfig{}
	if bypassPathsPresetEnabled(off, "static-assets") {
		t.Errorf("empty config: bypassPathsPresetEnabled = true, want false")
	}
	on := settings.BypassPathsConfig{EnabledPresets: []string{"well-known", "static-assets"}}
	if !bypassPathsPresetEnabled(on, "static-assets") {
		t.Errorf("preset present: bypassPathsPresetEnabled = false, want true")
	}
	if bypassPathsPresetEnabled(on, "api-paths") {
		t.Errorf("absent preset: bypassPathsPresetEnabled = true, want false")
	}
}

// TestIsHuntTipDismissed covers the cookie scan that suppresses the tip
// banner after the operator clicks the dismiss button.
func TestIsHuntTipDismissed(t *testing.T) {
	mk := func(ck string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/", nil)
		if ck != "" {
			r.AddCookie(&http.Cookie{Name: "unmask_hunt_tip_dismissed", Value: ck})
		}
		return r
	}
	cases := []struct {
		cookie, tip string
		want        bool
	}{
		{"", "static-assets", false},
		{"static-assets", "static-assets", true},
		{"well-known,static-assets", "static-assets", true},
		{"well-known", "static-assets", false},
		// URL-encoded comma still parses correctly via decodeCookieValue.
		{"well-known%2Cstatic-assets", "static-assets", true},
	}
	for _, c := range cases {
		if got := isHuntTipDismissed(mk(c.cookie), c.tip); got != c.want {
			t.Errorf("cookie=%q tip=%q: isHuntTipDismissed = %v, want %v", c.cookie, c.tip, got, c.want)
		}
	}
}

// TestStaticAssetsTipHitsCounting threads typical hunt rows through the same
// match loop AdminHuntIndex runs.  Paths carrying a query string strip the
// `?...` portion before matching so /static/site.css?v=1 still counts.
func TestStaticAssetsTipHitsCounting(t *testing.T) {
	pats := compileStaticAssetsTipPatterns()
	rows := []events.Row{
		{Path: "/static/site.css"},
		{Path: "/static/site.css?v=1"},
		{Path: "/assets/logo.png"},
		{Path: "/favicon.ico"},
		{Path: "/robots.txt"},
		{Path: "/api/users"}, // not in static-assets.
		{Path: ""},           // empty path skipped.
		{Path: "/foo"},       // unrelated path.
	}
	count := 0
	for _, e := range rows {
		p := e.Path
		if p == "" {
			continue
		}
		if i := indexQuery(p); i >= 0 {
			p = p[:i]
		}
		for _, re := range pats {
			if re.MatchString(p) {
				count++
				break
			}
		}
	}
	if count != 5 {
		t.Fatalf("count = %d, want 5", count)
	}
}

// indexQuery mirrors strings.IndexByte(p, '?') used inside AdminHuntIndex.
// Inlined to keep the test self-contained without exporting the loop body.
func indexQuery(s string) int {
	for i := 0; i < len(s); i++ {
		if s[i] == '?' {
			return i
		}
	}
	return -1
}

// TestRefFromQuery: the hunt search box pulls the 16-hex id out of whatever the
// operator pastes (the bare id, an uppercased copy, or the whole "Ref ID: <id>"
// footer text), and yields "" for anything without a 16-hex run -- so the
// FetchPaged LIKE it feeds is always hex-only.
func TestRefFromQuery(t *testing.T) {
	cases := []struct{ in, want string }{
		{"9fe5aa2f1ef4c1d3", "9fe5aa2f1ef4c1d3"},        // clean id (the normal paste)
		{"9FE5AA2F1EF4C1D3", "9fe5aa2f1ef4c1d3"},        // uppercased -> lowered
		{"Ref ID: 9fe5aa2f1ef4c1d3", "9fe5aa2f1ef4c1d3"}, // whole footer text pasted
		{"  9fe5aa2f1ef4c1d3  ", "9fe5aa2f1ef4c1d3"},    // surrounding whitespace
		{"9fe5aa2f1ef4c1d399", "9fe5aa2f1ef4c1d3"},      // first 16-run wins
		{"deadbeef", ""},                                // < 16 hex -> no filter
		{"", ""},                                        // empty
		{"'; DROP TABLE x --", ""},                      // no hex run -> no filter (LIKE-safe)
	}
	for _, c := range cases {
		if got := refFromQuery(c.in); got != c.want {
			t.Errorf("refFromQuery(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
