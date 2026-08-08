package main

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/handlers"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestSettingsTabRouting pins the ServeMux precedence after the settings tab
// moved from ?tab=X into the path (/admin/settings/{tab}/).  The {tab} wildcard
// must not shadow the literal settings sub-routes (asn/suggest, export, save) --
// Go routes the more specific literal first -- and the bare index must stay on
// its own {$} pattern.  Built through the real buildRouter, so a future route
// edit that reintroduces a conflict (or a registration panic) fails here rather
// than in production.  A miss returns pattern "" and trips the Contains check.
func TestSettingsTabRouting(t *testing.T) {
	s := settings.Settings{}
	s.Server.BasePath = "/unmask"
	mux := buildRouter(s, &handlers.Handler{}) // also asserts registration does not panic

	cases := []struct {
		method, path, wantPattern string
	}{
		{"GET", "/unmask/admin/settings/", "/admin/settings/{$}"},
		{"GET", "/unmask/admin/settings/sites/", "/admin/settings/{tab}/{$}"},
		{"GET", "/unmask/admin/settings/asn/", "/admin/settings/{tab}/{$}"},
		{"GET", "/unmask/admin/settings/ja4-verdicts/", "/admin/settings/{tab}/{$}"},
		{"GET", "/unmask/admin/settings/community-bans/", "/admin/settings/{tab}/{$}"},
		{"GET", "/unmask/admin/settings/asn/suggest", "/admin/settings/asn/suggest"},
		{"GET", "/unmask/admin/settings/export", "/admin/settings/export"},
		{"POST", "/unmask/admin/settings/save", "/admin/settings/save"},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil)
		_, pattern := mux.Handler(req)
		if !strings.Contains(pattern, c.wantPattern) {
			t.Errorf("%s %s -> matched pattern %q, want it to contain %q",
				c.method, c.path, pattern, c.wantPattern)
		}
	}
}
