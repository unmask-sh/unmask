// Phase 1.4b unit tests for the per-site editor on the protected /
// bypass-paths tabs.  Default-scope behavior must stay identical to the
// pre-scope helpers; site-scope writes must land in Overrides[scope] as
// sparse entries; empty overrides must be cleaned up; the reset flag must
// drop the whole entry.
package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// formReq builds a POST with x-www-form-urlencoded body suitable for the
// path-form handlers.  Repeated fields are passed as `key=v1&key=v2` so
// r.Form[key] yields a slice (= mirrors how the row UI submits).
func formReq(t *testing.T, raw string) *http.Request {
	t.Helper()
	r := httptest.NewRequest("POST", "/admin/settings/save", strings.NewReader(raw))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatalf("parse form: %v", err)
	}
	return r
}

// TestApplyProtectedFormScopedDefault: the empty-scope path must behave
// identically to the legacy applyProtectedForm (= writes into the baseline
// Paths slice + leaves the Overrides map untouched).
func TestApplyProtectedFormScopedDefault(t *testing.T) {
	n := &settings.Nginx{
		ProtectedPaths: settings.ProtectedPathsConfig{
			Paths: []settings.ProtectedPath{{Path: "/old/"}},
			Overrides: map[string]settings.ProtectedPathsOverride{
				"shop.example.com": {Append: []settings.ProtectedPath{{Path: "/shop-extra/"}}},
			},
		},
	}
	// One row + no preset toggles.  protected_default_action is left at the
	// default scope's normal value (pow_then_captcha).
	body := url.Values{
		"protected_pat":            []string{"^/admin/"},
		"protected_title":          []string{"admin"},
		"protected_enabled":        []string{"1"},
		"protected_updated_at":     []string{"0"},
		"protected_extra_action":   []string{"inherit"},
		"protected_default_action": []string{"pow_then_captcha"},
	}
	r := formReq(t, body.Encode())
	if err := applyProtectedFormScoped(n, r, i18n.LangEN, ""); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(n.ProtectedPaths.Paths) != 1 || n.ProtectedPaths.Paths[0].Path != "^/admin/" {
		t.Errorf("default scope did not rewrite Paths verbatim: %+v", n.ProtectedPaths.Paths)
	}
	if _, ok := n.ProtectedPaths.Overrides["shop.example.com"]; !ok {
		t.Errorf("default scope must not touch existing Overrides; map=%+v", n.ProtectedPaths.Overrides)
	}
}

// TestApplyProtectedFormScopedDefaultIgnoresRemove: the default scope cannot
// "remove" from itself -- the protected_remove field must be silently
// ignored so the baseline stays add-only (= invariant from the design doc).
func TestApplyProtectedFormScopedDefaultIgnoresRemove(t *testing.T) {
	n := &settings.Nginx{
		ProtectedPaths: settings.ProtectedPathsConfig{
			Paths: []settings.ProtectedPath{{Path: "/keep/"}},
		},
	}
	body := url.Values{
		"protected_pat":            []string{"/keep/"},
		"protected_remove":         []string{"/keep/", "/also/"},
		"protected_default_action": []string{"pow_then_captcha"},
	}
	r := formReq(t, body.Encode())
	if err := applyProtectedFormScoped(n, r, i18n.LangEN, ""); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(n.ProtectedPaths.Paths) != 1 || n.ProtectedPaths.Paths[0].Path != "/keep/" {
		t.Errorf("default scope must preserve /keep/; paths=%+v", n.ProtectedPaths.Paths)
	}
	// The default scope has no Overrides[<scope>] write path; nothing should
	// leak into a "" key either.
	if _, ok := n.ProtectedPaths.Overrides[""]; ok {
		t.Errorf("default scope must not create an Overrides[\"\"] entry")
	}
}

// TestApplyProtectedFormScopedSiteCreate: site scope writes the Append +
// Remove + DefaultAction fields into Overrides[scope].  Empty DefaultAction
// stays empty (= inherits).  Remove entries that do not match a default-
// scope canonical path are dropped silently (= stale removes can't grow
// just because the operator hand-edited the YAML before).
func TestApplyProtectedFormScopedSiteCreate(t *testing.T) {
	n := &settings.Nginx{
		ProtectedPaths: settings.ProtectedPathsConfig{
			Paths: []settings.ProtectedPath{
				{Path: "/admin/"},
				{Path: "/login/"},
				{Path: "/secret/"},
			},
		},
	}
	body := url.Values{
		// Append: one new row for this site.
		"protected_pat":          []string{"^/shop-admin/"},
		"protected_title":        []string{"shop admin"},
		"protected_enabled":      []string{"1"},
		"protected_updated_at":   []string{"0"},
		"protected_extra_action": []string{"inherit"},
		// Remove: drop two of the three default rows, plus a stale entry
		// that no longer exists in the default -- the handler must skip it.
		"protected_remove": []string{"/admin/", "/login/", "/ancient/"},
		// Override the per-site default action.
		"protected_default_action": []string{"deny"},
	}
	r := formReq(t, body.Encode())
	if err := applyProtectedFormScoped(n, r, i18n.LangEN, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(n.ProtectedPaths.Paths) != 3 {
		t.Errorf("site scope must not touch baseline Paths; got %d rows", len(n.ProtectedPaths.Paths))
	}
	ov, ok := n.ProtectedPaths.Overrides["shop.example.com"]
	if !ok {
		t.Fatalf("Overrides[shop.example.com] missing")
	}
	if len(ov.Append) != 1 || ov.Append[0].Path != "^/shop-admin/" {
		t.Errorf("Append wrong: %+v", ov.Append)
	}
	if len(ov.Remove) != 2 || ov.Remove[0] != "/admin/" || ov.Remove[1] != "/login/" {
		t.Errorf("Remove wrong: %+v (stale /ancient/ must be dropped)", ov.Remove)
	}
	if ov.DefaultAction != "deny" {
		t.Errorf("DefaultAction = %q, want deny", ov.DefaultAction)
	}
}

// TestApplyProtectedFormScopedSiteAllBlankDrops: an override that ends up
// with no append rows + no remove entries + empty DefaultAction + no
// EnabledPresets override must be deleted from the Overrides map so the
// YAML stays compact.
func TestApplyProtectedFormScopedSiteAllBlankDrops(t *testing.T) {
	n := &settings.Nginx{
		ProtectedPaths: settings.ProtectedPathsConfig{
			Paths: []settings.ProtectedPath{{Path: "/admin/"}},
			Overrides: map[string]settings.ProtectedPathsOverride{
				"shop.example.com": {Append: []settings.ProtectedPath{{Path: "/old/"}}},
				"blog.example.com": {DefaultAction: "deny"},
			},
		},
	}
	body := url.Values{
		// No append rows (pattern is empty -> skipped), no remove ticks,
		// no DefaultAction override (= "inherit" sentinel).
		"protected_pat":            []string{""},
		"protected_remove":         []string{},
		"protected_default_action": []string{"inherit"},
	}
	r := formReq(t, body.Encode())
	if err := applyProtectedFormScoped(n, r, i18n.LangEN, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := n.ProtectedPaths.Overrides["shop.example.com"]; ok {
		t.Errorf("all-blank site scope must delete the override; map=%+v", n.ProtectedPaths.Overrides)
	}
	if _, ok := n.ProtectedPaths.Overrides["blog.example.com"]; !ok {
		t.Errorf("sibling override must survive; map=%+v", n.ProtectedPaths.Overrides)
	}
}

// TestApplyProtectedFormScopedReset: reset_protected=1 drops the site's
// entry regardless of the rest of the form payload, and leaves siblings
// untouched.
func TestApplyProtectedFormScopedReset(t *testing.T) {
	n := &settings.Nginx{
		ProtectedPaths: settings.ProtectedPathsConfig{
			Paths: []settings.ProtectedPath{{Path: "/admin/"}},
			Overrides: map[string]settings.ProtectedPathsOverride{
				"shop.example.com": {Append: []settings.ProtectedPath{{Path: "/extra/"}}},
				"blog.example.com": {DefaultAction: "deny"},
			},
		},
	}
	body := url.Values{
		// Form carries a row + remove; the reset flag must short-circuit.
		"protected_pat":            []string{"^/will-be-ignored/"},
		"protected_remove":         []string{"/admin/"},
		"protected_default_action": []string{"deny"},
		"reset_protected":          []string{"1"},
	}
	r := formReq(t, body.Encode())
	if err := applyProtectedFormScoped(n, r, i18n.LangEN, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := n.ProtectedPaths.Overrides["shop.example.com"]; ok {
		t.Errorf("reset must drop the site entry; map=%+v", n.ProtectedPaths.Overrides)
	}
	if _, ok := n.ProtectedPaths.Overrides["blog.example.com"]; !ok {
		t.Errorf("reset must not touch sibling overrides; map=%+v", n.ProtectedPaths.Overrides)
	}
	if len(n.ProtectedPaths.Paths) != 1 {
		t.Errorf("reset must not touch baseline Paths; got %d rows", len(n.ProtectedPaths.Paths))
	}
}

// TestApplyBypassPathsFormScopedDefault: parity with the protected default-
// scope test -- the empty-scope path delegates to the legacy decoder and
// rewrites the baseline list.
func TestApplyBypassPathsFormScopedDefault(t *testing.T) {
	n := &settings.Nginx{
		BypassPaths: settings.BypassPathsConfig{
			Paths: []settings.BypassPath{{Path: "^/old/"}},
			Overrides: map[string]settings.BypassPathsOverride{
				"shop.example.com": {Append: []settings.BypassPath{{Path: "^/shop-extra/"}}},
			},
		},
	}
	body := url.Values{
		"bp_pat":        []string{"^/static/"},
		"bp_title":      []string{"static"},
		"bp_enabled":    []string{"1"},
		"bp_updated_at": []string{"0"},
	}
	r := formReq(t, body.Encode())
	if err := applyBypassPathsFormScoped(n, r, i18n.LangEN, ""); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(n.BypassPaths.Paths) != 1 || n.BypassPaths.Paths[0].Path != "^/static/" {
		t.Errorf("default scope did not rewrite Paths verbatim: %+v", n.BypassPaths.Paths)
	}
	if _, ok := n.BypassPaths.Overrides["shop.example.com"]; !ok {
		t.Errorf("default scope must not touch existing Overrides; map=%+v", n.BypassPaths.Overrides)
	}
}

// TestApplyBypassPathsFormScopedSiteCreate: site scope writes Append +
// Remove into Overrides[scope].  Empty Append rows are skipped; stale
// removes are dropped.
func TestApplyBypassPathsFormScopedSiteCreate(t *testing.T) {
	n := &settings.Nginx{
		BypassPaths: settings.BypassPathsConfig{
			Paths: []settings.BypassPath{
				{Path: "^/static/"},
				{Path: "^/health"},
			},
		},
	}
	body := url.Values{
		"bp_pat":        []string{"^/shop-static/"},
		"bp_title":      []string{"shop static"},
		"bp_enabled":    []string{"1"},
		"bp_updated_at": []string{"0"},
		"bp_remove":     []string{"^/static/", "^/never-existed/"},
	}
	r := formReq(t, body.Encode())
	if err := applyBypassPathsFormScoped(n, r, i18n.LangEN, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if len(n.BypassPaths.Paths) != 2 {
		t.Errorf("site scope must not touch baseline Paths; got %d rows", len(n.BypassPaths.Paths))
	}
	ov, ok := n.BypassPaths.Overrides["shop.example.com"]
	if !ok {
		t.Fatalf("Overrides[shop.example.com] missing")
	}
	if len(ov.Append) != 1 || ov.Append[0].Path != "^/shop-static/" {
		t.Errorf("Append wrong: %+v", ov.Append)
	}
	if len(ov.Remove) != 1 || ov.Remove[0] != "^/static/" {
		t.Errorf("Remove wrong (stale entry should be dropped): %+v", ov.Remove)
	}
}

// TestApplyBypassPathsFormScopedSiteAllBlankDrops: empty appends + empty
// remove + no preset override -> the entry is deleted from the map.
func TestApplyBypassPathsFormScopedSiteAllBlankDrops(t *testing.T) {
	n := &settings.Nginx{
		BypassPaths: settings.BypassPathsConfig{
			Paths: []settings.BypassPath{{Path: "^/static/"}},
			Overrides: map[string]settings.BypassPathsOverride{
				"shop.example.com": {Append: []settings.BypassPath{{Path: "^/extra/"}}},
			},
		},
	}
	body := url.Values{
		"bp_pat":    []string{""},
		"bp_remove": []string{},
	}
	r := formReq(t, body.Encode())
	if err := applyBypassPathsFormScoped(n, r, i18n.LangEN, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := n.BypassPaths.Overrides["shop.example.com"]; ok {
		t.Errorf("all-blank site scope must delete the override; map=%+v", n.BypassPaths.Overrides)
	}
}

// TestApplyBypassPathsFormScopedReset: reset_bypass_paths=1 drops the
// site's entry regardless of the form payload.
func TestApplyBypassPathsFormScopedReset(t *testing.T) {
	n := &settings.Nginx{
		BypassPaths: settings.BypassPathsConfig{
			Paths: []settings.BypassPath{{Path: "^/static/"}},
			Overrides: map[string]settings.BypassPathsOverride{
				"shop.example.com": {Append: []settings.BypassPath{{Path: "^/extra/"}}},
				"blog.example.com": {Remove: []string{"^/static/"}},
			},
		},
	}
	body := url.Values{
		"bp_pat":             []string{"^/will-be-ignored/"},
		"bp_remove":          []string{"^/static/"},
		"reset_bypass_paths": []string{"1"},
	}
	r := formReq(t, body.Encode())
	if err := applyBypassPathsFormScoped(n, r, i18n.LangEN, "shop.example.com"); err != nil {
		t.Fatalf("apply: %v", err)
	}
	if _, ok := n.BypassPaths.Overrides["shop.example.com"]; ok {
		t.Errorf("reset must drop the site entry; map=%+v", n.BypassPaths.Overrides)
	}
	if _, ok := n.BypassPaths.Overrides["blog.example.com"]; !ok {
		t.Errorf("reset must not touch sibling overrides; map=%+v", n.BypassPaths.Overrides)
	}
}

// TestProtectedPathsOverrideCount / TestBypassPathsOverrideCount: confirm
// the picker badge helpers count every dimension (append + remove +
// EnabledPresets + DefaultAction for protected).
func TestProtectedPathsOverrideCount(t *testing.T) {
	cases := []struct {
		name string
		ov   settings.ProtectedPathsOverride
		want int
	}{
		{"empty", settings.ProtectedPathsOverride{}, 0},
		{"append-only", settings.ProtectedPathsOverride{Append: []settings.ProtectedPath{{Path: "/a/"}, {Path: "/b/"}}}, 2},
		{"remove-only", settings.ProtectedPathsOverride{Remove: []string{"/a/"}}, 1},
		{"default-action-only", settings.ProtectedPathsOverride{DefaultAction: "deny"}, 1},
		{"presets-override", settings.ProtectedPathsOverride{EnabledPresets: &[]string{"unmask"}}, 1},
		{"mixed", settings.ProtectedPathsOverride{
			Append:         []settings.ProtectedPath{{Path: "/a/"}},
			Remove:         []string{"/b/", "/c/"},
			DefaultAction:  "deny",
			EnabledPresets: &[]string{},
		}, 5},
		{"empty-path-in-append-ignored", settings.ProtectedPathsOverride{
			Append: []settings.ProtectedPath{{Path: "  "}, {Path: "/real/"}},
		}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := protectedPathsOverrideCount(tc.ov); got != tc.want {
				t.Errorf("protectedPathsOverrideCount(%+v) = %d, want %d", tc.ov, got, tc.want)
			}
		})
	}
}

func TestBypassPathsOverrideCount(t *testing.T) {
	cases := []struct {
		name string
		ov   settings.BypassPathsOverride
		want int
	}{
		{"empty", settings.BypassPathsOverride{}, 0},
		{"append-only", settings.BypassPathsOverride{Append: []settings.BypassPath{{Path: "/a/"}}}, 1},
		{"remove-only", settings.BypassPathsOverride{Remove: []string{"/a/", "/b/"}}, 2},
		{"presets-override", settings.BypassPathsOverride{EnabledPresets: &[]string{}}, 1},
		{"mixed", settings.BypassPathsOverride{
			Append:         []settings.BypassPath{{Path: "/a/"}},
			Remove:         []string{"/b/"},
			EnabledPresets: &[]string{"static"},
		}, 3},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := bypassPathsOverrideCount(tc.ov); got != tc.want {
				t.Errorf("bypassPathsOverrideCount(%+v) = %d, want %d", tc.ov, got, tc.want)
			}
		})
	}
}

// TestBuildProtectedInheritedRowsRemovedFlag: rows whose path appears in
// the site's Override.Remove must surface Removed=true so the template can
// pre-tick the "remove for this site" checkbox.  Other rows must have
// Removed=false.  Default scope (= site == "") returns nil.
func TestBuildProtectedInheritedRowsRemovedFlag(t *testing.T) {
	cfg := settings.ProtectedPathsConfig{
		Paths: []settings.ProtectedPath{
			{Path: "/admin/"},
			{Path: "/login/"},
			{Path: "/secret/"},
		},
		Overrides: map[string]settings.ProtectedPathsOverride{
			"shop.example.com": {Remove: []string{"/login/"}},
		},
	}
	if rows := buildProtectedInheritedRows(cfg, ""); rows != nil {
		t.Errorf("default scope must return nil; got %+v", rows)
	}
	rows := buildProtectedInheritedRows(cfg, "shop.example.com")
	if len(rows) != 3 {
		t.Fatalf("inherited rows: got %d, want 3", len(rows))
	}
	for _, r := range rows {
		switch r.Pattern {
		case "/login/":
			if !r.Removed {
				t.Errorf("/login/ should be Removed=true")
			}
		default:
			if r.Removed {
				t.Errorf("%q should be Removed=false; got true", r.Pattern)
			}
		}
	}
}
