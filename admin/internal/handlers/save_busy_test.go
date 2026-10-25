package handlers

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// postForm finds a form that posts in a page template.
var postForm = regexp.MustCompile(`(?i)<form[^>]*method="post"`)

// TestSaveBusyOnEveryPostingPage: a button that sent a form spins until the
// next page (partial_busy.html).  header_tools carries the shim; a page that
// posts a form without header_tools must include it itself, so a new such
// page fails here and not with a save button that gives no sign.
func TestSaveBusyOnEveryPostingPage(t *testing.T) {
	ht, err := fs.ReadFile(assets.Templates, "templates/partial_header_tools.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(ht), `{{ template "init_busy" . }}`) {
		t.Fatal("header_tools does not include init_busy")
	}
	entries, err := fs.ReadDir(assets.Templates, "templates")
	if err != nil {
		t.Fatal(err)
	}
	pages, own := 0, 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".html") || strings.HasPrefix(name, "partial_") {
			continue
		}
		b, err := fs.ReadFile(assets.Templates, "templates/"+name)
		if err != nil {
			t.Fatal(err)
		}
		src := string(b)
		if !postForm.MatchString(src) {
			continue
		}
		pages++
		switch {
		case strings.Contains(src, `{{ template "header_tools" . }}`):
		case strings.Contains(src, `{{ template "init_busy" . }}`):
			own++
		default:
			t.Errorf("%s posts a form but has neither header_tools nor init_busy: its buttons would not say they were pressed", name)
		}
	}
	if pages < 10 || own < 5 {
		t.Fatalf("%d posting pages, %d with their own include; the scan is looking at the wrong thing", pages, own)
	}
}

// TestSaveBusyOnTheSettingsPage: the shim and its spinner reach a rendered
// page, and the settings page's fetch saves go through it.
func TestSaveBusyOnTheSettingsPage(t *testing.T) {
	h := vacuumHandler(t, 10)
	body := renderTab(t, h, "sites", user.RoleSuperadmin, "en")
	for _, w := range []string{"window.unmaskBusy", "@keyframes ux-busy-spin", "unmaskBusy.on(btn)"} {
		if !strings.Contains(body, w) {
			t.Errorf("the settings page lacks %q", w)
		}
	}
}
