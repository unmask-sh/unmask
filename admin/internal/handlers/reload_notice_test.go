package handlers

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/assets"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/renderwatch"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// reloadHandler: an installed handler whose render watch looks at a real
// render in a scratch dir.  It returns the id that render wrote and when.
func reloadHandler(t *testing.T) (*Handler, string, time.Time) {
	t.Helper()
	h := installedHandler(t)
	dir := t.TempDir()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := *h.cfg()
	s.Server.BasePath = "/unmask"
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	h.SetSettings(s)
	if err := nginxconf.Render(s, dir, "test"); err != nil {
		t.Fatal(err)
	}
	id, written := nginxconf.RenderIDOnDisk(dir)
	if id == "" {
		t.Fatal("the render wrote no id")
	}
	h.RenderWatch = renderwatch.New(func() string { return dir })
	return h, id, written
}

// TestReloadNoticeOnEveryPage: while nginx logs an older configuration than
// the one written, every page says so -- in the operator's language, with
// the commands that apply it behind the pages' shared help tip, which pins,
// and the popover assets that tip needs linked on the page -- and once nginx
// logs the new one, no page does.
func TestReloadNoticeOnEveryPage(t *testing.T) {
	h, id, written := reloadHandler(t)

	// nginx runs a configuration from before render ids: its lines carry none.
	h.RenderWatch.Saw("", written.Add(2*time.Minute))
	for path, fn := range pagesWithTheHeader(h) {
		body := renderAs(t, fn, path, user.RoleViewer, "en")
		at := strings.Index(body, `id="rlnote"`)
		if at < 0 || !strings.Contains(body, "nginx is still running the previous configuration") {
			t.Errorf("%s: the reload notice is missing", path)
			continue
		}
		notice := body[at:]
		if end := strings.Index(notice, "</div>"); end >= 0 {
			notice = notice[:end]
		}
		if !strings.Contains(notice, "nginx -t &amp;&amp; sudo nginx -s reload") || strings.Contains(notice, "reload_notice.") {
			t.Errorf("%s: the notice lacks the command, or shows a raw key", path)
		}
		if !strings.Contains(notice, `<time class="js-datetime" data-ts="`) {
			t.Errorf("%s: the notice does not say when the configuration was written", path)
		}
		// The "?" is the shared help tip: hover opens it, a click pins it as
		// a window the command is copied from, titled by the tip itself (it
		// sits in no heading or label a title would be read from).
		if !strings.Contains(notice, `class="info-tip"`) || !strings.Contains(notice, `class="info-popup"`) ||
			!strings.Contains(notice, `data-pin-title="nginx is still running the previous configuration"`) {
			t.Errorf("%s: the notice's help is not the shared, pinnable tip", path)
		}
		// The tip opens and pins through the popover assets, which the page
		// links with the build stamp like every page that has tips.
		for _, asset := range []string{"popover-pin.css", "popover-pin.js"} {
			if !strings.Contains(body, asset+"?v=") {
				t.Errorf("%s: the page does not link %s, which the notice's help tip opens and pins with", path, asset)
			}
		}
	}
	ja := renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleSuperadmin, "ja")
	if !strings.Contains(ja, "nginx がまだ前の設定で動いています") {
		t.Error("ja: the notice is not in Japanese")
	}

	// The reload: nginx logs the configuration on disk.
	h.RenderWatch.Saw(id, written.Add(3*time.Minute))
	for path, fn := range pagesWithTheHeader(h) {
		if body := renderAs(t, fn, path, user.RoleSuperadmin, "en"); strings.Contains(body, "rlnote") {
			t.Errorf("%s: still carries the reload notice after nginx logged the current configuration", path)
		}
	}
}

// TestReloadNoticeHelpIsPinnableOnEveryPage: the notice rides with the header
// onto every signed-in page, and its help tip opens and pins through
// popover-pin.css and .js, so every page template with the header links the
// popover assets.  The test above renders a handful of pages; this reads
// every page template, so a page added without the assets fails here and not
// in front of an operator whose "?" opens nothing.
func TestReloadNoticeHelpIsPinnableOnEveryPage(t *testing.T) {
	entries, err := fs.ReadDir(assets.Templates, "templates")
	if err != nil {
		t.Fatal(err)
	}
	pages := 0
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
		if !strings.Contains(src, `{{ template "header_tools" . }}`) {
			continue
		}
		pages++
		if !strings.Contains(src, `{{ template "popover_pin_assets" . }}`) {
			t.Errorf("%s has the header, and with it the reload notice, but not the popover assets its help tip opens and pins with", name)
		}
	}
	if pages < 10 {
		t.Fatalf("%d page templates carry the header; the scan is looking at the wrong thing", pages)
	}
}

// TestNoReloadNoticeWithoutEvidence: no access-log lines (a forward-auth
// install, or no traffic yet) and no render watch at all both mean no
// notice -- silence is not a claim that nginx is behind.
func TestNoReloadNoticeWithoutEvidence(t *testing.T) {
	h, _, _ := reloadHandler(t)
	for path, fn := range pagesWithTheHeader(h) {
		if body := renderAs(t, fn, path, user.RoleSuperadmin, "en"); strings.Contains(body, "rlnote") {
			t.Errorf("%s: a reload notice with no access-log line seen", path)
		}
	}
	h.RenderWatch = nil
	if body := renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleSuperadmin, "en"); strings.Contains(body, "rlnote") {
		t.Error("a reload notice with no render watch")
	}
}
