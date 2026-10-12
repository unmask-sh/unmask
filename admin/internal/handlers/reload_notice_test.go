package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
// the commands that apply it -- and once nginx logs the new one, no page
// does.
func TestReloadNoticeOnEveryPage(t *testing.T) {
	h, id, written := reloadHandler(t)

	// nginx runs a configuration from before render ids: its lines carry none.
	h.RenderWatch.Saw("", written.Add(2*time.Minute))
	for path, fn := range pagesWithTheHeader(h) {
		body := renderAs(t, fn, path, user.RoleViewer, "en")
		if !strings.Contains(body, `id="rlnote"`) || !strings.Contains(body, "nginx is still running the previous configuration") {
			t.Errorf("%s: the reload notice is missing", path)
			continue
		}
		if !strings.Contains(body, "systemctl reload nginx") || strings.Contains(body, "reload_notice.") {
			t.Errorf("%s: the notice lacks the command, or shows a raw key", path)
		}
		if !strings.Contains(body, `<time class="js-datetime" data-ts="`) {
			t.Errorf("%s: the notice does not say when the configuration was written", path)
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
