package handlers

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/renderwatch"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// moduleBehind: a module file placed three minutes ago whose id nginx has
// not logged -- what a plugin upgrade leaves until nginx restarts.  Returns
// the file's own id, for the line that ends it.
func moduleBehind(t *testing.T, h *Handler) string {
	t.Helper()
	so := filepath.Join(t.TempDir(), "ngx_http_unmask_module.so")
	if err := os.WriteFile(so, []byte("a module nginx has not loaded"), 0o755); err != nil {
		t.Fatal(err)
	}
	placed := time.Now().Add(-3 * time.Minute)
	if err := os.Chtimes(so, placed, placed); err != nil {
		t.Fatal(err)
	}
	onDisk, _ := renderwatch.ModuleIDOnDisk(so)
	h.RenderWatch.SetModulePath(func() string { return so })
	h.RenderWatch.SawModule("0123456789abcdef", placed.Add(2*time.Minute))
	return onDisk
}

// TestRestartNoticeWhenTheModuleIsBehind: a module file newer than the one
// nginx logs is a notice on every page that asks for a restart, not a
// reload -- on its own when the configuration is current, and in place of
// the reload command when a render waits too -- and once nginx logs the
// file's id, no page says so.
func TestRestartNoticeWhenTheModuleIsBehind(t *testing.T) {
	restart := nginxRestartCommand()
	if !strings.HasSuffix(restart, "restart nginx") {
		t.Fatalf("restart command %q", restart)
	}

	// The configuration is current (nginx logs its id), the module is not.
	h, id, written := reloadHandler(t)
	h.RenderWatch.Saw(id, written.Add(2*time.Second))
	onDisk := moduleBehind(t, h)
	for path, fn := range pagesWithTheHeader(h) {
		for _, lang := range []string{"ja", "en"} {
			notice := noticeOf(renderAs(t, fn, path, user.RoleSuperadmin, lang))
			if notice == "" {
				t.Errorf("%s (%s): no notice while the module on disk is newer than the one nginx runs", path, lang)
				continue
			}
			if !strings.Contains(notice, restart) {
				t.Errorf("%s (%s): the help does not name the restart (%s)", path, lang, restart)
			}
			if strings.Contains(notice, "nginx -s reload") {
				t.Errorf("%s (%s): the help still offers a reload, which keeps the old module", path, lang)
			}
		}
	}
	if ja := noticeOf(renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleSuperadmin, "ja")); !strings.Contains(ja, "前のモジュールで動いています") {
		t.Error("with the configuration current, the notice must say the module alone is behind")
	}
	// nginx restarted: it logs the file on disk, and the notice goes.
	h.RenderWatch.SawModule(onDisk, time.Now())
	if body := renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleSuperadmin, "en"); strings.Contains(body, "rlnote") {
		t.Error("nginx logs the module on disk, yet a notice remains")
	}

	// A render waiting as well: the configuration's own message, with the
	// restart in place of the reload it would otherwise offer.
	h2, _, written2 := reloadHandler(t)
	h2.RenderWatch.Saw("ffffffffffff", written2.Add(2*time.Minute))
	moduleBehind(t, h2)
	notice := noticeOf(renderAs(t, h2.AdminTopOverview, "/unmask/admin/", user.RoleSuperadmin, "ja"))
	if !strings.Contains(notice, "前の設定で動いています") || !strings.Contains(notice, restart) || strings.Contains(notice, "nginx -s reload") {
		t.Error("a waiting render with the module behind must keep the configuration's message and ask for a restart, not a reload")
	}
	// The render alone (the module current) keeps asking for the reload.
	h3, _, written3 := reloadHandler(t)
	h3.RenderWatch.Saw("ffffffffffff", written3.Add(2*time.Minute))
	if notice := noticeOf(renderAs(t, h3.AdminTopOverview, "/unmask/admin/", user.RoleSuperadmin, "en")); !strings.Contains(notice, "nginx -s reload") || strings.Contains(notice, restart) {
		t.Error("a waiting render with no module behind must ask for the reload, as before")
	}
}

// noticeOf: the reload notice's own markup in a page, "" when the page has
// none -- a page may name a reload elsewhere (the hunt page does), so the
// commands are checked inside the notice alone.
func noticeOf(body string) string {
	i := strings.Index(body, `<div id="rlnote"`)
	if i < 0 {
		return ""
	}
	rest := body[i:]
	if j := strings.Index(rest, "</div>"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}
