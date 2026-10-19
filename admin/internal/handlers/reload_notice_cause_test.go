package handlers

import (
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/renderwatch"
	"github.com/unmask-sh/unmask/admin/internal/settings"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// The notice says why the waiting configuration was written -- an automatic
// update, a save on a named tab -- and, behind the tip, what moved.
func TestReloadNoticeNamesTheCause(t *testing.T) {
	h, id, _ := reloadHandler(t)
	s := *h.cfg()
	dir := s.Nginx.OutputDir
	notice := func() string {
		t.Helper()
		for path, fn := range pagesWithTheHeader(h) {
			body := renderAs(t, fn, path, user.RoleViewer, "en")
			at := strings.Index(body, `id="rlnote"`)
			if at < 0 {
				t.Fatalf("%s: no notice", path)
			}
			n := body[at:]
			if end := strings.Index(n, "</script>"); end >= 0 {
				n = n[:end]
			}
			return n
		}
		return ""
	}
	rule := func(cidr string) {
		s.Nginx.CustomRules = []settings.CustomRule{{ID: "cr1", Label: "x", Enabled: true, Action: "captcha_only",
			Conditions: []settings.CustomCondition{{Kind: "ip", Values: []string{cidr}}}}}
		h.SetSettings(s)
	}

	// The relay list's sync re-rendered: the notice says so, and what moved.
	rule("203.0.113.0/24")
	if err := nginxconf.RenderFor(s, dir, "test", nginxconf.RenderCause{Kind: nginxconf.RenderByIPRange, Detail: "relay"}); err != nil {
		t.Fatal(err)
	}
	id2, written := nginxconf.RenderIDOnDisk(dir)
	h.RenderWatch = renderwatch.New(func() string { return dir }) // reads the new render now (the watch re-stats every few seconds)
	h.RenderWatch.Saw(id, written.Add(2*time.Minute))             // nginx still logs the first render
	n := notice()
	for _, want := range []string{"The automatic update at", "IP range sync: the relay egress list", "What changed", "custom rules:"} {
		if !strings.Contains(n, want) {
			t.Errorf("the notice lacks %q:\n%s", want, n)
		}
	}
	if strings.Contains(n, "reload_notice.") || strings.Contains(n, "%s") {
		t.Errorf("the notice shows a raw key or verb:\n%s", n)
	}

	// A save names its tab.
	rule("198.51.100.0/24")
	if err := nginxconf.RenderFor(s, dir, "test", nginxconf.RenderCause{Kind: nginxconf.RenderBySettings, Detail: "custom-rules-add"}); err != nil {
		t.Fatal(err)
	}
	_, written = nginxconf.RenderIDOnDisk(dir)
	h.RenderWatch = renderwatch.New(func() string { return dir })
	h.RenderWatch.Saw(id2, written.Add(2*time.Minute))
	n = notice()
	tab := i18n.T("en", "settings.tab.custom_rules")
	for _, want := range []string{"the settings saved at", "(" + tab + ")", "custom rules:"} {
		if !strings.Contains(n, want) {
			t.Errorf("the notice lacks %q:\n%s", want, n)
		}
	}
}
