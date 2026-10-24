package handlers

import (
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/banfile"
	"github.com/unmask-sh/unmask/admin/internal/user"
)

// TestBanFileNoticeOnEveryPage: while nginx's worker cannot read the ban
// list, every page says so -- who cannot read what -- in the operator's
// language, with the cause and the commands that fix it behind the pages'
// shared help tip, each command with its copy button; and once the worker
// reads it, no page does.
func TestBanFileNoticeOnEveryPage(t *testing.T) {
	h := installedHandler(t)
	s := *h.cfg()
	s.Server.BasePath = "/unmask"
	s.Nginx.Honeypot.BanFilePath = "/var/lib/unmask/nginx/banned.txt"
	h.SetSettings(s)
	h.BanFileCheck = func() banfile.Verdict {
		return banfile.Verdict{User: "nginx", Source: "nginx.conf", Blocker: "/var/lib/unmask", Need: "x"}
	}
	for path, fn := range pagesWithTheHeader(h) {
		body := renderAs(t, fn, path, user.RoleViewer, "en")
		at := strings.Index(body, `id="bfnote"`)
		if at < 0 || !strings.Contains(body, "nginx&#39;s worker (user nginx) cannot read the ban list /var/lib/unmask/nginx/banned.txt, so nginx enforces no ban.") {
			t.Errorf("%s: the ban-list notice is missing", path)
			continue
		}
		notice := body[at:]
		if end := strings.Index(notice, "</div>"); end >= 0 {
			notice = notice[:end]
		}
		for _, want := range []string{
			"cannot pass through /var/lib/unmask (no x for others)",
			// html/template writes + as &#43; in text; the copy button reads it back as +.
			`<code class="cmd">sudo chmod o&#43;x /var/lib/unmask</code>`,
			"on the next request (no reload)",
			`class="info-tip"`, `class="info-popup"`, `data-pin-title="nginx enforces no ban"`,
		} {
			if !strings.Contains(notice, want) {
				t.Errorf("%s: the notice lacks %q", path, want)
			}
		}
		if strings.Contains(notice, "ban_file_notice.") {
			t.Errorf("%s: the notice shows a raw key", path)
		}
	}
	ja := renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleSuperadmin, "ja")
	if !strings.Contains(ja, "nginx では BAN が効いていません") {
		t.Error("ja: the notice is not in Japanese")
	}

	// A file the worker cannot read names the file and asks for r.
	h.BanFileCheck = func() banfile.Verdict {
		return banfile.Verdict{User: "www-data", Source: "nginx.conf", Blocker: "/var/lib/unmask/nginx/banned.txt", Need: "r"}
	}
	h.banFileAt = time.Time{}
	body := renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleSuperadmin, "en")
	if !strings.Contains(body, "cannot read /var/lib/unmask/nginx/banned.txt (no r for others)") ||
		!strings.Contains(body, `<code class="cmd">sudo chmod o&#43;r /var/lib/unmask/nginx/banned.txt</code>`) {
		t.Error("a file the worker cannot read must be named with the r fix")
	}

	// The worker reads the list: no page says anything.
	h.BanFileCheck = func() banfile.Verdict { return banfile.Verdict{OK: true, User: "nginx"} }
	h.banFileAt = time.Time{}
	for path, fn := range pagesWithTheHeader(h) {
		if body := renderAs(t, fn, path, user.RoleSuperadmin, "en"); strings.Contains(body, "bfnote") {
			t.Errorf("%s: carries the ban-list notice although the worker reads the list", path)
		}
	}
}

// TestNoBanFileNoticeWithoutAList: an install with no ban list written (no
// ban yet, a test instance) says nothing, whatever nginx.conf says.
func TestNoBanFileNoticeWithoutAList(t *testing.T) {
	h := installedHandler(t)
	s := *h.cfg()
	s.Server.BasePath = "/unmask"
	s.Nginx.Honeypot.BanFilePath = "/nonexistent/unmask/banned.txt"
	h.SetSettings(s)
	body := renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleSuperadmin, "en")
	if strings.Contains(body, "bfnote") {
		t.Error("a notice without a list to read")
	}
}
