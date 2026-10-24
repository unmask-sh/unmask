package handlers

import (
	"bytes"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/dashboard"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// A path on the stats page has to say which host it belongs to.
//
// The default view is not one site: site="default" means "no site filter" in
// the SQL, so the tables span every host the install serves -- and a bare
// "/article/detail/1" then names a path on nobody's server in particular.  The
// row also has to carry enough to build the address, so the popover can offer
// the same Open / Copy the hunt table does.
func TestStatsPathCellsCarryTheirHost(t *testing.T) {
	tpl, err := loadDashboardTemplate()
	if err != nil {
		t.Fatal(err)
	}
	render := func(site string, ghost bool) string {
		var buf bytes.Buffer
		data := map[string]any{
			"Lang": i18n.LangJA, "Site": site, "BasePath": "/unmask",
			// The page's ghost set: the host is a ghost when the test says so.
			"GhostSites": map[string]bool{"codezine.jp": ghost},
			"CaptchaReport": map[string]any{
				"Total": 1, "Bot": 1, "Ok": 0, "TopIPs": []any{}, "ByReason": []any{},
				"Recent": []dashboard.CaptchaPassRow{{
					Date: "2026-08-07 00:00:00", IP: "203.0.113.5", Path: "/article/detail/1",
					UA: "curl/8.0", UAFull: "curl/8.0",
					Site: "codezine.jp", Scheme: "https", Port: 443,
				}},
			},
		}
		if err := tpl.ExecuteTemplate(&buf, "captcha_report_card", data); err != nil {
			t.Fatalf("render: %v", err)
		}
		return buf.String()
	}

	// "" is the site picker's "all sites", which is what the stats page
	// actually passes -- the "default" in the URL path is not the value the
	// template sees, and comparing against it silently hid the badge on every
	// row of the view that needs it most.
	out := render("", false)
	for _, want := range []string{
		`data-site="codezine.jp"`,       // the host the request was made on
		`data-scheme="https"`,           // and how to reach it
		`data-port="443"`,               //
		`data-path="/article/detail/1"`, // the path alone, so the popover does not
		// read the badge text back as part of the URL
		`class="cp-site">codezine.jp<`, // visible without opening anything
		`cellpop url`,                  // opens the popover with Open / Copy
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the path cell is missing %s", want)
		}
	}

	// Narrowed to one site, the badge would repeat the page heading on every
	// row.  The data attributes stay -- the popover still builds the URL.
	out = render("codezine.jp", false)
	if strings.Contains(out, `class="cp-site"`) {
		t.Error("a single-site view must not repeat the host on every row")
	}
	if !strings.Contains(out, `data-site="codezine.jp"`) {
		t.Error("the row must still carry its host, or the popover cannot build a URL")
	}

	// A host that is not a defined site is coloured as the hunt's rows colour
	// it, so a spoofed Host or an unregistered vhost stands out here too.
	out = render("", true)
	if !strings.Contains(out, `class="cp-site cp-ghost">codezine.jp<`) {
		t.Error("a ghost host must carry the cp-ghost class on its badge")
	}
}
