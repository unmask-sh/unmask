package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/user"
)

// The top nav (partial_nav.html) offers an account the pages its role can
// open.  An administrator gets the five entries; a viewer gets the dashboard,
// the statistics and bot hunt (which it reads) -- the BAN pages and the
// settings refuse the role, and an entry that answers "forbidden" is not
// offered.  The mark of the page's own entry follows the request path.

func navHandler(t *testing.T) *Handler {
	t.Helper()
	h := installedHandler(t)
	st := *h.cfg()
	st.Server.BasePath = "/unmask"
	h.SetSettings(st)
	return h
}

// navOf cuts the top nav out of a rendered page.
func navOf(t *testing.T, body, path string) string {
	t.Helper()
	i := strings.Index(body, `<nav class="nav">`)
	if i < 0 {
		t.Fatalf("%s: no top nav", path)
	}
	j := strings.Index(body[i:], "</nav>")
	if j < 0 {
		t.Fatalf("%s: the top nav is not closed", path)
	}
	return body[i : i+j]
}

func TestNavOffersWhatTheRoleCanOpen(t *testing.T) {
	h := navHandler(t)
	pages := pagesWithTheHeader(h)
	pages["/unmask/admin/live/"] = h.AdminLive
	pages["/unmask/admin/profile/"] = h.AdminProfileIndex
	pages["/unmask/admin/stats/?list=1"] = h.AdminSiteList // the site list, beside a site's statistics
	all := []string{`href="/unmask/admin/"`, `href="/unmask/admin/stats/"`, `href="/unmask/admin/hunt/"`, `href="/unmask/admin/bans/"`, `href="/unmask/admin/settings/"`}
	for path, fn := range pages {
		nav := navOf(t, renderAs(t, fn, path, user.RoleAdmin, "en"), path)
		for _, want := range all {
			if !strings.Contains(nav, want) {
				t.Errorf("%s: an administrator's nav lacks %s: %s", path, want, nav)
			}
		}
		nav = navOf(t, renderAs(t, fn, path, user.RoleViewer, "en"), path)
		for _, want := range all[:3] {
			if !strings.Contains(nav, want) {
				t.Errorf("%s: a viewer's nav lacks %s: %s", path, want, nav)
			}
		}
		for _, gone := range all[3:] {
			if strings.Contains(nav, gone) {
				t.Errorf("%s: a viewer's nav offers %s, a page the role cannot open", path, gone)
			}
		}
		if n := strings.Count(nav, "<a "); n != 3 {
			t.Errorf("%s: a viewer's nav has %d entries, want 3: %s", path, n, nav)
		}
	}
}

// TestNavMarksThePage: the active entry is the page's -- the live view
// under the dashboard, the advisor's candidates under BAN, a site's
// statistics under the statistics -- and pages with no entry mark none.
func TestNavMarksThePage(t *testing.T) {
	h := navHandler(t)
	pages := pagesWithTheHeader(h)
	pages["/unmask/admin/live/"] = h.AdminLive
	pages["/unmask/admin/profile/"] = h.AdminProfileIndex
	pages["/unmask/admin/stats/?list=1"] = h.AdminSiteList // the site list, beside a site's statistics
	active := map[string]string{
		"/unmask/admin/":              `href="/unmask/admin/" class="active"`,
		"/unmask/admin/live/":         `href="/unmask/admin/" class="active"`,
		"/unmask/admin/stats/":        `href="/unmask/admin/stats/" class="active"`,
		"/unmask/admin/stats/?list=1": `href="/unmask/admin/stats/" class="active"`,
		"/unmask/admin/hunt/":         `href="/unmask/admin/hunt/" class="active"`,
		"/unmask/admin/bans/":         `href="/unmask/admin/bans/" class="active"`,
		"/unmask/admin/settings/":     `href="/unmask/admin/settings/" class="active"`,
		"/unmask/admin/audit/":        "",
		"/unmask/admin/users/":        "",
		"/unmask/admin/profile/":      "",
	}
	for path, fn := range pages {
		want, known := active[path]
		if !known {
			t.Fatalf("%s: no expectation for this page", path)
		}
		nav := navOf(t, renderAs(t, fn, path, user.RoleSuperadmin, "en"), path)
		if want == "" {
			if strings.Contains(nav, `class="active"`) {
				t.Errorf("%s: an entry is marked on a page with none: %s", path, nav)
			}
			continue
		}
		if !strings.Contains(nav, want) || strings.Count(nav, `class="active"`) != 1 {
			t.Errorf("%s: want the one mark %s: %s", path, want, nav)
		}
	}
}

func TestNavActive(t *testing.T) {
	for path, want := range map[string]string{
		"/unmask/admin/":                        "dashboard",
		"/admin/":                               "dashboard",
		"/unmask/admin/live/":                   "dashboard",
		"/unmask/admin/stats/":                  "stats",
		"/unmask/admin/stats/blog/":             "stats",
		"/unmask/admin/hunt/":                   "hunt",
		"/unmask/admin/bans/":                   "bans",
		"/unmask/admin/advisor/":                "bans",
		"/unmask/admin/community-bans/":         "bans",
		"/unmask/admin/community-bans/removals": "bans",
		"/unmask/admin/settings/":               "settings",
		"/unmask/admin/settings/rate-limit/":    "settings",
		"/unmask/admin/audit/":                  "",
		"/unmask/admin/notices/":                "",
		"/unmask/admin/ask/":                    "",
		"/unmask/admin/users/":                  "",
		"/unmask/admin/profile/":                "",
		"/unmask/admin/playground/":             "",
		"/unmask/administration/":               "",
		"/unmask/challenge/":                    "",
	} {
		if got := navActive(path); got != want {
			t.Errorf("navActive(%q) = %q, want %q", path, got, want)
		}
	}
}

// TestOverviewShortcutsFollowTheRole: the dashboard's shortcut tiles to BAN
// management and the settings are drawn for an administrator and not for a
// viewer, who keeps the statistics, bot hunt, the community feed and the
// documentation.
func TestOverviewShortcutsFollowTheRole(t *testing.T) {
	h := navHandler(t)
	tile := func(href string) string { return `class="shortcut" href="` + href + `"` }
	admin := renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleAdmin, "en")
	for _, href := range []string{"/unmask/admin/stats/", "/unmask/admin/hunt/", "/unmask/admin/bans/", "/unmask/admin/community-bans/", "/unmask/admin/settings/"} {
		if !strings.Contains(admin, tile(href)) {
			t.Errorf("administrator: no tile to %s", href)
		}
	}
	viewer := renderAs(t, h.AdminTopOverview, "/unmask/admin/", user.RoleViewer, "en")
	for _, href := range []string{"/unmask/admin/stats/", "/unmask/admin/hunt/", "/unmask/admin/community-bans/"} {
		if !strings.Contains(viewer, tile(href)) {
			t.Errorf("viewer: no tile to %s", href)
		}
	}
	for _, href := range []string{"/unmask/admin/bans/", "/unmask/admin/settings/"} {
		if strings.Contains(viewer, tile(href)) {
			t.Errorf("viewer: a tile to %s, a page the role cannot open", href)
		}
	}
	if n, m := strings.Count(admin, `class="shortcut"`), strings.Count(viewer, `class="shortcut"`); n != 6 || m != 4 {
		t.Errorf("tiles: administrator %d (want 6), viewer %d (want 4)", n, m)
	}
	// The reasons card's links follow the same line: the reason's records in
	// bot hunt for every role, the gear to its setting and the sentence that
	// tells of it for an administrator.
	if !strings.Contains(viewer, `href="/unmask/admin/hunt/?range=24h"`) || strings.Contains(viewer, `class="rs-set"`) {
		t.Errorf("viewer: the reasons card's links: hunt %v, gear %v", strings.Contains(viewer, `href="/unmask/admin/hunt/?range=24h"`), strings.Contains(viewer, `class="rs-set"`))
	}
	if !strings.Contains(viewer, "Click a reason to open its records in bot hunt.") || strings.Contains(viewer, "or its ⚙︎ to open where it is set") {
		t.Errorf("viewer: the reasons sentence tells of links the role does not get")
	}
	if !strings.Contains(admin, "or its ⚙︎ to open where it is set") {
		t.Errorf("administrator: the reasons sentence lacks the gear")
	}
}

// TestHuntReadsForEveryRole: bot hunt opens for a viewer as a reading --
// the rankings and the event log without the BAN and rule buttons, which
// post to an action route that takes admin.  An administrator keeps them:
// the event log's actions column, and the way to a custom rule.
func TestHuntReadsForEveryRole(t *testing.T) {
	h := navHandler(t)
	const actions = `/admin/hunt/action`
	viewer := renderAs(t, h.AdminHuntIndex, "/unmask/admin/hunt/?range=24h", user.RoleViewer, "en")
	for _, gone := range []string{actions, `class="rank-act cr-from-filter"`, `<th style="width:4rem"></th>`, `class="js-ban-form"`, `class="js-asn-form"`, `class="js-ua-form"`} {
		if strings.Contains(viewer, gone) {
			t.Errorf("viewer: bot hunt draws %s, a way to an action the role cannot take", gone)
		}
	}
	if !strings.Contains(viewer, `href="/unmask/admin/hunt/" class="active"`) {
		t.Errorf("viewer: the hunt entry is not marked on the hunt page")
	}
	admin := renderAs(t, h.AdminHuntIndex, "/unmask/admin/hunt/?range=24h", user.RoleAdmin, "en")
	if !strings.Contains(admin, `<th style="width:4rem"></th>`) {
		t.Errorf("administrator: the event log lacks its actions column")
	}
}

// TestBanTabsFollowTheRole: on the community feed, which a viewer can open,
// the tabs to the BAN list and the advisor's candidates (admin pages) are
// drawn only for an account that can open them.
func TestBanTabsFollowTheRole(t *testing.T) {
	h := navHandler(t)
	if h.BanMgr == nil {
		pagesWithTheHeader(h) // sets the ban manager the page lists from
	}
	tabs := func(body string) string {
		i := strings.Index(body, `<nav class="ban-tabs"`)
		if i < 0 {
			t.Fatal("no ban tabs on the community feed")
		}
		return body[i : i+strings.Index(body[i:], "</nav>")]
	}
	admin := tabs(renderAs(t, h.AdminCommunityBansIndex, "/unmask/admin/community-bans/", user.RoleAdmin, "en"))
	for _, href := range []string{"/unmask/admin/bans/", "/unmask/admin/advisor/", "/unmask/admin/community-bans/"} {
		if !strings.Contains(admin, `href="`+href+`"`) {
			t.Errorf("administrator: no tab to %s: %s", href, admin)
		}
	}
	viewer := tabs(renderAs(t, h.AdminCommunityBansIndex, "/unmask/admin/community-bans/", user.RoleViewer, "en"))
	if !strings.Contains(viewer, `href="/unmask/admin/community-bans/"`) || strings.Contains(viewer, "/admin/bans/") || strings.Contains(viewer, "/admin/advisor/") {
		t.Errorf("viewer: tabs %s", viewer)
	}
}

// TestCanWriteOnEveryPage: the flag the templates test is set for every
// account, false for a viewer and for no session, so a page never meets a
// missing key.
func TestCanWriteOnEveryPage(t *testing.T) {
	h := navHandler(t)
	for role, want := range map[string]bool{user.RoleSuperadmin: true, user.RoleAdmin: true, user.RoleViewer: false} {
		data := map[string]any{}
		h.addMeToData(asRole(httptest.NewRequest(http.MethodGet, "/unmask/admin/stats/", nil), role), data)
		if data["CanWrite"] != want || data["NavActive"] != "stats" {
			t.Errorf("%s: CanWrite=%v NavActive=%v", role, data["CanWrite"], data["NavActive"])
		}
	}
	data := map[string]any{}
	h.addMeToData(httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil), data)
	if data["CanWrite"] != false {
		t.Errorf("no session: CanWrite=%v", data["CanWrite"])
	}
}
