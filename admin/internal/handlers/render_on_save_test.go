package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/ban"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The community-bans subscribe mode decides whether http.inc includes the
// shared-ban maps, so switching it renders and asks for a reload.  The
// toggle on the bans pages only saved the mode: a switch to fetch_apply
// applied nothing after a reload, and a switch away kept the shared bans
// enforced.
func TestSubscribeToggleRendersTheMaps(t *testing.T) {
	h := ruleTestHandler(t)
	withDB := installedHandler(t) // the bans handler looks the account up
	h.DB, h.UserRepo = withDB.DB, withDB.UserRepo
	h.BanMgr = ban.New(h.DB, "", 0)
	toggle := func(mode string) string {
		t.Helper()
		form := url.Values{"op": {"subscribe-toggle"}, "subscribe_mode": {mode}, "return_to": {"community-bans"}}
		r := httptest.NewRequest(http.MethodPost, "/unmask/admin/bans/save", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
		rr := httptest.NewRecorder()
		h.AdminBansSave(rr, asRole(r, "admin"))
		if rr.Code != http.StatusFound {
			t.Fatalf("toggle %s: %d", mode, rr.Code)
		}
		return rr.Header().Get("Location")
	}
	httpInc := func() string {
		t.Helper()
		b, err := os.ReadFile(filepath.Join(h.cfg().Nginx.OutputDir, "http.inc"))
		if err != nil {
			t.Fatalf("http.inc: %v", err)
		}
		return string(b)
	}
	const include = "community-bans-ipja4.map;"

	toggle("off") // from whatever the defaults say
	if loc := toggle("fetch_apply"); !strings.Contains(loc, "/admin/community-bans/?saved=1&reload=1") {
		t.Errorf("switching to fetch_apply does not ask for a reload: %s", loc)
	}
	if !strings.Contains(httpInc(), include) {
		t.Fatalf("fetch_apply: http.inc does not include the shared-ban maps")
	}
	if loc := toggle("off"); !strings.Contains(loc, "reload=1") {
		t.Errorf("switching off does not ask for a reload: %s", loc)
	}
	if strings.Contains(httpInc(), include) {
		t.Errorf("off: http.inc still includes the shared-ban maps")
	}
	// A switch that changes nothing nginx reads asks for no reload.
	if loc := toggle("fetch"); strings.Contains(loc, "reload=1") {
		t.Errorf("off -> fetch asks for a reload: %s", loc)
	}

	// The page the toggle returns to says the change waits for a reload.
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/community-bans/?saved=1&reload=1", nil)
	r.AddCookie(&http.Cookie{Name: i18n.CookieName, Value: "en"})
	rr := httptest.NewRecorder()
	h.AdminCommunityBansIndex(rr, asRole(r, "admin"))
	if rr.Code != http.StatusOK {
		t.Fatalf("community-bans page: %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "nginx -s reload") {
		t.Errorf("the community-bans page does not ask for the reload")
	}
}

// Installing an mmdb from the network tab renders nginx's configuration,
// which carries the CIDRs of the country and ASN rules read from the file,
// as the daily update does.  It did not: the first install left those
// rules empty in nginx until another save rendered.
func TestIPGeoInstallRenders(t *testing.T) {
	h := ruleTestHandler(t)
	out := h.cfg().Nginx.OutputDir
	if _, err := os.Stat(filepath.Join(out, "http.inc")); err == nil {
		t.Fatal("http.inc exists before the install")
	}
	changed, err := h.renderAfterIPGeoInstall(h.snapshotSettings())
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if !changed {
		t.Errorf("the first render reports no change")
	}
	if _, err := os.Stat(filepath.Join(out, "http.inc")); err != nil {
		t.Fatalf("no http.inc after the install's render: %v", err)
	}
	// The same file again: nothing for nginx to reload.
	if changed, err := h.renderAfterIPGeoInstall(h.snapshotSettings()); err != nil || changed {
		t.Errorf("an unchanged render reports changed=%v err=%v", changed, err)
	}
}
