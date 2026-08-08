package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A rejected network-tab save must carry the operator's typed rows back, so
// the error page shows their input instead of the last-saved list -- the whole
// point of "keep the wrong input on error".  This drives the draft round-trip
// (stash -> overlay) directly.
func TestNetListDraftRoundTrip(t *testing.T) {
	form := url.Values{}
	form["admin_allowed_hosts"] = []string{`tool\d+\-[a-z]`, "admin.example.com"}
	form["admin_allowed_hosts_enabled"] = []string{"1", "0"}
	form["admin_allowed_ips"] = []string{"10.0.0.0/8"}
	form["admin_allowed_ips_enabled"] = []string{"1"}

	// Stash, then read the flash back the way the GET render would.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/unmask/admin/settings/save?section=network", nil)
	setNetListDraft(w, r, "/unmask", form)

	var cookie string
	for _, c := range w.Result().Cookies() {
		if c.Name == flashCookiePrefix+netListDraftFlash {
			cookie = c.Value
		}
	}
	if cookie == "" {
		t.Fatal("no draft cookie was set on the error path")
	}
	raw, err := url.QueryUnescape(cookie)
	if err != nil {
		t.Fatal(err)
	}

	n := &settings.Nginx{
		// Pre-existing stored state that must be overwritten by the draft, not
		// merged with it.
		AdminAllowedHosts: []string{"stale.example.com"},
	}
	overlayNetListDraft(n, raw)

	if len(n.AdminAllowedHosts) != 2 || n.AdminAllowedHosts[0] != `tool\d+\-[a-z]` {
		t.Fatalf("the invalid value the operator typed was not preserved: %#v", n.AdminAllowedHosts)
	}
	if n.AdminAllowedHosts[1] != "admin.example.com" {
		t.Errorf("the other row was lost: %#v", n.AdminAllowedHosts)
	}
	// The second row was submitted disabled; that state has to survive too.
	if len(n.AdminAllowedHostsDisabled) != 2 || !n.AdminAllowedHostsDisabled[1] || n.AdminAllowedHostsDisabled[0] {
		t.Errorf("per-row enabled state not preserved: %#v", n.AdminAllowedHostsDisabled)
	}
	if len(n.AdminAllowedIPs) != 1 || n.AdminAllowedIPs[0] != "10.0.0.0/8" {
		t.Errorf("the IP list was not preserved: %#v", n.AdminAllowedIPs)
	}
}

// The draft is a convenience; an oversized payload must not break the redirect.
func TestNetListDraftSkipsOversized(t *testing.T) {
	form := url.Values{}
	big := make([]string, 0, 500)
	for i := 0; i < 500; i++ {
		big = append(big, strings.Repeat("x", 40))
	}
	form["admin_allowed_hosts"] = big

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/x", nil)
	setNetListDraft(w, r, "/unmask", form)
	for _, c := range w.Result().Cookies() {
		if c.Name == flashCookiePrefix+netListDraftFlash {
			t.Fatal("an oversized draft was written to a cookie instead of being skipped")
		}
	}
}

// A field the operator cleared to empty must overlay as empty, not fall back
// to the stored list (clearing is a legitimate edit that must survive a
// sibling field's error).
func TestNetListDraftPreservesCleared(t *testing.T) {
	form := url.Values{}
	form["admin_allowed_hosts"] = []string{""} // present in the POST but empty
	form["admin_allowed_ips"] = []string{"not-an-ip"}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/x", nil)
	setNetListDraft(w, r, "/unmask", form)
	var raw string
	for _, c := range w.Result().Cookies() {
		if c.Name == flashCookiePrefix+netListDraftFlash {
			raw, _ = url.QueryUnescape(c.Value)
		}
	}
	n := &settings.Nginx{AdminAllowedHosts: []string{"stale.example.com"}}
	overlayNetListDraft(n, raw)
	if len(n.AdminAllowedHosts) != 0 {
		t.Errorf("a cleared field fell back to the stored list: %#v", n.AdminAllowedHosts)
	}
}
