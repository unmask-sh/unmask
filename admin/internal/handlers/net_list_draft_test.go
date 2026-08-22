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
	form["admin_allowed_hosts"] = []string{`web\d+\-[a-z]`, "admin.example.com"}
	form["admin_allowed_hosts_enabled"] = []string{"1", "0"}
	form["admin_allowed_ips"] = []string{"10.0.0.0/8"}
	form["admin_allowed_ips_enabled"] = []string{"1"}

	// Stash, then read the flash back the way the GET render would.
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/unmask/admin/settings/save?section=network", nil)
	setSectionDraft(w, r, "/unmask", "network", form, []string{`web\d+\-[a-z]`}, "admin_allowed_hosts", "", "boom")

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

	full := &settings.Settings{}
	// Pre-existing stored state that must be overwritten by the draft.
	full.Nginx.AdminAllowedHosts = []string{"stale.example.com"}
	view := overlaySectionDraft(full, "network", raw)
	n := &full.Nginx
	if !view.Focus[`web\d+\-[a-z]`] {
		t.Errorf("the changed value is not in the focus set: %#v", view.Focus)
	}
	if view.Focus["admin.example.com"] {
		t.Errorf("an unchanged, pre-existing-looking row must not be focused")
	}
	// The located error round-trips too, so the render can point at the row.
	if view.ErrField != "admin_allowed_hosts" || view.ErrMsg != "boom" {
		t.Errorf("the located error did not survive the round-trip: %#v", view)
	}
	if len(n.AdminAllowedHosts) != 2 || n.AdminAllowedHosts[0] != `web\d+\-[a-z]` {
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
	setSectionDraft(w, r, "/unmask", "network", form, nil, "", "", "")
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
	setSectionDraft(w, r, "/unmask", "network", form, nil, "", "", "")
	var raw string
	for _, c := range w.Result().Cookies() {
		if c.Name == flashCookiePrefix+netListDraftFlash {
			raw, _ = url.QueryUnescape(c.Value)
		}
	}
	full := &settings.Settings{}
	full.Nginx.AdminAllowedHosts = []string{"stale.example.com"}
	_ = overlaySectionDraft(full, "network", raw)
	n := &full.Nginx
	if len(n.AdminAllowedHosts) != 0 {
		t.Errorf("a cleared field fell back to the stored list: %#v", n.AdminAllowedHosts)
	}
}

// Only the rows the operator added or changed become the focus set -- the
// point of "open only the error row, not the whole list".  A value already in
// the stored list is not focused even when resubmitted.
func TestChangedListValues(t *testing.T) {
	stored := map[string][]string{
		"admin_allowed_hosts": {"admin.example.com", `exact:keep.example.com`},
		"admin_allowed_ips":   {"10.0.0.0/8"},
		"metrics_allow_from":  nil,
	}
	form := url.Values{}
	// One unchanged host, one brand-new host; the IP list resubmitted as-is;
	// a new metrics entry.
	form["admin_allowed_hosts"] = []string{"admin.example.com", `web\d+-[a-z]+`}
	form["admin_allowed_ips"] = []string{"10.0.0.0/8"}
	form["metrics_allow_from"] = []string{"192.0.2.1"}

	got := changedListValues(stored, form)
	set := map[string]bool{}
	for _, v := range got {
		set[v] = true
	}
	if !set[`web\d+-[a-z]+`] {
		t.Errorf("the newly-added host is not in the changed set: %v", got)
	}
	if !set["192.0.2.1"] {
		t.Errorf("the newly-added metrics entry is not in the changed set: %v", got)
	}
	if set["admin.example.com"] {
		t.Errorf("an unchanged, already-stored host must not be flagged as changed: %v", got)
	}
	if set["10.0.0.0/8"] {
		t.Errorf("a resubmitted, unchanged IP must not be flagged as changed: %v", got)
	}
}

// The generalisation must carry to another section unchanged: a rejected
// bypass-ips save preserves its rows and locates its error the same way the
// network tab does, through the shared registry.
func TestSectionDraftBypassIPs(t *testing.T) {
	form := url.Values{}
	form["bypass_ip"] = []string{"10.0.0.0/8", "not-an-ip"}
	form["bypass_ip_enabled"] = []string{"1", "1"}
	form["stats_exclude_ips"] = []string{"192.0.2.5"}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/unmask/admin/settings/save?section=bypass-ips", nil)
	setSectionDraft(w, r, "/unmask", "bypass-ips", form, []string{"not-an-ip", "192.0.2.5"}, "bypass_ip", "not-an-ip", "bad ip")
	var raw string
	for _, c := range w.Result().Cookies() {
		if c.Name == flashCookiePrefix+netListDraftFlash {
			raw, _ = url.QueryUnescape(c.Value)
		}
	}
	if raw == "" {
		t.Fatal("no bypass draft cookie set")
	}

	full := &settings.Settings{}
	full.Nginx.BypassIPs = []string{"203.0.113.9"} // stale, must be replaced
	view := overlaySectionDraft(full, "bypass-ips", raw)

	if len(full.Nginx.BypassIPs) != 2 || full.Nginx.BypassIPs[1] != "not-an-ip" {
		t.Fatalf("bypass rows not preserved (invalid value included): %#v", full.Nginx.BypassIPs)
	}
	if len(full.Nginx.StatsExcludeIPs) != 1 || full.Nginx.StatsExcludeIPs[0] != "192.0.2.5" {
		t.Errorf("stats-exclude rows not preserved: %#v", full.Nginx.StatsExcludeIPs)
	}
	if view.ErrField != "bypass_ip" || view.ErrValue != "not-an-ip" {
		t.Errorf("bypass error not located: %#v", view)
	}
	if !view.Focus["not-an-ip"] {
		t.Errorf("the bad bypass row is not focused: %#v", view.Focus)
	}

	// A draft from another section must be ignored (stale-tab safety).
	fresh := &settings.Settings{}
	fresh.Nginx.BypassIPs = []string{"203.0.113.9"}
	if v := overlaySectionDraft(fresh, "network", raw); v.ErrField != "" || len(fresh.Nginx.BypassIPs) != 1 {
		t.Errorf("a bypass draft was applied to the network tab: %#v", v)
	}
}

// The structured path lists (honeypot / protected / bypass-paths and the
// geo/asn exempt lists) carry Action + Site columns and store []struct, not
// []string.  A rejected save must round-trip all of that through the shared
// draft so the error page rebuilds the rows -- invalid value included.
func TestSectionDraftStructuredPaths(t *testing.T) {
	form := url.Values{}
	form["honeypot_url_path"] = []string{"/trap", "bad("}
	form["honeypot_url_title"] = []string{"a", "b"}
	form["honeypot_url_enabled"] = []string{"1", "0"}
	form["honeypot_url_action"] = []string{"deny", ""}
	form["honeypot_url_site"] = []string{"", "shop.example"}

	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "/x?section=honeypot", nil)
	setSectionDraft(w, r, "/unmask", "honeypot", form, []string{"bad("}, "honeypot_url_path", "bad(", "boom")
	var raw string
	for _, c := range w.Result().Cookies() {
		if c.Name == flashCookiePrefix+netListDraftFlash {
			raw, _ = url.QueryUnescape(c.Value)
		}
	}
	full := &settings.Settings{}
	full.Nginx.Honeypot.URLs = []settings.HoneypotURL{{Path: "/stale"}}
	view := overlaySectionDraft(full, "honeypot", raw)

	u := full.Nginx.Honeypot.URLs
	if len(u) != 2 || u[0].Path != "/trap" || u[1].Path != "bad(" {
		t.Fatalf("honeypot rows not rebuilt (invalid value must survive): %#v", u)
	}
	if u[0].Action != "deny" || u[1].Site != "shop.example" {
		t.Errorf("action/site columns not preserved: %#v", u)
	}
	if !u[1].Disabled || u[0].Disabled {
		t.Errorf("per-row enabled not preserved: %#v", u)
	}
	if view.ErrField != "honeypot_url_path" || view.ErrValue != "bad(" || !view.Focus["bad("] {
		t.Errorf("error location / focus not carried: %#v", view)
	}
}
