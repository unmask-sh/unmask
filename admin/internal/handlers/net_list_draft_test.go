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
	setNetListDraft(w, r, "/unmask", form, []string{`tool\d+\-[a-z]`})

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
	focus := overlayNetListDraft(n, raw)
	if !focus[`tool\d+\-[a-z]`] {
		t.Errorf("the changed value is not in the focus set: %#v", focus)
	}
	if focus["admin.example.com"] {
		t.Errorf("an unchanged, pre-existing-looking row must not be focused")
	}
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
	setNetListDraft(w, r, "/unmask", form, nil)
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
	setNetListDraft(w, r, "/unmask", form, nil)
	var raw string
	for _, c := range w.Result().Cookies() {
		if c.Name == flashCookiePrefix+netListDraftFlash {
			raw, _ = url.QueryUnescape(c.Value)
		}
	}
	n := &settings.Nginx{AdminAllowedHosts: []string{"stale.example.com"}}
	_ = overlayNetListDraft(n, raw)
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
	form["admin_allowed_hosts"] = []string{"admin.example.com", `tool\d+-[a-z]+`}
	form["admin_allowed_ips"] = []string{"10.0.0.0/8"}
	form["metrics_allow_from"] = []string{"192.0.2.1"}

	got := changedListValues(stored, form)
	set := map[string]bool{}
	for _, v := range got {
		set[v] = true
	}
	if !set[`tool\d+-[a-z]+`] {
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
