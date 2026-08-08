package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// An address allowlist stops being readable within months: "10.8.11.1" does
// not say whose laptop it is, and finding out means digging through VPN
// configs -- which is the research an operator has to redo before they dare
// delete a line they no longer recognise.  Each row therefore carries a note.
//
// The note lives in a parallel form field, so the pair has to be walked
// together on save.  Filtering the values (blank rows, duplicates) while
// filtering the notes separately would slide every note onto the wrong
// address, and a note on the wrong row is worse than none: it would state
// that some OTHER address is the one that is safe to keep.
func TestNetworkNotesStayOnTheirOwnRow(t *testing.T) {
	form := url.Values{}
	// Deliberately messy: a blank row in the middle and a duplicate at the
	// end, exactly what the row UI produces after some editing.
	form["admin_allowed_ips"] = []string{"10.8.11.1", "", "127.0.0.1", "10.8.11.1"}
	form["admin_allowed_ips_title"] = []string{"umi-note1 (VPN)", "left over", "loopback", "dup"}
	form["admin_allowed_hosts"] = []string{"admin.example.com"}
	form["admin_allowed_hosts_title"] = []string{"the only vhost that exposes /admin"}
	form["metrics_allow_from"] = []string{"10.0.0.0/8"}
	form["metrics_allow_from_title"] = []string{"internal scrape"}

	r := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=network",
		strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	var n settings.Nginx
	if err := applyNetworkForm(&n, r, i18n.Lang("en"), "10.8.11.1", "admin.example.com"); err != nil {
		t.Fatalf("save: %v", err)
	}

	if got, want := len(n.AdminAllowedIPs), 2; got != want {
		t.Fatalf("kept %d IPs, want %d (blank dropped, duplicate collapsed)", got, want)
	}
	if len(n.AdminAllowedIPsTitle) != len(n.AdminAllowedIPs) {
		t.Fatalf("notes (%d) and IPs (%d) are different lengths -- every note past the gap is on the wrong row",
			len(n.AdminAllowedIPsTitle), len(n.AdminAllowedIPs))
	}
	// The note that followed the blank row must land on the address it was
	// typed next to, not inherit the blank row's.
	for i, ip := range n.AdminAllowedIPs {
		want := map[string]string{"10.8.11.1": "umi-note1 (VPN)", "127.0.0.1": "loopback"}[ip]
		if n.AdminAllowedIPsTitle[i] != want {
			t.Errorf("%s carries note %q, want %q", ip, n.AdminAllowedIPsTitle[i], want)
		}
	}
	if n.AdminAllowedHostsTitle[0] != "the only vhost that exposes /admin" {
		t.Errorf("host note = %q", n.AdminAllowedHostsTitle[0])
	}
	if n.MetricsAllowFromTitle[0] != "internal scrape" {
		t.Errorf("metrics note = %q", n.MetricsAllowFromTitle[0])
	}
}

// Notes are free text typed by an operator and land in the YAML config, so the
// characters that would break it out of its quoting are stripped -- same
// treatment the bypass-IP rows give theirs.
func TestNetworkNotesAreSanitisedForYAML(t *testing.T) {
	form := url.Values{}
	form["admin_allowed_ips"] = []string{"10.0.0.1"}
	form["admin_allowed_ips_title"] = []string{"  said \"ok\"\nand \\ ran  "}

	r := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	var n settings.Nginx
	if err := applyNetworkForm(&n, r, i18n.Lang("en"), "10.0.0.1", "h"); err != nil {
		t.Fatal(err)
	}
	got := n.AdminAllowedIPsTitle[0]
	if strings.ContainsAny(got, "\"\\\n\r") {
		t.Errorf("note kept a character that can break the config file: %q", got)
	}
	if got != "said 'ok' and / ran" {
		t.Errorf("note = %q", got)
	}
}

// The value list and the note list are rendered by one shared template, and a
// caller that wants no notes (the sites tab) passes none -- which used to
// panic the whole settings page ("len on a zero Value") and blank the tab.
func TestValueRuleListRendersWithAndWithoutNotes(t *testing.T) {
	h := newTestHandler(t)
	for _, tab := range []string{"network", "sites"} {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab="+tab, nil)
		req.SetPathValue("tab", tab)
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("tab=%s: want 200, got %d", tab, rr.Code)
		}
		// A template that panicked mid-render still returns 200 with a body
		// cut off at the failure, so check for content that comes after the
		// list rather than trusting the status alone.
		if !strings.Contains(rr.Body.String(), "</html>") {
			t.Errorf("tab=%s: page is truncated -- the shared rule-list template failed mid-render", tab)
		}
	}
	// The network tab must actually offer the note inputs.
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=network", nil)
	req.SetPathValue("tab", "network")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	for _, want := range []string{`name="admin_allowed_ips_title"`, `name="metrics_allow_from_title"`, `name="admin_allowed_hosts_title"`} {
		if !strings.Contains(rr.Body.String(), want) {
			t.Errorf("network tab is missing the note input %s", want)
		}
	}
}
