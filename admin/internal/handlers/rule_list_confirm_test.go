package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func networkForm(pairs url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=network",
		strings.NewReader(pairs.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	return r
}

// A row switched off stays in the config (one-click re-enable) but stops
// counting: the gate, the allow-all detection and the lockout guard all judge
// the enabled subset only.
func TestApplyNetworkFormDisabledRows(t *testing.T) {
	var n settings.Nginx
	r := networkForm(url.Values{
		"admin_allowed_ips":         {"10.0.0.0/8", "203.0.113.7"},
		"admin_allowed_ips_title":   {"office", "old vpn"},
		"admin_allowed_ips_enabled": {"1", "0"},
	})
	if err := applyNetworkForm(&n, r, "en", "10.1.2.3", "admin.example.com"); err != nil {
		t.Fatalf("save: %v", err)
	}
	if len(n.AdminAllowedIPs) != 2 || len(n.AdminAllowedIPsDisabled) != 2 {
		t.Fatalf("rows/flags = %v / %v", n.AdminAllowedIPs, n.AdminAllowedIPsDisabled)
	}
	if n.AdminAllowedIPsDisabled[0] || !n.AdminAllowedIPsDisabled[1] {
		t.Errorf("disabled flags misaligned: %v", n.AdminAllowedIPsDisabled)
	}

	// The operator's own IP is admitted only by the row being switched OFF:
	// that save is a lockout and must be rejected.
	r = networkForm(url.Values{
		"admin_allowed_ips":         {"203.0.113.7", "10.0.0.0/8"},
		"admin_allowed_ips_enabled": {"0", "1"},
	})
	if err := applyNetworkForm(&n, r, "en", "203.0.113.7", "admin.example.com"); err == nil {
		t.Error("disabling the row that admits the operator must be rejected as a lockout")
	}

	// Every row off = effectively empty = "no restriction", same as an empty
	// list; not a lockout.
	r = networkForm(url.Values{
		"admin_allowed_ips":         {"10.0.0.0/8"},
		"admin_allowed_ips_enabled": {"0"},
	})
	if err := applyNetworkForm(&n, r, "en", "203.0.113.7", "admin.example.com"); err != nil {
		t.Errorf("all-off list means open, not lockout: %v", err)
	}
	if n.AdminAllowedIPsDisabled == nil || !n.AdminAllowedIPsDisabled[0] {
		t.Errorf("all-off flags lost: %v", n.AdminAllowedIPsDisabled)
	}

	// A dropped duplicate value must drop its flag too, or every later toggle
	// slides onto the wrong row.
	r = networkForm(url.Values{
		"admin_allowed_ips":         {"10.0.0.0/8", "10.0.0.0/8", "192.0.2.0/24"},
		"admin_allowed_ips_enabled": {"1", "1", "0"},
	})
	if err := applyNetworkForm(&n, r, "en", "10.1.2.3", "admin.example.com"); err != nil {
		t.Fatalf("save: %v", err)
	}
	if len(n.AdminAllowedIPs) != 2 || len(n.AdminAllowedIPsDisabled) != 2 ||
		n.AdminAllowedIPsDisabled[0] || !n.AdminAllowedIPsDisabled[1] {
		t.Errorf("dedup slid the flags: %v / %v", n.AdminAllowedIPs, n.AdminAllowedIPsDisabled)
	}
}

// All-enabled rows keep the legacy shape: no *_disabled key lands in the yml.
func TestApplyNetworkFormAllEnabledKeepsLegacyShape(t *testing.T) {
	var n settings.Nginx
	r := networkForm(url.Values{
		"admin_allowed_ips":         {"10.0.0.0/8"},
		"admin_allowed_ips_enabled": {"1"},
	})
	if err := applyNetworkForm(&n, r, "en", "10.1.2.3", ""); err != nil {
		t.Fatalf("save: %v", err)
	}
	if n.AdminAllowedIPsDisabled != nil {
		t.Errorf("all-enabled list should store no flags, got %v", n.AdminAllowedIPsDisabled)
	}
}

func TestEnabledValues(t *testing.T) {
	vals := []string{"a", "b", "c"}
	if got := settings.EnabledValues(vals, nil); len(got) != 3 {
		t.Errorf("nil flags: %v", got)
	}
	if got := settings.EnabledValues(vals, []bool{false, true}); len(got) != 2 || got[1] != "c" {
		t.Errorf("short flags: %v", got)
	}
	if got := settings.EnabledValues(nil, nil); len(got) != 0 {
		t.Errorf("empty: %v", got)
	}
}

// The /admin/* IP gate must treat a disabled row as absent -- otherwise
// "switched off" would still admit the address, which is the exact accident
// the confirm-style rows exist to prevent.
func TestAdminGateSkipsDisabledRows(t *testing.T) {
	h := newTestHandler(t)
	// SetupNeeded bypasses the gate while no admin user exists -- give the
	// install a completed shape so the gate actually runs.
	if _, err := h.DB.Exec(`CREATE TABLE unmask_user (id INTEGER PRIMARY KEY, username TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.DB.Exec(`INSERT INTO unmask_user (username) VALUES ('op')`); err != nil {
		t.Fatal(err)
	}
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	s.Nginx.AdminAllowedIPs = []string{"10.0.0.0/8", "192.0.2.1"}
	s.Nginx.AdminAllowedIPsDisabled = []bool{false, true}
	h.SetSettings(s)

	gate := h.AdminIPAllowMiddleware(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?range=1h", nil)
	req.RemoteAddr = "192.0.2.1:44321"
	rr := httptest.NewRecorder()
	gate(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Errorf("disabled allowlist row still admits its IP: %d", rr.Code)
	}

	req = httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?range=1h", nil)
	req.RemoteAddr = "10.9.9.9:44321"
	rr = httptest.NewRecorder()
	gate(rr, req)
	if rr.Code == http.StatusForbidden {
		t.Errorf("enabled row stopped admitting its range: %d", rr.Code)
	}
}

// Defined-site rows honour their toggle across every consumer: ghost
// detection and the sites form round-trip.
func TestSiteDefinedDisabledRows(t *testing.T) {
	c := settings.SiteAcceptanceConfig{
		Mode:            settings.SiteModeDefined,
		Defined:         []string{"a.example.com", "b.example.com"},
		DefinedDisabled: []bool{false, true},
	}
	if c.IsGhost("a.example.com") {
		t.Error("enabled definition must not be a ghost")
	}
	if !c.IsGhost("b.example.com") {
		t.Error("a disabled definition reverts the site to ghost handling")
	}
	if got := c.ActiveDefined(); len(got) != 1 || got[0] != "a.example.com" {
		t.Errorf("ActiveDefined = %v", got)
	}

	r := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=sites",
		strings.NewReader(url.Values{
			"site_mode":            {"defined"},
			"site_defined":         {"A.example.com", "b.example.com"},
			"site_defined_title":   {"main", ""},
			"site_defined_enabled": {"1", "0"},
		}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r.ParseForm()
	var got settings.SiteAcceptanceConfig
	applySitesForm(&got, r)
	if len(got.Defined) != 2 || got.Defined[0] != "a.example.com" {
		t.Fatalf("Defined = %v", got.Defined)
	}
	if len(got.DefinedDisabled) != 2 || got.DefinedDisabled[0] || !got.DefinedDisabled[1] {
		t.Errorf("DefinedDisabled = %v", got.DefinedDisabled)
	}
	if len(got.DefinedTitle) != 2 || got.DefinedTitle[0] != "main" {
		t.Errorf("DefinedTitle = %v", got.DefinedTitle)
	}
}

// A disabled trusted-LB extra is out of the trusted set entirely.
func TestTrustedLBExtraDisabled(t *testing.T) {
	var n settings.Nginx
	n.TrustedLBExtra = []settings.TrustedLBExtra{
		{ID: "mylb", CIDRs: []string{"198.51.100.0/24"}, Disabled: true},
	}
	if trusted, _ := nginxconf.IsTrustedLBIP("198.51.100.9", n); trusted {
		t.Error("a disabled LB extra must not be trusted")
	}
	n.TrustedLBExtra[0].Disabled = false
	if trusted, vendor := nginxconf.IsTrustedLBIP("198.51.100.9", n); !trusted || vendor != "mylb" {
		t.Error("the same row enabled must be trusted again")
	}
}

// The trusted-LB form round-trips label + enabled through the rule-row shape.
func TestApplyTrustedLBFormLabelAndEnabled(t *testing.T) {
	var n settings.Nginx
	r := networkForm(url.Values{
		"lb_extra_id":      {"lb1", "lb2"},
		"lb_extra_label":   {"front LB", ""},
		"lb_extra_cidrs":   {"198.51.100.0/24", "203.0.113.0/24"},
		"lb_extra_header":  {"X-Client-JA4", "X-Client-JA4"},
		"lb_extra_enabled": {"1", "0"},
	})
	applyTrustedLBForm(&n, r)
	if len(n.TrustedLBExtra) != 2 {
		t.Fatalf("extras = %+v", n.TrustedLBExtra)
	}
	if n.TrustedLBExtra[0].Label != "front LB" || n.TrustedLBExtra[0].Disabled {
		t.Errorf("row1 = %+v", n.TrustedLBExtra[0])
	}
	if !n.TrustedLBExtra[1].Disabled {
		t.Errorf("row2 lost its off flag: %+v", n.TrustedLBExtra[1])
	}
}

// The network tab renders the lists as CONFIRMED rows: view mode by default,
// with the toggle / arrows present and the off row marked.  Only the
// clone-template row may carry the editing class.
func TestNetworkTabRendersConfirmedRows(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	s.Nginx.AdminAllowedIPs = []string{"10.0.0.0/8", "192.0.2.1"}
	s.Nginx.AdminAllowedIPsTitle = []string{"office", "retired"}
	s.Nginx.AdminAllowedIPsDisabled = []bool{false, true}
	h.SetSettings(s)

	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=network", nil)
	r.SetPathValue("tab", "network")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("network tab: %d", rr.Code)
	}
	body := rr.Body.String()

	// Server-rendered rows are confirmed (not editing).  Editing rows are
	// legitimate only inside <template> clone sources.
	stripped := regexp.MustCompile(`(?s)<template.*?</template>`).ReplaceAllString(body, "")
	if strings.Contains(stripped, `"rule-row editing"`) {
		t.Error("a server-rendered list row starts in editing mode; rows must render confirmed")
	}
	if !strings.Contains(body, `name="admin_allowed_ips_enabled" value="0"`) {
		t.Error("the disabled row does not carry its off flag")
	}
	if !strings.Contains(stripped, "disabled-row") {
		t.Error("the disabled row is not visually marked")
	}
	for _, frag := range []string{"rule-toggle", "rule-up", "rule-down", "rule-edit"} {
		if !strings.Contains(body, frag) {
			t.Errorf("missing %s in the rendered rows", frag)
		}
	}
	// The state line counts enabled rows only (1 of the 2).
	if !strings.Contains(body, ">office<") && !strings.Contains(body, "office") {
		t.Error("note text lost")
	}
}
