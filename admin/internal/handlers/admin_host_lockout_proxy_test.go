package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The save-time self-lockout check on admin_allowed_hosts has to judge the
// host the /admin/* gate will judge.  Behind a proxy that rewrites Host
// (Apache's ProxyPass sends the backend's address) the gate reads the trusted
// X-Forwarded-Host; the check read r.Host, so it refused a list naming the
// operator's own domain as a lockout and accepted the list its own message
// suggested -- the backend address -- which the gate then turned the operator
// away under.
func TestNetworkSaveLockoutCheckReadsTheGatesHost(t *testing.T) {
	h := ruleTestHandler(t)
	mk := func(hosts []string) *http.Request {
		form := url.Values{"admin_allowed_hosts": hosts}
		en := make([]string, len(hosts))
		for i := range en {
			en[i] = "1"
		}
		form["admin_allowed_hosts_enabled"] = en
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=network", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "127.0.0.1:40000"                      // the proxy on the same host: a trusted peer
		req.Host = "127.0.0.1:9477"                             // what ProxyPass sends as Host
		req.Header.Set("X-Forwarded-Host", "admin.example.com") // what the operator typed
		return req
	}
	flashOf := func(rr *httptest.ResponseRecorder) string {
		for _, c := range rr.Result().Cookies() {
			if c.Name == flashCookiePrefix+"err" {
				v, _ := url.QueryUnescape(c.Value)
				return v
			}
		}
		return ""
	}
	gateAdmits := func() bool {
		cfg := *h.cfg()
		return hostAllowed(adminClientHost(mk(nil), cfg), settings.EnabledValues(cfg.Nginx.AdminAllowedHosts, cfg.Nginx.AdminAllowedHostsDisabled))
	}

	// The backend address is the name that locks the operator out: refused,
	// and the message names the host the gate sees.
	rr := httptest.NewRecorder()
	h.AdminSettingsSave(rr, mk([]string{"exact:127.0.0.1"}))
	cur, err := settings.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cur.Nginx.AdminAllowedHosts) != 0 {
		t.Errorf("a list the gate turns the operator away under was saved: %v", cur.Nginx.AdminAllowedHosts)
	}
	if msg := flashOf(rr); !strings.Contains(msg, "admin.example.com") {
		t.Errorf("the refusal does not name the host the gate sees: %q", msg)
	}

	// The operator's own domain is no lockout: saved, and the gate admits the
	// next request.
	rr = httptest.NewRecorder()
	h.AdminSettingsSave(rr, mk([]string{"exact:admin.example.com"}))
	cur, err = settings.Load(h.ConfigPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(cur.Nginx.AdminAllowedHosts) != 1 || cur.Nginx.AdminAllowedHosts[0] != "exact:admin.example.com" {
		t.Fatalf("the operator's own host was refused: stored %v, flash %q", cur.Nginx.AdminAllowedHosts, flashOf(rr))
	}
	if !gateAdmits() {
		t.Error("the save was accepted and the gate now refuses the operator")
	}
}
