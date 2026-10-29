package handlers

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestDeniedAdminRequestReadsABareForbidden: the body a rejected visitor reads
// names neither the address the daemon took them for (an oracle for which
// forwarded header is trusted) nor the setting that admits them.  The operator's
// way back in after a self-lockout is in the log line instead.
func TestDeniedAdminRequestReadsABareForbidden(t *testing.T) {
	h := installedHandler(t)
	cfg := *h.cfg()
	cfg.Nginx.AdminAllowedIPs = []string{"10.0.0.0/8"}
	cfg.Nginx.AdminAllowedHosts = []string{"admin.example.com"}
	h.SetSettings(cfg)

	cases := []struct {
		name, ip, host, setting, logged string
	}{
		{"ip", "203.0.113.9", "admin.example.com", "admin_allowed_ips", "ip=203.0.113.9"},
		{"host", "10.1.2.3", "evil.example.com", "admin_allowed_hosts", "host=evil.example.com"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			for name, gate := range map[string]func(http.HandlerFunc) http.HandlerFunc{
				"login gate": h.AdminIPAllowMiddleware,
				"session":    h.AuthMiddleware,
			} {
				logged := &bytes.Buffer{}
				restore := captureLog(logged)
				r := httptest.NewRequest(http.MethodGet, "/unmask/admin/", nil)
				r.RemoteAddr = "127.0.0.1:5555"
				r.Header.Set("X-Real-IP", c.ip)
				r.Host = c.host
				rr := httptest.NewRecorder()
				gate(func(http.ResponseWriter, *http.Request) { t.Errorf("%s: reached the handler", name) })(rr, r)
				restore()

				if rr.Code != http.StatusForbidden {
					t.Fatalf("%s: status %d, want 403", name, rr.Code)
				}
				body := rr.Body.String()
				if strings.TrimSpace(body) != "Forbidden" {
					t.Errorf("%s: body %q, want a bare Forbidden", name, body)
				}
				for _, leak := range []string{c.ip, c.host, "config.yml", "admin_allowed", "Settings"} {
					if strings.Contains(body, leak) {
						t.Errorf("%s: body names %q", name, leak)
					}
				}
				for _, want := range []string{c.logged, c.setting, "config.yml", "Settings -> Network"} {
					if !strings.Contains(logged.String(), want) {
						t.Errorf("%s: log line lacks %q: %q", name, want, logged.String())
					}
				}
			}
		})
	}
}
