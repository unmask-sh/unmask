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

// applyNetworkForm must reject a save whose non-empty admin_allowed_ips /
// admin_allowed_hosts would exclude the operator's own IP / Host (a self-
// lockout), while accepting an empty list (= allow all) or one that includes
// them.  curIP/curHost are the in-flight request's, resolved the same way the
// /admin/* gate resolves them.
func TestApplyNetworkFormLockout(t *testing.T) {
	const curIP, curHost = "10.0.0.5", "admin.example.com"

	mk := func(allowFrom, allowedHosts string) *http.Request {
		// admin_allowed_ips / _hosts are now value-rule-lists (one entry per
		// repeated field), so pass each non-empty value as its own param.
		form := url.Values{}
		if allowFrom != "" {
			form.Add("admin_allowed_ips", allowFrom)
		}
		if allowedHosts != "" {
			form.Add("admin_allowed_hosts", allowedHosts)
		}
		req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// applyNetworkForm reads r.Form directly (no FormValue to trigger it).
		_ = req.ParseForm()
		return req
	}

	cases := []struct {
		name             string
		allowFrom, hosts string
		wantErr          bool
	}{
		{"host list excludes me -> lockout", "", "panel.example.com", true},
		{"host list includes me -> ok", "", "admin.example.com", false},
		{"host list empty -> allow all", "", "", false},
		{"ip list excludes me -> lockout", "192.168.0.0/24", "", true},
		{"ip list includes me -> ok", "10.0.0.0/8", "", false},
		{"both lists include me -> ok", "10.0.0.5", "admin.example.com", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var n settings.Nginx
			err := applyNetworkForm(&n, mk(c.allowFrom, c.hosts), i18n.LangEN, curIP, curHost)
			if (err != nil) != c.wantErr {
				t.Fatalf("applyNetworkForm err=%v, wantErr=%v", err, c.wantErr)
			}
		})
	}
}
