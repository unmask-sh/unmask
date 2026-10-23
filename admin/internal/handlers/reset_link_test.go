package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The password-reset / account-setup link is mailed to the account's own
// address, so the host it is built on decides who the token reaches.  The
// link's host comes from the request only when admin_allowed_hosts admits it
// -- read with the gate's own exact: / subdomain: / regex reading, which this
// used to ignore (and then built the link on the literal first entry,
// "exact:admin.example.com") -- or, outside the list, from the first entry
// that names a host.  X-Forwarded-Host and -Proto count only off a trusted
// proxy.
func TestBuildResetURL(t *testing.T) {
	const tok = "0123456789abcdef"
	type req struct {
		peer, host, fwdHost, fwdProto string
	}
	direct := func(host string) req { return req{peer: "203.0.113.9:5555", host: host} }
	viaProxy := func(host, fwdHost string) req {
		return req{peer: "127.0.0.1:41234", host: host, fwdHost: fwdHost}
	}
	cfg := func(hosts []string, disabled []bool) settings.Settings {
		var s settings.Settings
		s.Server.BasePath = "/unmask"
		s.Nginx.AdminAllowedHosts = hosts
		s.Nginx.AdminAllowedHostsDisabled = disabled
		return s
	}
	link := func(scheme, host string) string {
		return scheme + "://" + host + "/unmask/admin/reset-password?token=" + tok
	}
	cases := []struct {
		name string
		r    req
		cfg  settings.Settings
		want string
	}{
		{"empty list trusts the Host header",
			direct("admin.example.com"), cfg(nil, nil), link("http", "admin.example.com")},
		{"empty list, X-Forwarded-Host off a trusted proxy",
			viaProxy("127.0.0.1:9477", "admin.example.com"), cfg(nil, nil), link("http", "admin.example.com")},
		{"empty list, X-Forwarded-Host off an untrusted peer is ignored",
			req{peer: "203.0.113.9:5555", host: "unmask.example.com", fwdHost: "attacker.example"}, cfg(nil, nil),
			link("http", "unmask.example.com")},
		{"exact: entry admits its host",
			direct("admin.example.com"), cfg([]string{"exact:admin.example.com"}, nil), link("http", "admin.example.com")},
		{"exact: entry, case and port aside",
			direct("Admin.Example.com:8443"), cfg([]string{"exact:admin.example.com"}, nil), link("http", "Admin.Example.com:8443")},
		{"exact: entry stands in for a host outside the list",
			direct("attacker.example"), cfg([]string{"exact:admin.example.com"}, nil), link("http", "admin.example.com")},
		{"subdomain: entry admits a subdomain",
			direct("ops.example.com"), cfg([]string{"subdomain:example.com"}, nil), link("http", "ops.example.com")},
		{"subdomain: entry stands in with the domain itself",
			direct("example.com.attacker.example"), cfg([]string{"subdomain:example.com"}, nil), link("http", "example.com")},
		{"regex entry admits what it spells out",
			direct("web1-jp.example.com"), cfg([]string{`web\d+-[a-z]+\.example\.com`}, nil), link("http", "web1-jp.example.com")},
		{"a list of patterns alone names no host to stand in",
			direct("attacker.example"), cfg([]string{`web\d+-[a-z]+\.example\.com`}, nil), ""},
		{"the first entry that names a host stands in, patterns skipped",
			direct("attacker.example"), cfg([]string{`web\d+\.example\.com`, "exact:admin.example.com"}, nil), link("http", "admin.example.com")},
		{"a bare plain name names a host",
			direct("attacker.example"), cfg([]string{"admin.example.com"}, nil), link("http", "admin.example.com")},
		{"a disabled entry neither admits nor stands in",
			direct("old.example.com"), cfg([]string{"exact:old.example.com", "exact:admin.example.com"}, []bool{true, false}),
			link("http", "admin.example.com")},
		{"X-Forwarded-Host off a trusted proxy is matched against the list",
			viaProxy("127.0.0.1:9477", "admin.example.com"), cfg([]string{"exact:admin.example.com"}, nil), link("http", "admin.example.com")},
		{"X-Forwarded-Proto off a trusted proxy sets the scheme",
			req{peer: "127.0.0.1:41234", host: "admin.example.com", fwdProto: "https"}, cfg(nil, nil), link("https", "admin.example.com")},
		{"X-Forwarded-Proto off an untrusted peer is ignored",
			req{peer: "203.0.113.9:5555", host: "admin.example.com", fwdProto: "https"}, cfg(nil, nil), link("http", "admin.example.com")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, "/unmask/admin/forgot-password", nil)
			r.RemoteAddr = c.r.peer
			r.Host = c.r.host
			if c.r.fwdHost != "" {
				r.Header.Set("X-Forwarded-Host", c.r.fwdHost)
			}
			if c.r.fwdProto != "" {
				r.Header.Set("X-Forwarded-Proto", c.r.fwdProto)
			}
			if got := buildResetURL(r, c.cfg, tok); got != c.want {
				t.Errorf("buildResetURL = %q, want %q", got, c.want)
			}
		})
	}
}

// A TLS connection straight to the daemon says https by itself.
func TestBuildResetURLSchemeFromTLS(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "https://admin.example.com/unmask/admin/forgot-password", nil)
	r.RemoteAddr = "203.0.113.9:5555"
	var s settings.Settings
	s.Server.BasePath = "/unmask"
	if got, want := buildResetURL(r, s, "t"), "https://admin.example.com/unmask/admin/reset-password?token=t"; got != want {
		t.Errorf("buildResetURL = %q, want %q", got, want)
	}
}
