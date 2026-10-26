package settings

import "testing"

// admin_public_url is scheme://host with an optional base path: the links
// in mail are the value plus "/admin/...", so a trailing slash goes, and a
// value that already ends in /admin, a query, credentials or another scheme
// are refused rather than saved to build a broken or leaking link.
func TestParseAdminPublicURL(t *testing.T) {
	for in, want := range map[string]string{
		"":                                  "",
		"  https://admin.example.com  ":     "https://admin.example.com",
		"https://admin.example.com/":        "https://admin.example.com",
		"https://admin.example.com/unmask":  "https://admin.example.com/unmask",
		"https://admin.example.com/unmask/": "https://admin.example.com/unmask",
		"http://localhost:8080/unmask":      "http://localhost:8080/unmask",
		"https://[2001:db8::1]:8443/u":      "https://[2001:db8::1]:8443/u",
		"HTTPS://Admin.Example.com/Unmask":  "https://Admin.Example.com/Unmask",
	} {
		got, err := ParseAdminPublicURL(in)
		if err != nil || got != want {
			t.Errorf("%q: %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{
		"admin.example.com",
		"ftp://admin.example.com",
		"https://",
		"https://user:pw@admin.example.com",
		"https://admin.example.com/unmask?x=1",
		"https://admin.example.com/unmask#x",
		"https://admin.example.com/unmask/admin",
		"https://admin.example.com/admin/",
		"mailto:ops@example.com",
	} {
		if got, err := ParseAdminPublicURL(in); err == nil {
			t.Errorf("%q was accepted as %q", in, got)
		}
	}
}
