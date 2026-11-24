package nginxconf

import (
	"net/netip"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestLetDetailNamesWhatABypassMatched: the list of requests let through
// without a challenge says which range or which path row let each one
// through -- the operator's own row first, a preset by its id, and nothing
// for what the settings do not know.
func TestLetDetailNamesWhatABypassMatched(t *testing.T) {
	var n settings.Nginx
	n.BypassIPs = []string{"198.51.100.0/24", "203.0.113.7", "192.0.2.0/24", "2001:db8:1::/48"}
	n.BypassIPsTitle = []string{"office", "", "switched off"}
	n.BypassIPsDisabled = []bool{false, false, true}
	n.BypassIPEnabledPresets = []string{"google-common"}
	n.BypassPaths.Paths = []settings.BypassPath{
		{Path: "^/api/", Title: "partner API"},
		{Path: "^/shop-only/", Site: "shop.example"},
		{Path: "^/off/", Disabled: true},
		{Path: "^/pcre/(?!x)"}, // nginx reads it, Go's regexp does not
	}
	d := NewLetDetail(n)

	google := bypassIPGroupByID("google-common")
	if google == nil || len(google.Prefixes()) == 0 {
		t.Fatal("the google-common preset has no ranges; the test has nothing to match a preset with")
	}
	inGoogle := firstAddress(t, google.Prefixes()[0])

	for ip, want := range map[string]string{
		"198.51.100.20":  "list:office",
		"203.0.113.7":    "list:203.0.113.7",
		"203.0.113.8":    "",
		"192.0.2.9":      "", // the row is switched off
		"2001:db8:1::42": "list:2001:db8:1::/48",
		inGoogle:         "google-common",
		"not an address": "",
		"":               "",
	} {
		if got := d.IP(ip); got != want {
			t.Errorf("IP(%q) = %q, want %q", ip, got, want)
		}
		if got := d.IP(ip); got != want { // the second answer comes from the cache
			t.Errorf("IP(%q), asked again = %q, want %q", ip, got, want)
		}
	}
	for _, c := range []struct{ host, path, want string }{
		{"a.example", "/api/v1/items", "list:partner API"},
		{"a.example", "/shop-only/x", ""},
		{"shop.example", "/shop-only/x", "list:^/shop-only/"},
		{"SHOP.example", "/shop-only/x", "list:^/shop-only/"},
		{"a.example", "/off/x", ""},
		{"a.example", "/pcre/y", ""},
		{"a.example", "/robots.txt", "static-assets"},
		{"a.example", "/page", ""},
		{"a.example", "", ""},
	} {
		if got := d.Path(c.host, c.path); got != c.want {
			t.Errorf("Path(%q, %q) = %q, want %q", c.host, c.path, got, c.want)
		}
	}
	var none *LetDetail
	if none.IP("198.51.100.20") != "" || none.Path("a.example", "/api/") != "" {
		t.Error("a nil LetDetail names something")
	}
}

// firstAddress is an address inside prefix (its network address, or the one
// after it for a range wider than a single address).
func firstAddress(t *testing.T, prefix string) string {
	t.Helper()
	p, err := netip.ParsePrefix(prefix)
	if err != nil {
		a, err := netip.ParseAddr(prefix)
		if err != nil {
			t.Fatalf("%q is neither a prefix nor an address", prefix)
		}
		return a.String()
	}
	a := p.Masked().Addr()
	if n := a.Next(); p.Contains(n) {
		a = n
	}
	return a.String()
}
