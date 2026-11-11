package settings

import "testing"

func TestValidSiteHost(t *testing.T) {
	for site, want := range map[string]bool{
		"shop.example.com":   true,
		"a-b.example.com":    true,
		"localhost":          true,
		"203.0.113.9":        true,
		"[2001:db8::1]":      true,
		"intranet_host":      true,
		`"shop.example.com"`: false, // quoted: the rule became one for every host
		`shop.example.com\`:  false, // `nginx -t`: unexpected "$"
		"default":            false, // duplicate default map parameter
		"Include":            false, // opens a file
		"hostnames":          false,
		"volatile":           false,
		"shop example.com":   false,
		"shop.example.com;":  false,
		"*.example.com":      false, // a host map matches whole names only
		"-shop.example.com":  false,
		"":                   false,
	} {
		if got := ValidSiteHost(site); got != want {
			t.Errorf("ValidSiteHost(%q) = %v, want %v", site, got, want)
		}
	}
}
