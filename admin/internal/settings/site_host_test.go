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

// A custom rule's host line names hosts; the scope picker's word for the
// default scope is not one, and as a map key nginx would read it as its own.
func TestCustomRuleHostRefusesMapWords(t *testing.T) {
	for _, v := range []string{"default", "Default", "include"} {
		c := CustomCondition{Kind: CustomCondHost, Values: []string{v}}
		if err := NormalizeCustomCondition(&c); err == nil {
			t.Errorf("host %q was accepted", v)
		}
	}
	c := CustomCondition{Kind: CustomCondHost, Values: []string{"Shop.Example.com", "defaults.example.com"}}
	if err := NormalizeCustomCondition(&c); err != nil {
		t.Fatalf("real host names were refused: %v", err)
	}
	if len(c.Values) != 2 || c.Values[0] != "shop.example.com" {
		t.Errorf("values = %v", c.Values)
	}
}
