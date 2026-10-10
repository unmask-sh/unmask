package settings

import (
	"strings"
	"testing"
)

func TestNormalizeCustomRule(t *testing.T) {
	r := CustomRule{ID: "CR1", Label: " x ", Action: "captcha_only", IPs: []string{" 203.0.113.5 ", "", "10.0.0.0/8"}, JA4s: []string{"T13D*"}, Countries: []string{"jp"}, ASNs: []uint32{0, 4134}, UA: "(?i)curl", Path: `^/a\?b=1`, Hosts: []string{"Example.COM"}, RatePerMin: 2_000_000}
	if err := NormalizeCustomRule(&r); err != nil {
		t.Fatal(err)
	}
	if r.ID != "cr1" || r.Label != "x" || len(r.IPs) != 2 || r.JA4s[0] != "t13d*" || r.Countries[0] != "JP" || len(r.ASNs) != 1 || r.Hosts[0] != "example.com" || r.RatePerMin != 1_000_000 {
		t.Errorf("normalised: %+v", r)
	}
	for name, bad := range map[string]CustomRule{
		"no condition": {Action: "deny"},
		"bad action":   {Action: "ban", IPs: []string{"203.0.113.5"}},
		"bad cidr":     {Action: "deny", IPs: []string{"203.0.113.5/40"}},
		"bad ja4":      {Action: "deny", JA4s: []string{"t13d 1516"}},
		"bad country":  {Action: "deny", Countries: []string{"JPN"}},
		"bad regex":    {Action: "deny", UA: "("},
		"bad host":     {Action: "deny", Hosts: []string{"a b"}},
	} {
		b := bad
		if err := NormalizeCustomRule(&b); err == nil {
			t.Errorf("%s: accepted %+v", name, b)
		} else if !strings.Contains(err.Error(), "rule") {
			t.Errorf("%s: the error does not name the rule: %v", name, err)
		}
	}
	var n Nginx
	n.CustomRules = []CustomRule{{ID: "a", Enabled: true, IPs: []string{"203.0.113.5"}, Action: "deny"}, {ID: "b", Enabled: false, IPs: []string{"203.0.113.6"}, Action: "deny"}, {ID: "c", Enabled: true, Action: "deny"}}
	if got := n.EnabledCustomRules(); len(got) != 1 || got[0].ID != "a" {
		t.Errorf("enabled: %+v", got)
	}
}
