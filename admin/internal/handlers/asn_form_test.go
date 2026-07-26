package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func asnForm(t *testing.T, form url.Values) *settings.AsnConfig {
	t.Helper()
	r := httptest.NewRequest("POST", "/save?section=asn", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	var c settings.AsnConfig
	if err := applyAsnForm(&c, r); err != nil {
		t.Fatalf("applyAsnForm: %v", err)
	}
	return &c
}

// TestApplyAsnForm pins the save across presets + custom rules: an enabled
// catalog provider round-trips with its action; a custom row parses as an
// exact AS number ("AS16509"/"16509") or as an org substring (anything else);
// the default "skip" stores as unset.
func TestApplyAsnForm(t *testing.T) {
	form := url.Values{}
	form.Set("asn_default_action", "skip")      // -> stored unset
	form.Set("asn_default_rule_action", "deny") // registered-row inherit target
	form.Set("asn_default_rate", "150")         // feature B: config-level inherited default
	// preset provider
	form.Set("asn_provider_enabled_microsoft", "1")
	form.Set("asn_provider_action_microsoft", "deny")
	form.Set("asn_provider_rate_microsoft", "80") // per-preset rate override
	// custom rows: exact ASN, org string
	form["asn_number"] = []string{"AS16509", "Contabo"}
	form["asn_label"] = []string{"Amazon", "cheap VPS"}
	form["asn_action"] = []string{"captcha_only", "deny"}
	form["asn_rate"] = []string{"100", ""} // row0 throttled to 100/min, row1 immediate
	form.Set("asn_enabled_0", "1")
	form.Set("asn_enabled_1", "1")

	c := asnForm(t, form)
	if c.DefaultAction != "" {
		t.Errorf("default skip must store unset, got %q", c.DefaultAction)
	}
	if c.DefaultRatePerMin != 150 {
		t.Errorf("asn_default_rate=150 must parse into DefaultRatePerMin, got %d", c.DefaultRatePerMin)
	}
	if c.DefaultRuleAction != "deny" {
		t.Errorf("asn_default_rule_action=deny must persist, got %q", c.DefaultRuleAction)
	}
	// The resolve default (pow_then_captcha) stores as unset for a no-op save.
	f2 := url.Values{}
	f2.Set("asn_default_rule_action", "pow_then_captcha")
	r2 := httptest.NewRequest("POST", "/save?section=asn", strings.NewReader(f2.Encode()))
	r2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_ = r2.ParseForm()
	var c2 settings.AsnConfig
	if err := applyAsnForm(&c2, r2); err != nil {
		t.Fatalf("applyAsnForm: %v", err)
	}
	if c2.DefaultRuleAction != "" {
		t.Errorf("pow_then_captcha (the resolve default) must store unset, got %q", c2.DefaultRuleAction)
	}
	if len(c.Providers) != 1 || c.Providers[0].ID != "microsoft" || c.Providers[0].Action != "deny" || !c.Providers[0].Enabled ||
		c.Providers[0].RatePerMin == nil || *c.Providers[0].RatePerMin != 80 {
		t.Errorf("providers = %+v, want [microsoft deny enabled rate 80]", c.Providers)
	}
	if len(c.Rules) != 2 {
		t.Fatalf("want 2 custom rules, got %d (%+v)", len(c.Rules), c.Rules)
	}
	if c.Rules[0].ASN != 16509 || c.Rules[0].Org != "" || c.Rules[0].Action != "captcha_only" || (c.Rules[0].RatePerMin == nil || *c.Rules[0].RatePerMin != 100) {
		t.Errorf("row0 = %+v, want exact ASN16509 captcha_only rate 100", c.Rules[0])
	}
	if c.Rules[1].Org != "Contabo" || c.Rules[1].ASN != 0 || c.Rules[1].Action != "deny" || c.Rules[1].RatePerMin != nil {
		t.Errorf("row1 = %+v, want org Contabo deny rate 0", c.Rules[1])
	}
}

func TestApplyAsnFormRejects(t *testing.T) {
	cases := []struct {
		name string
		set  func(url.Values)
	}{
		{"dup ASN", func(f url.Values) {
			f["asn_number"] = []string{"16509", "AS16509"}
			f["asn_action"] = []string{"deny", "skip"}
			f.Set("asn_enabled_0", "1")
			f.Set("asn_enabled_1", "1")
		}},
		{"dup org", func(f url.Values) {
			f["asn_number"] = []string{"OVH", "ovh"} // case-insensitive dup
			f["asn_action"] = []string{"deny", "deny"}
			f.Set("asn_enabled_0", "1")
			f.Set("asn_enabled_1", "1")
		}},
		{"bad action", func(f url.Values) {
			f["asn_number"] = []string{"16509"}
			f["asn_action"] = []string{"nonsense"}
			f.Set("asn_enabled_0", "1")
		}},
		{"bad provider action", func(f url.Values) {
			f.Set("asn_provider_enabled_google", "1")
			f.Set("asn_provider_action_google", "bogus")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			form := url.Values{}
			c.set(form)
			r := httptest.NewRequest("POST", "/save", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			_ = r.ParseForm()
			var cfg settings.AsnConfig
			if err := applyAsnForm(&cfg, r); err == nil {
				t.Errorf("%s: expected error, got nil", c.name)
			}
		})
	}
}
