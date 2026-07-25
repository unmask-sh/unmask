package handlers

import (
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func asnForm(t *testing.T, form url.Values) *settings.AsnConfig {
	t.Helper()
	r := httptest.NewRequest("POST", "/save?section=geo", strings.NewReader(form.Encode()))
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

// TestApplyAsnForm pins the ASN save: "AS" prefix and bare numbers both parse,
// the default "skip" stores as unset, per-row action/label/enabled round-trip,
// and duplicates / non-numeric input are rejected.
func TestApplyAsnForm(t *testing.T) {
	form := url.Values{}
	form.Set("asn_default_action", "skip") // resolve default -> stored unset
	form["asn_number"] = []string{"AS16509", "14061"}
	form["asn_label"] = []string{"Amazon AWS", ""}
	form["asn_action"] = []string{"deny", "captcha_only"}
	form.Set("asn_enabled_0", "1")
	// row 1 enabled unset -> disabled

	c := asnForm(t, form)
	if c.DefaultAction != "" {
		t.Errorf("default skip must store as unset, got %q", c.DefaultAction)
	}
	if len(c.Rules) != 2 {
		t.Fatalf("want 2 rules, got %d", len(c.Rules))
	}
	r0 := c.Rules[0]
	if r0.ASN != 16509 || r0.Action != "deny" || r0.Label != "Amazon AWS" || !r0.Enabled {
		t.Errorf("row0 = %+v, want ASN16509 deny 'Amazon AWS' enabled", r0)
	}
	r1 := c.Rules[1]
	if r1.ASN != 14061 || r1.Action != "captcha_only" || r1.Enabled {
		t.Errorf("row1 = %+v, want ASN14061 captcha_only disabled", r1)
	}
}

func TestApplyAsnFormRejects(t *testing.T) {
	cases := []struct {
		name string
		nums []string
		acts []string
	}{
		{"non-numeric", []string{"notanumber"}, []string{"deny"}},
		{"zero", []string{"0"}, []string{"deny"}},
		{"duplicate", []string{"16509", "AS16509"}, []string{"deny", "skip"}},
		{"bad action", []string{"16509"}, []string{"nonsense"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			form := url.Values{}
			form["asn_number"] = c.nums
			form["asn_action"] = c.acts
			for i := range c.nums {
				form.Set("asn_enabled_"+strconv.Itoa(i), "1")
			}
			r := httptest.NewRequest("POST", "/save", strings.NewReader(form.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			_ = r.ParseForm()
			var cfg settings.AsnConfig
			if err := applyAsnForm(&cfg, r); err == nil {
				t.Errorf("%s: expected error, got nil (rules=%+v)", c.name, cfg.Rules)
			}
		})
	}
}
