package handlers

import (
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestApplyGeoFormRate pins the geo tab's rate wiring, mirroring the ASN form:
// a per-row geo_rate parses into GeoRule.RatePerMin (nullable -- blank stays
// nil to inherit, an explicit number incl. 0 becomes a pointer), and
// geo_default_rate parses into GeoConfig.DefaultRatePerMin.
func TestApplyGeoFormRate(t *testing.T) {
	form := url.Values{}
	form.Set("geo_default_action", "deny")
	form.Set("geo_default_rate", "200")
	form["geo_country"] = []string{"CN", "BR", "JP"}
	form["geo_label"] = []string{"", "throttled", ""}
	form["geo_action"] = []string{"deny", "captcha_only", "deny"}
	form["geo_rate"] = []string{"", "60", "0"} // CN inherits, BR explicit 60, JP explicit 0
	form.Set("geo_enabled_0", "1")
	form.Set("geo_enabled_1", "1")
	form.Set("geo_enabled_2", "1")

	r := httptest.NewRequest("POST", "/save?section=geo", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	var c settings.GeoConfig
	if err := applyGeoForm(&c, r); err != nil {
		t.Fatalf("applyGeoForm: %v", err)
	}
	if c.DefaultRatePerMin != 200 {
		t.Errorf("geo_default_rate=200 must persist, got %d", c.DefaultRatePerMin)
	}
	if len(c.Rules) != 3 {
		t.Fatalf("want 3 rules, got %d (%+v)", len(c.Rules), c.Rules)
	}
	if c.Rules[0].Country != "CN" || c.Rules[0].RatePerMin != nil {
		t.Errorf("CN row = %+v, want blank rate -> nil (inherit)", c.Rules[0])
	}
	if c.Rules[1].Country != "BR" || c.Rules[1].RatePerMin == nil || *c.Rules[1].RatePerMin != 60 {
		t.Errorf("BR row = %+v, want explicit rate 60", c.Rules[1])
	}
	if c.Rules[2].Country != "JP" || c.Rules[2].RatePerMin == nil || *c.Rules[2].RatePerMin != 0 {
		t.Errorf("JP row = %+v, want explicit rate 0 (no throttle)", c.Rules[2])
	}
	// Effective resolution: CN inherits the default 200, JP's explicit 0 opts
	// out, so only CN and BR are rate-mode.
	rr := c.RateRules()
	if len(rr) != 2 {
		t.Fatalf("RateRules() = %+v, want CN@200 + BR@60", rr)
	}
}
