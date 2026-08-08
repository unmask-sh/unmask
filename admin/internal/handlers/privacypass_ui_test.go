package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The privacy-pass settings tab must render its form fully.  A missing data key
// (.PrivacyPass.*) or a template error would silently truncate the page at HTTP
// 200, so assert the controls render, the configured issuer shows, AND the
// document closes.
func TestSettingsPrivacyPassTabRenders(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Nginx.AdvancedEnabled = true // master gate: gated tabs redirect when off
		s.Nginx.PrivacyPass = settings.PrivacyPassConfig{
			Enabled:              true,
			EnabledIssuerPresets: []string{"cloudflare"},
			Issuers:              []settings.PrivacyPassIssuer{{Name: "issuer.example", Key: "QUJD"}},
		}
	})
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=privacy-pass", nil)
	req.SetPathValue("tab", "privacy-pass")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`section=privacy-pass`,
		`name="enabled" value="1" checked`,             // Enabled=true → box pre-checked
		`name="pp_preset" value="cloudflare" checked`,  // enabled issuer preset
		`card-badge preset`,                            // preset section badge
		`card-badge custom`,                            // custom section badge
		`name="pp_issuer_name" value="issuer.example"`, // issuer row name field
		`>QUJD</textarea>`,                             // key in the row textarea
		`ppAddIssuer()`,                                // add-row button
		`</html>`,                                      // page must not truncate mid-template
	} {
		if !strings.Contains(body, want) {
			t.Errorf("privacy-pass tab render missing %q", want)
		}
	}
}

func TestApplyPrivacyPassForm(t *testing.T) {
	form := url.Values{}
	form.Set("enabled", "1")
	form.Add("pp_preset", "cloudflare") // checked issuer presets
	form.Add("pp_preset", "fastly")
	// Parallel-indexed name/key rows; a row with an empty side is dropped.
	form.Add("pp_issuer_name", "issuer.example")
	form.Add("pp_issuer_key", "QUJDREVG")
	form.Add("pp_issuer_name", "   ") // empty name → skip
	form.Add("pp_issuer_key", "orphan-key")
	form.Add("pp_issuer_name", "emptykey.example")
	form.Add("pp_issuer_key", "   ") // empty key → skip
	form.Add("pp_issuer_name", "  b.example  ")
	form.Add("pp_issuer_key", "  S0VZ  ") // trimmed both sides
	req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var c settings.PrivacyPassConfig
	applyPrivacyPassForm(&c, req)

	if !c.Enabled {
		t.Error("enabled not set")
	}
	if len(c.Issuers) != 2 {
		t.Fatalf("want 2 issuers, got %d: %+v", len(c.Issuers), c.Issuers)
	}
	if c.Issuers[0] != (settings.PrivacyPassIssuer{Name: "issuer.example", Key: "QUJDREVG"}) {
		t.Errorf("issuer[0] = %+v", c.Issuers[0])
	}
	if c.Issuers[1] != (settings.PrivacyPassIssuer{Name: "b.example", Key: "S0VZ"}) {
		t.Errorf("issuer[1] = %+v (trim failed?)", c.Issuers[1])
	}
	if strings.Join(c.EnabledIssuerPresets, ",") != "cloudflare,fastly" {
		t.Errorf("EnabledIssuerPresets = %v, want [cloudflare fastly]", c.EnabledIssuerPresets)
	}

	// Unchecking enabled + no rows clears everything.
	req2 := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(url.Values{}.Encode()))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	applyPrivacyPassForm(&c, req2)
	if c.Enabled || len(c.Issuers) != 0 || len(c.EnabledIssuerPresets) != 0 {
		t.Errorf("clear failed: enabled=%v issuers=%+v presets=%v", c.Enabled, c.Issuers, c.EnabledIssuerPresets)
	}
}
