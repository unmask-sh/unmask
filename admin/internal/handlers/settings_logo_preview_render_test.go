package handlers

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// The "Page design" (theme) tab must render the live-logo-preview wiring: the
// thumbnail elements, the file input, the upload endpoint URL, and the shared
// token plumbing the deny + challenge preview scripts read.  A missing marker
// means the preview silently stops reflecting a picked logo.
func TestSettingsThemeTabLogoPreviewWiring(t *testing.T) {
	h := newTestHandler(t)
	s := *h.cfg()
	s.Server.BasePath = "/unmask"
	h.SetSettings(s)

	req := httptest.NewRequest("GET", "/unmask/admin/settings/?tab=theme", nil)
	rec := httptest.NewRecorder()
	h.AdminSettingsIndex(rec, req)
	if rec.Code != 200 {
		t.Fatalf("render status = %d", rec.Code)
	}
	body := rec.Body.String()

	for _, m := range []string{
		`id="branding-logo-file"`,
		`id="branding-logo-thumb"`,
		`id="branding-logo-thumb-wrap"`,
		`unmask:logo-preview`,                 // the broadcast event both preview scripts listen for
		`__unmaskPreviewLogo`,                 // the shared token flag
		`function logoQS(`,                    // deny IIFE helper
		`function logoPreviewQS(`,             // challenge IIFE helper
		`/unmask/admin/test/preview-logo`,     // the ephemeral upload endpoint
		`settings.branding.logo_selected`,     // would appear only if untranslated; sanity that the i18n key resolves below
	} {
		// the i18n key itself must NOT appear literally (it should be translated)
		if m == `settings.branding.logo_selected` {
			if strings.Contains(body, m) {
				t.Errorf("i18n key %q rendered untranslated", m)
			}
			continue
		}
		if !strings.Contains(body, m) {
			t.Errorf("rendered theme tab missing marker %q", m)
		}
	}
}
