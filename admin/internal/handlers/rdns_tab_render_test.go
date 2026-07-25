package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestBypassIPsTabRendersRDNS pins that the reverse-DNS card renders on the
// bypass-ips tab: the controls exist, the stored state is reflected, and no raw
// i18n key leaks (a missing dict entry).
func TestBypassIPsTabRendersRDNS(t *testing.T) {
	h := newTestHandler(t)
	h.updateSettingsInMemory(func(s *settings.Settings) {
		s.Nginx.CrawlerVerify = settings.CrawlerVerifyConfig{Enabled: true, ForgedAction: settings.GeoActionDeny}
	})
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=bypass-ips", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`name="crawler_verify_enabled"`,
		`name="crawler_verify_forged_action"`,
		`crawler_verify_enabled" value="1" checked`, // Enabled=true reflected
		`value="deny"             selected`,         // ForgedAction=deny reflected
	} {
		if !strings.Contains(body, want) {
			t.Errorf("bypass-ips tab missing %q", want)
		}
	}
	if strings.Contains(body, "settings.rdns.") {
		t.Error("raw settings.rdns.* i18n key leaked (missing dict entry)")
	}
}
