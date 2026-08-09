package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The bypass-ips tab must render the GCP LB health-check stats-exclude toggle
// (checkbox + its CIDRs + resolved i18n).
func TestBypassIPsTabShowsGCPLBHCToggle(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest("GET", "/unmask/admin/settings/bypass-ips/", nil)
	req.SetPathValue("tab", "bypass-ips")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("bypass-ips tab status %d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, `name="stats_exclude_gcp_lb_hc"`) {
		t.Error("GCP LB HC toggle checkbox missing from the bypass-ips tab")
	}
	if !strings.Contains(body, "35.191.0.0/16") {
		t.Error("GCP HC CIDR not shown in the toggle's CIDR list")
	}
	if strings.Contains(body, "settings.stats_exclude.gcp_lb_hc_label") {
		t.Error("raw i18n key rendered -- the gcp_lb_hc_label translation is missing")
	}
}
