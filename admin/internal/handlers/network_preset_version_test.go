package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The trusted-LB and HTTPS-redirect-exempt presets on the network tab used to
// render without a version; they now carry a "since vX.Y.Z" label like every
// other preset.
func TestNetworkTabPresetsCarryVersion(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest("GET", "/unmask/admin/settings/network/", nil)
	req.SetPathValue("tab", "network")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("network tab status %d", rr.Code)
	}
	body := rr.Body.String()

	// Both preset kinds render...
	if !strings.Contains(body, `name="trusted_lb_preset"`) {
		t.Fatal("trusted-LB presets not rendered on the network tab")
	}
	if !strings.Contains(body, `name="redirect_exempt_preset_enabled"`) {
		t.Fatal("redirect-exempt presets not rendered on the network tab")
	}
	// ...and now carry a version label (they are all v0.1.0-era baseline presets).
	if !strings.Contains(body, "since v0.1.0") {
		t.Error("network-tab presets are missing the 'since vX.Y.Z' version label")
	}
}
