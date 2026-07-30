package handlers

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The policy checkbox has to survive a save round trip, and the per-pattern
// rows it outranks must still be written -- turning the policy off is what
// brings them back, so losing them here would make the switch one-way.
func TestRequireRangeVerificationSaveRoundTrip(t *testing.T) {
	// adminScalarSiteSave / AdminSettingsSave persist through settings.Save,
	// so the handler needs a real config file to write to.
	var base settings.Settings
	base.Server.BasePath = "/unmask"
	h := newTestHandler(t)
	cfgPath := filepath.Join(t.TempDir(), "config.yml")
	if err := settings.Save(base, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	h.SetSettings(base)

	page := func() string {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=ua-filter", nil)
		rr := httptest.NewRecorder()
		h.AdminSettingsIndex(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("ua-filter tab: %d", rr.Code)
		}
		return rr.Body.String()
	}
	if !strings.Contains(page(), `name="require_range_verification"`) {
		t.Fatal("the ua-filter tab does not offer the policy checkbox")
	}
	// Off by default: this changes who gets rescued, so it is opt-in.
	if load0, _ := settings.Load(cfgPath); load0.Nginx.SearchBots.RequireRangeVerification {
		t.Error("the policy must default to off")
	}

	save := func(form string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost,
			"/unmask/admin/settings/save?section=ua-filter", strings.NewReader(form))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rr := httptest.NewRecorder()
		h.AdminSettingsSave(rr, req)
		if rr.Code != http.StatusSeeOther && rr.Code != http.StatusFound {
			t.Fatalf("save: want redirect, got %d: %s", rr.Code, rr.Body.String())
		}
	}

	// AdminSettingsSave persists to disk (fresh-read -> modify -> atomic
	// save), so assert against the file rather than the in-memory snapshot.
	load := func() settings.Nginx {
		t.Helper()
		got, err := settings.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		return got.Nginx
	}

	save(`require_range_verification=1&upstream_ua_enabled=Googlebot%5C%2F`)
	sb := load().SearchBots
	if !sb.RequireRangeVerification {
		t.Error("policy did not persist")
	}
	if len(sb.UpstreamUAEnabled) == 0 {
		t.Error("the per-pattern opt-in was dropped; switching the policy off would not restore it")
	}
	// The in-memory swap happens only after a successful nginx render, which
	// this environment has no config for -- the save itself completed (the
	// file above proves it), so publish what was written and check the form
	// comes back reflecting it.
	if reloaded, err := settings.Load(cfgPath); err == nil {
		h.SetSettings(reloaded)
	}
	if !strings.Contains(page(), `name="require_range_verification" value="1" checked`) {
		t.Error("the saved policy does not render as checked")
	}

	// Unchecking a checkbox submits nothing at all, so the absent field has
	// to read as false rather than leaving the stored value alone.
	save(`upstream_ua_enabled=Googlebot%5C%2F`)
	if load().SearchBots.RequireRangeVerification {
		t.Error("unchecking the policy did not turn it off")
	}
}
