package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The redirect-exempt rows are handed to the template as a map, not a struct,
// so a field the map does not carry renders as nothing and the form posts an
// empty date -- which the server reads as "no date" and restamps.  The dates
// survived the save path all along; the row simply never sent them back.
func TestRedirectExemptRowsCarryTheirDates(t *testing.T) {
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	s.Nginx.HTTPSRedirectExempt.Rules = []settings.HTTPSRedirectExemptRule{
		{Type: "path", Pattern: "^/health", Title: "LB", CreatedAt: 1740000000},
	}
	cfg := filepath.Join(t.TempDir(), "config.yml")
	if err := settings.Save(s, cfg); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfg
	h.SetSettings(s)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=network", nil)
	req.SetPathValue("tab", "network")
	h.AdminSettingsIndex(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, `name="re_created_at" value="1740000000"`) {
		t.Errorf("the re row does not carry its add date back into the form")
	}
	// Post it back the way the form does.
	f := url.Values{}
	f["re_type"] = []string{"path"}
	f["re_pattern"] = []string{"^/health"}
	f["re_title"] = []string{"LB"}
	f["re_enabled"] = []string{"1"}
	f["re_created_at"] = []string{"1740000000"}
	f["re_updated_at"] = []string{"0"}
	req = httptest.NewRequest(http.MethodPost,
		"/unmask/admin/settings/save?section=network", strings.NewReader(f.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	h.AdminSettingsSave(httptest.NewRecorder(), req)
	saved, err := settings.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i, r := range saved.Nginx.HTTPSRedirectExempt.Rules {
		t.Logf("re[%d] %s created=%d updated=%d", i, r.Pattern, r.CreatedAt, r.UpdatedAt)
		if r.CreatedAt != 1740000000 {
			t.Errorf("re[%d]: add date %d, want 1740000000 -- a save restamped it", i, r.CreatedAt)
		}
	}
}
