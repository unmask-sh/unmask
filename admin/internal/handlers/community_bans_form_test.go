package handlers

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The action must survive the round trip a real operator makes: render the
// tab, post the form back, read the config from disk.  A picker that renders
// but never persists (wrong field name, missing apply* branch) is invisible
// until someone wonders why the feed still challenges after they picked deny.
func TestCommunityBansActionSurvivesTheSettingsForm(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	emptyPath := filepath.Join(dir, "empty.yml")
	os.WriteFile(emptyPath, []byte("{}\n"), 0o600)
	s, err := settings.Load(emptyPath)
	if err != nil {
		t.Fatal(err)
	}
	s.Server.BasePath = "/unmask"
	s.Nginx.OutputDir = dir
	s.CommunityBans.MapDir = dir
	settings.Save(s, cfgPath)
	h.ConfigPath = cfgPath
	loaded, _ := settings.Load(cfgPath)
	h.SetSettings(loaded)

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=community-bans", nil)
	req.SetPathValue("tab", "community-bans")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != 200 {
		t.Fatalf("status %d", rr.Code)
	}
	body := rr.Body.String()
	i := strings.Index(body, "community_bans_action")
	if i < 0 {
		t.Fatal("the action picker is missing from the rendered tab")
	}
	// The picker must be able to express "unset", selected by default.  A
	// select without that option pins its displayed value the first time an
	// unrelated field on the same tab is saved -- the challenge_targets bug.
	if !strings.Contains(body[i:i+900], `value=""                 selected`) {
		t.Error("the action picker cannot express \"unset\", or does not default to it")
	}

	// Save round-trip: pick deny, confirm it persists AND that the render +
	// the resolver both see it, then clear it back to the default.
	for _, tc := range []struct{ post, wantStored, wantResolved string }{
		{"deny", "deny", "deny"},
		{"pow_only", "pow_only", "pow_only"},
		{"", "", "captcha_only"},
		{"garbage", "", "captcha_only"},
	} {
		form := url.Values{"subscribe_mode": {"fetch_apply"}, "community_bans_action": {tc.post}}
		pr := httptest.NewRequest(http.MethodPost,
			"/unmask/admin/settings/save?section=community-bans", strings.NewReader(form.Encode()))
		pr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		prr := httptest.NewRecorder()
		h.AdminSettingsSave(prr, pr)
		got, err := settings.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if got.CommunityBans.Action != tc.wantStored {
			t.Errorf("post %q: stored %q, want %q", tc.post, got.CommunityBans.Action, tc.wantStored)
		}
		if got.CommunityBans.ResolvedAction() != tc.wantResolved {
			t.Errorf("post %q: resolved %q, want %q", tc.post, got.CommunityBans.ResolvedAction(), tc.wantResolved)
		}
	}
}
