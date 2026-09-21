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
		{"", "", "pow_then_captcha"},
		{"garbage", "", "pow_then_captcha"},
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

// The liveness opt-out has to survive being turned off, which is the whole
// point of it and the one way this kind of field usually breaks: a bool that
// defaults to true and carries `omitempty` is dropped from the file when the
// operator sets it to false, and Load then hands back the default -- silently
// putting the install back into the count it just opted out of.
//
// So: render (checked, because the default is on), post the form without the
// box, and read the config back off disk.  The Save/Load round trip is the
// assertion that matters; the render is there because a wrong template key
// leaves the tab a 200 with no inputs.
func TestCommunityBansLivenessOptOutPersists(t *testing.T) {
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
	if !s.CommunityBans.PublishLiveness {
		t.Fatal("publish_liveness should default to on, or the hub can count nothing")
	}
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
	if !strings.Contains(body, `name="publish_liveness" value="1" checked`) {
		t.Error("the liveness checkbox is missing from the tab, or does not render the default as on")
	}
	if !strings.Contains(body, "</html>") {
		t.Error("the tab truncated mid-template (usually a template key that does not exist)")
	}

	// Unchecked boxes are simply absent from the POST body.
	for _, tc := range []struct {
		name string
		form url.Values
		want bool
	}{
		{"box unchecked", url.Values{"subscribe_mode": {"fetch_apply"}}, false},
		{"box checked", url.Values{"subscribe_mode": {"fetch_apply"}, "publish_liveness": {"1"}}, true},
	} {
		pr := httptest.NewRequest(http.MethodPost,
			"/unmask/admin/settings/save?section=community-bans", strings.NewReader(tc.form.Encode()))
		pr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		h.AdminSettingsSave(httptest.NewRecorder(), pr)
		got, err := settings.Load(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if got.CommunityBans.PublishLiveness != tc.want {
			t.Errorf("%s: publish_liveness read back %v, want %v", tc.name, got.CommunityBans.PublishLiveness, tc.want)
		}
	}
}
