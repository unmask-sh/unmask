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

func TestAIEndpointHost(t *testing.T) {
	cases := map[string]string{
		"":                                "",
		"   ":                             "",
		"http://127.0.0.1:11434":          "127.0.0.1:11434",
		"HTTPS://Api.Example.com/v1/":     "api.example.com",
		"https://api.example.com":         "api.example.com",
		"https://api.example.com:8443/v1": "api.example.com:8443",
		"127.0.0.1:11434":                 "127.0.0.1:11434",
	}
	for in, want := range cases {
		if got := aiEndpointHost(in); got != want {
			t.Errorf("aiEndpointHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// The stored key follows its destination: a change of provider or of the
// endpoint's host without a new key drops it; a path, a scheme or a case
// change does not, and a typed key is taken as it is.
func TestApplyAIAdvisorFormDropsKeyWhenDestinationChanges(t *testing.T) {
	apply := func(c settings.AIAdvisorConfig, form url.Values) (settings.AIAdvisorConfig, bool) {
		req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		cleared := applyAIAdvisorForm(&c, req)
		return c, cleared
	}
	cases := []struct {
		name        string
		stored      settings.AIAdvisorConfig
		form        url.Values
		wantKey     string
		wantCleared bool
	}{
		{"unchanged", settings.AIAdvisorConfig{Provider: "anthropic", APIKey: "k"},
			url.Values{"ai_provider": {"anthropic"}}, "k", false},
		{"endpoint set", settings.AIAdvisorConfig{Provider: "anthropic", APIKey: "k"},
			url.Values{"ai_provider": {"anthropic"}, "ai_endpoint": {"https://proxy.example/v1"}}, "", true},
		{"endpoint path, case and slash", settings.AIAdvisorConfig{Provider: "openai", Endpoint: "https://proxy.example/v1", APIKey: "k"},
			url.Values{"ai_provider": {"openai"}, "ai_endpoint": {"HTTP://Proxy.Example/openai/v1/"}}, "k", false},
		{"endpoint replaced", settings.AIAdvisorConfig{Provider: "openai", Endpoint: "https://proxy.example/v1", APIKey: "k"},
			url.Values{"ai_provider": {"openai"}, "ai_endpoint": {"https://proxy.example:8443/v1"}}, "", true},
		{"endpoint dropped", settings.AIAdvisorConfig{Provider: "openai", Endpoint: "https://proxy.example/v1", APIKey: "k"},
			url.Values{"ai_provider": {"openai"}, "ai_endpoint": {""}}, "", true},
		{"provider changed", settings.AIAdvisorConfig{Provider: "anthropic", APIKey: "k"},
			url.Values{"ai_provider": {"openai"}}, "", true},
		{"provider changed with a key", settings.AIAdvisorConfig{Provider: "anthropic", APIKey: "k"},
			url.Values{"ai_provider": {"openai"}, "ai_api_key": {"k2"}}, "k2", false},
		{"endpoint set with a key", settings.AIAdvisorConfig{Provider: "anthropic", APIKey: "k"},
			url.Values{"ai_provider": {"anthropic"}, "ai_endpoint": {"https://proxy.example"}, "ai_api_key": {"k2"}}, "k2", false},
		{"cleared by hand", settings.AIAdvisorConfig{Provider: "anthropic", APIKey: "k"},
			url.Values{"ai_provider": {"anthropic"}, "ai_api_key": {"-"}}, "", false},
		{"nothing stored", settings.AIAdvisorConfig{Provider: "anthropic"},
			url.Values{"ai_provider": {"ollama"}, "ai_endpoint": {"http://127.0.0.1:11434"}}, "", false},
	}
	for _, c := range cases {
		got, cleared := apply(c.stored, c.form)
		if got.APIKey != c.wantKey || cleared != c.wantCleared {
			t.Errorf("%s: key %q cleared=%v, want key %q cleared=%v", c.name, got.APIKey, cleared, c.wantKey, c.wantCleared)
		}
	}
}

// The whole save: the key is gone from the file, and the redirect carries
// the flag the tab's banner reads, which then says so.
func TestAIAdvisorSaveFlagsDroppedKey(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()
	emptyPath := filepath.Join(dir, "empty.yml")
	if err := os.WriteFile(emptyPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := settings.Load(emptyPath)
	if err != nil {
		t.Fatal(err)
	}
	s.Server.BasePath = "/unmask"
	s.Nginx.OutputDir = dir
	s.CommunityBans.MapDir = dir
	s.AIAdvisor = settings.AIAdvisorConfig{Enabled: true, Provider: "anthropic", APIKey: "k-stored"}
	cfgPath := filepath.Join(dir, "config.yml")
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	loaded, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	h.SetSettings(loaded)

	form := url.Values{"ai_enabled": {"1"}, "ai_provider": {"anthropic"}, "ai_endpoint": {"https://proxy.example/v1"}}
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=ai-advisor", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.AdminSettingsSave(rr, req)
	loc := rr.Header().Get("Location")
	if rr.Code != http.StatusFound || !strings.Contains(loc, "credential_cleared=ai_api_key") {
		t.Fatalf("save: want a 302 flagged credential_cleared=ai_api_key, got %d -> %s", rr.Code, loc)
	}
	if got, _ := settings.Load(cfgPath); got.AIAdvisor.APIKey != "" || got.AIAdvisor.Endpoint != "https://proxy.example/v1" {
		t.Errorf("file after the save: %+v", got.AIAdvisor)
	}

	req = httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/ai-advisor/?saved=1&section=ai-advisor&credential_cleared=ai_api_key", nil)
	req.SetPathValue("tab", "ai-advisor")
	req.Header.Set("Accept-Language", "en")
	rr = httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "the saved API key was dropped") {
		t.Errorf("the ai-advisor tab does not say the key was dropped (HTTP %d)", rr.Code)
	}
}
