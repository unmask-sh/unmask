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

// The AI-advisor tab must render every field, all the way to the closing tag.
// A template error midway (the first cut of this tab read the section off the
// wrong struct) leaves a page that looks fine at a glance -- heading, intro --
// and simply has no inputs, which the wiring test above did not notice
// because the <form> tag comes before the failure point.
func TestAIAdvisorTabRendersEveryField(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/ai-advisor/", nil)
	req.SetPathValue("tab", "ai-advisor")
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("ai-advisor tab: want 200, got %d", rr.Code)
	}
	body := rr.Body.String()
	for _, want := range []string{
		`name="ai_enabled"`, `name="ai_provider"`, `name="ai_model"`, `name="ai_endpoint"`,
		`name="ai_api_key"`, `name="ai_notify_enabled"`, `name="ai_notify_interval"`,
		`name="ai_notify_min_score"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("ai-advisor tab is missing %s", want)
		}
	}
	if !strings.Contains(body, "</html>") {
		t.Fatal("ai-advisor tab was cut short: no closing </html> (template error mid-render)")
	}
	// The picker: a select with the presets and a custom escape hatch, over
	// the text field that is actually submitted.
	for _, want := range []string{`id="ai_model_sel"`, `value="__custom__"`, `value="claude-opus-5"`, `id="ai_model_fetch"`} {
		if !strings.Contains(body, want) {
			t.Errorf("model picker is missing %s", want)
		}
	}
	// Every provider's presets and defaults ride along, so the picker can
	// follow the provider select client-side (it used to keep showing the
	// saved provider's list -- Anthropic models under "openai").
	i := strings.Index(body, `id="ai_model_presets"`)
	if i < 0 {
		t.Fatal("the presets blob is missing")
	}
	blob := body[i:]
	if j := strings.Index(blob, "</script>"); j > 0 {
		blob = blob[:j]
	}
	for _, want := range []string{`"gpt-4o-mini"`, `"llama3.1"`, `"claude-opus-5"`, `"defaults"`, `"openai":"gpt-4o-mini"`} {
		if !strings.Contains(blob, want) {
			t.Errorf("presets blob is missing %s", want)
		}
	}
	// The key itself must never be in the page, set or not.
	if strings.Contains(body, `name="ai_api_key" value="`) && !strings.Contains(body, `name="ai_api_key" value=""`) {
		t.Error("the API key field must render empty")
	}
}

// The picker's live list comes from the SAVED provider with the saved key,
// and the key never appears in the response.
func TestAdminAIModelsListsFromSavedProvider(t *testing.T) {
	var gotKey string
	stub := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		if r.URL.Path != "/v1/models" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":[{"id":"claude-opus-5","display_name":"Claude Opus 5"},{"id":"claude-sonnet-5","display_name":"Claude Sonnet 5"}],"has_more":false}`))
	}))
	defer stub.Close()

	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.AIAdvisor.Enabled = true
	cur.AIAdvisor.Provider = "anthropic"
	cur.AIAdvisor.APIKey = "k-secret-marker"
	cur.AIAdvisor.Endpoint = stub.URL
	h.settingsPtr.Store(&cur)

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/api/ai-models?endpoint=http://attacker.invalid", nil)
	rr := httptest.NewRecorder()
	h.AdminAIModels(rr, req)
	body := rr.Body.String()
	if rr.Code != http.StatusOK || !strings.Contains(body, `"claude-sonnet-5"`) {
		t.Fatalf("expected the stub's models, got %d %s", rr.Code, body)
	}
	if gotKey != "k-secret-marker" {
		t.Errorf("the saved key was not used: %q", gotKey)
	}
	if strings.Contains(body, "k-secret-marker") {
		t.Error("the key leaked into the response")
	}
}

// The tab must survive the round trip a real operator makes: post the form,
// read the config from disk.  The section allowlist in AdminSettingsSave is a
// separate list from the apply switch; the tab shipped with its apply branch
// in place and its name missing from the list, so every save from the UI was
// a 400 "unknown section" -- unnoticed because the fleet key went in through
// config.yml.  The key stays write-only: empty keeps it, "-" clears it.
func TestAIAdvisorSettingsSaveRoundTrip(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yml")
	emptyPath := filepath.Join(dir, "empty.yml")
	_ = os.WriteFile(emptyPath, []byte("{}\n"), 0o600)
	s, err := settings.Load(emptyPath)
	if err != nil {
		t.Fatal(err)
	}
	s.Server.BasePath = "/unmask"
	s.Nginx.OutputDir = dir
	s.CommunityBans.MapDir = dir
	if err := settings.Save(s, cfgPath); err != nil {
		t.Fatal(err)
	}
	h.ConfigPath = cfgPath
	loaded, _ := settings.Load(cfgPath)
	h.SetSettings(loaded)

	post := func(form url.Values) int {
		pr := httptest.NewRequest(http.MethodPost, "/unmask/admin/settings/save?section=ai-advisor", strings.NewReader(form.Encode()))
		pr.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		prr := httptest.NewRecorder()
		h.AdminSettingsSave(prr, pr)
		return prr.Code
	}
	if code := post(url.Values{
		"ai_enabled": {"1"}, "ai_provider": {"anthropic"}, "ai_model": {"claude-sonnet-5"},
		"ai_endpoint": {"http://127.0.0.1:9"}, "ai_api_key": {"k-round-trip"},
		"ai_notify_enabled": {"1"}, "ai_notify_interval": {"12"}, "ai_notify_min_score": {"7"},
	}); code >= 400 {
		t.Fatalf("saving the ai-advisor section: HTTP %d", code)
	}
	got, err := settings.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	ai := got.AIAdvisor
	if !ai.Enabled || ai.Provider != "anthropic" || ai.Model != "claude-sonnet-5" || ai.Endpoint != "http://127.0.0.1:9" || ai.APIKey != "k-round-trip" ||
		!ai.NotifyEnabled || ai.NotifyIntervalHours != 12 || ai.NotifyMinScore != 7 {
		t.Fatalf("the saved section did not persist: %+v", ai)
	}
	// An empty key field keeps the stored key; "-" clears it.
	if code := post(url.Values{"ai_enabled": {"1"}, "ai_provider": {"anthropic"}, "ai_api_key": {""}}); code >= 400 {
		t.Fatalf("second save: HTTP %d", code)
	}
	if got, _ = settings.Load(cfgPath); got.AIAdvisor.APIKey != "k-round-trip" {
		t.Errorf("an empty key field must keep the key, got %q", got.AIAdvisor.APIKey)
	}
	if code := post(url.Values{"ai_provider": {"anthropic"}, "ai_api_key": {"-"}}); code >= 400 {
		t.Fatalf("third save: HTTP %d", code)
	}
	if got, _ = settings.Load(cfgPath); got.AIAdvisor.APIKey != "" || got.AIAdvisor.Enabled {
		t.Errorf("\"-\" must clear the key and an unticked box must disable: %+v", got.AIAdvisor)
	}
}
