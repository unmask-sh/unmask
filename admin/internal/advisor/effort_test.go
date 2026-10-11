package advisor

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func TestEffortDefault(t *testing.T) {
	for _, c := range []struct {
		model        string
		def          string
		takes, known bool
	}{
		{"claude-opus-5-5", "medium", true, true},
		{"claude-haiku-5-5", "medium", true, true},
		{"claude-sonnet-5-5", "high", true, true},
		{"claude-opus-4-5-20251101", "high", true, true}, // the dated id
		{"claude-haiku-4-5-20251001", "", false, true},   // takes none
		{"claude-3-5-sonnet-latest", "", false, true},    // the -latest alias
		{"gpt-5.1", "none", true, true},
		{"gpt-5-mini-2025-08-07", "medium", true, true},
		{"gpt-5-pro", "high", true, true},
		{"gpt-5.1-codex", "", true, false}, // a variant is not its base
		{"gpt-4o-mini", "", false, true},
		{"llama3.2", "", true, false},
		{"", "", true, false},
	} {
		def, takes, known := EffortDefault(c.model)
		if def != c.def || takes != c.takes || known != c.known {
			t.Errorf("%q: %q %v %v, want %q %v %v", c.model, def, takes, known, c.def, c.takes, c.known)
		}
	}
}

func TestEffortToSend(t *testing.T) {
	if e := effortToSend("claude-haiku-4-5", "high"); e != "" {
		t.Errorf("a model that takes no effort was sent %q", e)
	}
	if e := effortToSend("claude-haiku-5-5", "low"); e != "low" {
		t.Errorf("haiku 5.5: %q", e)
	}
	if e := effortToSend("some-local-model", "low"); e != "low" {
		t.Errorf("an unknown model is held back: %q", e)
	}
	if e := effortToSend("claude-haiku-5-5", ""); e != "" {
		t.Errorf("nothing picked: %q", e)
	}
}

// The advisor's review carries the effort too, beside its output format,
// and leaves it out for a model that takes none.
func TestReviewSendsEffort(t *testing.T) {
	body := anthropicReviewBody(settings.AIAdvisorConfig{Provider: "anthropic", Model: "claude-opus-5-5", Effort: "low"}, "u")
	oc, _ := body["output_config"].(map[string]any)
	if oc["effort"] != "low" || oc["format"] == nil {
		t.Errorf("anthropic output_config: %v", oc)
	}
	body = anthropicReviewBody(settings.AIAdvisorConfig{Provider: "anthropic", Model: "claude-haiku-4-5", Effort: "low"}, "u")
	if oc, _ := body["output_config"].(map[string]any); oc["effort"] != nil {
		t.Errorf("haiku 4.5 was sent an effort: %v", oc)
	}
	body = openaiReviewBody(settings.AIAdvisorConfig{Provider: "openai", Model: "gpt-5.5", Effort: "high"}, "u")
	if body["reasoning_effort"] != "high" {
		t.Errorf("openai reasoning_effort: %v", body["reasoning_effort"])
	}
	body = openaiReviewBody(settings.AIAdvisorConfig{Provider: "openai", Model: "gpt-4o", Effort: "high"}, "u")
	if _, ok := body["reasoning_effort"]; ok {
		t.Error("gpt-4o was sent an effort")
	}
}
