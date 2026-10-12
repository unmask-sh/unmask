package advisor

import (
	"strings"
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

// The pickers' order: the families by name, versions newest first, a base
// model before its variants, and a later dated ID of one name first.
func TestSortModels(t *testing.T) {
	ms := []ModelInfo{
		{ID: "claude-haiku-4-5-20251001", Label: "Claude Haiku 4.5"},
		{ID: "claude-opus-4-5-20251101", Label: "Claude Opus 4.5"},
		{ID: "claude-opus-5", Label: "Claude Opus 5"},
		{ID: "claude-fable-5", Label: "Claude Fable 5"},
		{ID: "claude-opus-5-5", Label: "Claude Opus 5.5"},
		{ID: "claude-haiku-5-5", Label: "Claude Haiku 5.5"},
		{ID: "claude-fable-5-1", Label: "Claude Fable 5.1"},
		{ID: "claude-opus-4-8", Label: "Claude Opus 4.8"},
		{ID: "claude-opus-4-10", Label: "Claude Opus 4.10"},
		{ID: "claude-sonnet-5-5", Label: "Claude Sonnet 5.5"},
	}
	SortModels(ms)
	var got []string
	for _, m := range ms {
		got = append(got, m.Label)
	}
	want := "Claude Fable 5.1,Claude Fable 5,Claude Haiku 5.5,Claude Haiku 4.5,Claude Opus 5.5,Claude Opus 5,Claude Opus 4.10,Claude Opus 4.8,Claude Opus 4.5,Claude Sonnet 5.5"
	if strings.Join(got, ",") != want {
		t.Errorf("anthropic:\n got %s\nwant %s", strings.Join(got, ","), want)
	}

	ids := []ModelInfo{{ID: "gpt-5"}, {ID: "gpt-4o"}, {ID: "gpt-5-mini"}, {ID: "gpt-5.2"}, {ID: "o3"}, {ID: "gpt-4.1"}, {ID: "o4-mini"}, {ID: "gpt-5.4-mini"}, {ID: "gpt-5.4"}, {ID: "o3-mini"}, {ID: "gpt-4o-2024-05-13"}}
	SortModels(ids)
	got = got[:0]
	for _, m := range ids {
		got = append(got, m.ID)
	}
	want = "gpt-5.4,gpt-5.4-mini,gpt-5.2,gpt-5,gpt-5-mini,gpt-4.1,gpt-4o,gpt-4o-2024-05-13,o4-mini,o3,o3-mini"
	if strings.Join(got, ",") != want {
		t.Errorf("openai:\n got %s\nwant %s", strings.Join(got, ","), want)
	}

	// Two IDs of one name: the later date first.
	same := []ModelInfo{{ID: "claude-x-20250101", Label: "Claude X"}, {ID: "claude-x-20251001", Label: "Claude X"}}
	SortModels(same)
	if same[0].ID != "claude-x-20251001" {
		t.Errorf("dated: %v", same)
	}
}

// max_tokens leaves room for the thinking by effort: the picked one, else
// the model's own default.  A model that takes no effort, or an unknown
// one at its own default, keeps the reply's size.
func TestMaxTokensFor(t *testing.T) {
	for _, tc := range []struct {
		model, effort string
		want          int
	}{
		{"claude-opus-5-5", "", 16000}, // runs at medium
		{"claude-opus-5-5", "max", 64000},
		{"claude-opus-5-5", "xhigh", 64000},
		{"claude-opus-5-5", "high", 32000},
		{"claude-opus-5-5", "low", 16000},
		{"claude-sonnet-5-5", "", 32000},  // runs at high
		{"claude-haiku-4-5", "max", 8192}, // takes no effort
		{"claude-3-5-haiku-20241022", "", 8192},
		{"some-local-model", "", 8192},
		{"some-local-model", "max", 64000},
	} {
		if got := maxTokensFor(tc.model, tc.effort, 8192); got != tc.want {
			t.Errorf("%s %q: %d, want %d", tc.model, tc.effort, got, tc.want)
		}
	}
	if got := maxTokensFor("claude-opus-5-5", "", 20000); got != 20000 {
		t.Errorf("a reply larger than the effort's room keeps its own: %d", got)
	}
	for _, tc := range []struct {
		model, effort string
		want          bool
	}{
		{"claude-opus-5-5", "max", true},
		{"claude-opus-5-5", "xhigh", true},
		{"claude-opus-5-5", "", false},
		{"claude-haiku-4-5", "max", false},
	} {
		if got := ThinksLong(tc.model, tc.effort); got != tc.want {
			t.Errorf("ThinksLong(%s, %q) = %v", tc.model, tc.effort, got)
		}
	}
}
