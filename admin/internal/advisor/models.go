// models.go — the model picker's data: a starting list per provider, and the
// live list fetched from the provider the operator saved.
//
// The presets keep the picker usable before a key is saved and when the
// provider cannot be reached; the live list is what keeps it honest, since
// models appear faster than any bundled table.  Either way a custom ID can be
// typed in -- the list is a convenience, never a gate.
package advisor

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
	"regexp"
	"strconv"
)

// ModelInfo is one entry the settings tab offers.
type ModelInfo struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// ModelPresets is the starting list per provider.  Anthropic IDs are the
// current family (cached 2026-06); the others are the well-known names and
// rely on the live fetch for the rest.
var ModelPresets = map[string][]ModelInfo{
	"anthropic": {
		{ID: "claude-opus-5", Label: "Claude Opus 5"},
		{ID: "claude-sonnet-5", Label: "Claude Sonnet 5"},
		{ID: "claude-fable-5-1", Label: "Claude Fable 5.1"},
		{ID: "claude-opus-4-8", Label: "Claude Opus 4.8"},
		{ID: "claude-opus-4-7", Label: "Claude Opus 4.7"},
		{ID: "claude-opus-4-6", Label: "Claude Opus 4.6"},
		{ID: "claude-sonnet-4-6", Label: "Claude Sonnet 4.6"},
		{ID: "claude-haiku-4-5", Label: "Claude Haiku 4.5"},
	},
	"openai": {
		{ID: "gpt-4o", Label: "gpt-4o"},
		{ID: "gpt-4o-mini", Label: "gpt-4o-mini"},
		{ID: "gpt-4.1", Label: "gpt-4.1"},
		{ID: "gpt-4.1-mini", Label: "gpt-4.1-mini"},
	},
	"ollama": {
		{ID: "llama3.1", Label: "llama3.1"},
		{ID: "qwen2.5", Label: "qwen2.5"},
		{ID: "mistral", Label: "mistral"},
		{ID: "gemma2", Label: "gemma2"},
	},
}

// ListModels asks the SAVED provider for its model list.  It deliberately
// takes the stored config only: the credential must never be sent anywhere an
// unsaved form field (or a crafted GET) could point it.
func ListModels(ctx context.Context, cfg settings.AIAdvisorConfig) ([]ModelInfo, error) {
	out, err := listModels(ctx, cfg)
	if err != nil {
		return nil, err
	}
	// One order for every provider (SortModels), so the picker reads the
	// same whatever order the provider lists in.
	SortModels(out)
	return out, nil
}

// SortModels orders a model list the way the pickers show it: the families
// by name, and within a family the versions newest first -- Claude Opus
// 5.5, 5, 4.8 ...; gpt-5.4, gpt-5.4-mini, gpt-5.2 ... (operator,
// 2026-10-12: "バージョンは降順のほうがいい").  It reads the name the
// picker shows (the label, else the ID) as runs of text and of versions
// (digits, dotted parts): text runs compare as text, version runs newest
// first, and a name that stops where another goes on (gpt-5 against
// gpt-5-mini) comes first.  Two models of one name -- dated IDs of one
// model -- put the later ID first.
func SortModels(ms []ModelInfo) {
	sort.SliceStable(ms, func(i, j int) bool { return modelBefore(ms[i], ms[j]) })
}

func init() {
	for _, ms := range ModelPresets {
		SortModels(ms)
	}
}

// modelRun is a run of a model's name: text, or a version (4.5 -> [4 5]).
type modelRun struct {
	text  string
	ver   []int
	isVer bool
}

var modelVerRE = regexp.MustCompile(`\d+(?:\.\d+)*`)

func modelRuns(name string) []modelRun {
	name = strings.ToLower(name)
	var out []modelRun
	pos := 0
	for _, m := range modelVerRE.FindAllStringIndex(name, -1) {
		if m[0] > pos {
			out = append(out, modelRun{text: name[pos:m[0]]})
		}
		var v []int
		for _, p := range strings.Split(name[m[0]:m[1]], ".") {
			n, _ := strconv.Atoi(p)
			v = append(v, n)
		}
		out = append(out, modelRun{ver: v, isVer: true})
		pos = m[1]
	}
	if pos < len(name) {
		out = append(out, modelRun{text: name[pos:]})
	}
	return out
}

// newerVersion compares two versions part by part, a missing part below
// any present one (5.5 is newer than 5).
func newerVersion(a, b []int) int {
	for i := 0; i < len(a) || i < len(b); i++ {
		x, y := -1, -1
		if i < len(a) {
			x = a[i]
		}
		if i < len(b) {
			y = b[i]
		}
		if x != y {
			if x > y {
				return 1
			}
			return -1
		}
	}
	return 0
}

func modelBefore(a, b ModelInfo) bool {
	name := func(m ModelInfo) string {
		if strings.TrimSpace(m.Label) != "" {
			return m.Label
		}
		return m.ID
	}
	ra, rb := modelRuns(name(a)), modelRuns(name(b))
	for i := 0; i < len(ra) && i < len(rb); i++ {
		x, y := ra[i], rb[i]
		switch {
		case x.isVer && y.isVer:
			if c := newerVersion(x.ver, y.ver); c != 0 {
				return c > 0
			}
		case !x.isVer && !y.isVer:
			if x.text != y.text {
				return x.text < y.text
			}
		default:
			return !x.isVer
		}
	}
	if len(ra) != len(rb) {
		return len(ra) < len(rb)
	}
	return strings.ToLower(a.ID) > strings.ToLower(b.ID)
}

func listModels(ctx context.Context, cfg settings.AIAdvisorConfig) ([]ModelInfo, error) {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	switch cfg.ResolvedProvider() {
	case "anthropic":
		if cfg.APIKey == "" {
			return nil, fmt.Errorf("no API key saved")
		}
		raw, err := getJSON(ctx, endpointOr(cfg, "https://api.anthropic.com")+"/v1/models?limit=100",
			map[string]string{"x-api-key": cfg.APIKey, "anthropic-version": "2023-06-01"})
		if err != nil {
			return nil, err
		}
		var resp struct {
			Data []struct {
				ID          string `json:"id"`
				DisplayName string `json:"display_name"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, err
		}
		out := make([]ModelInfo, 0, len(resp.Data))
		for _, m := range resp.Data {
			label := m.DisplayName
			if label == "" {
				label = m.ID
			}
			out = append(out, ModelInfo{ID: m.ID, Label: label})
		}
		return out, nil
	case "openai":
		if cfg.APIKey == "" {
			return nil, fmt.Errorf("no API key saved")
		}
		raw, err := getJSON(ctx, endpointOr(cfg, "https://api.openai.com")+"/v1/models",
			map[string]string{"authorization": "Bearer " + cfg.APIKey})
		if err != nil {
			return nil, err
		}
		var resp struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, err
		}
		out := make([]ModelInfo, 0, len(resp.Data))
		for _, m := range resp.Data {
			out = append(out, ModelInfo{ID: m.ID, Label: m.ID})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
		return out, nil
	case "ollama":
		raw, err := getJSON(ctx, endpointOr(cfg, "http://127.0.0.1:11434")+"/api/tags", nil)
		if err != nil {
			return nil, err
		}
		var resp struct {
			Models []struct {
				Name string `json:"name"`
			} `json:"models"`
		}
		if err := json.Unmarshal(raw, &resp); err != nil {
			return nil, err
		}
		out := make([]ModelInfo, 0, len(resp.Models))
		for _, m := range resp.Models {
			out = append(out, ModelInfo{ID: m.Name, Label: m.Name})
		}
		return out, nil
	}
	return nil, fmt.Errorf("unknown provider %q", cfg.Provider)
}

func getJSON(ctx context.Context, url string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	out, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		msg := strings.TrimSpace(string(out))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return nil, fmt.Errorf("provider returned %s: %s", resp.Status, msg)
	}
	return out, nil
}
