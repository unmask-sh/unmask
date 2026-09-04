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
