// advisor_models.go — the model picker's live list.
package handlers

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/advisor"
)

// The fetched list is kept beside the daemon's other state, so the picker
// opens on it from then on (the operator's 2026-10-10 call) rather than on
// the presets until the button is pressed again.  A different provider or
// endpoint sets it aside; the next fetch replaces it.
//
// ModelCachePath is the file; tests point it at a temporary one.
var ModelCachePath = "/var/lib/unmask/ai-models.json"

type aiModelCache struct {
	Provider  string              `json:"provider"`
	Endpoint  string              `json:"endpoint"`
	FetchedAt int64               `json:"fetched_at"`
	Models    []advisor.ModelInfo `json:"models"`
}

// loadModelCache returns the cached list when it is the saved provider's.
func (h *Handler) loadModelCache() *aiModelCache {
	b, err := os.ReadFile(ModelCachePath)
	if err != nil {
		return nil
	}
	var c aiModelCache
	if json.Unmarshal(b, &c) != nil || len(c.Models) == 0 {
		return nil
	}
	cfg := h.cfg().AIAdvisor
	if c.Provider != cfg.ResolvedProvider() || c.Endpoint != cfg.Endpoint {
		return nil
	}
	return &c
}

func saveModelCache(c aiModelCache) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	tmp := ModelCachePath + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, ModelCachePath)
}

// AdminAIModels: GET {base}/admin/api/ai-models
//
// Lists the models of the provider the operator SAVED.  No query overrides
// on purpose: the stored credential is sent to the provider, and a parameter
// that redirected the request would let a crafted link turn this GET into a
// key exfiltration.  Change the provider, save, then fetch.
func (h *Handler) AdminAIModels(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	cfg := h.cfg().AIAdvisor
	models, err := advisor.ListModels(r.Context(), cfg)
	if err != nil {
		// A 200 with an error field: the picker shows it inline and keeps
		// the preset list, which is the right fallback for "can't reach it".
		_ = json.NewEncoder(w).Encode(map[string]any{
			"provider": cfg.ResolvedProvider(),
			"error":    err.Error(),
		})
		return
	}
	c := aiModelCache{Provider: cfg.ResolvedProvider(), Endpoint: cfg.Endpoint, FetchedAt: time.Now().Unix(), Models: models}
	if err := saveModelCache(c); err != nil {
		log.Printf("ai-models: keeping the list: %v", err)
	}
	_ = json.NewEncoder(w).Encode(map[string]any{
		"provider":   cfg.ResolvedProvider(),
		"models":     models,
		"fetched_at": c.FetchedAt,
	})
}
