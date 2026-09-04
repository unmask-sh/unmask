// advisor_models.go — the model picker's live list.
package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/unmask-sh/unmask/admin/internal/advisor"
)

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
	_ = json.NewEncoder(w).Encode(map[string]any{
		"provider": cfg.ResolvedProvider(),
		"models":   models,
	})
}
