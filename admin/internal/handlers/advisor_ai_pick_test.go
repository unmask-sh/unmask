package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/advisor"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// A stored AI pick the challenge already stops -- no passes, short of the
// cost floor -- is not shown however it got into the store (a run before the
// cost rule); a pick that passes, or a contained one past the floor, still
// is.  Operator (2026-09-10): "AI ピックで 0 通過があがってくる".
func TestAdvisorStoredContainedPickIsHidden(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.AIAdvisor = settings.AIAdvisorConfig{Enabled: true, Provider: "anthropic", APIKey: "k", Endpoint: "http://127.0.0.1:9"}
	h.settingsPtr.Store(&cur)
	key := advisor.ResultKey(cur.AIAdvisor, 24*60, string(i18n.Resolve(httptest.NewRequest(http.MethodGet, "/", nil))))
	pick := func(ip string, passes, serves, requests int) advisor.Candidate {
		return advisor.Candidate{Type: "ip", Target: ip, Scope: "ip_only", Nominated: true, Contained: passes == 0,
			Passes: passes, Serves: serves, Requests: requests, UA: "Mozilla/5.0",
			Signals: []advisor.Signal{{ID: "ai_pick", Detail: "proposed by the model from the wider ranking"}}}
	}
	advisor.StoreLast(h.DB, key, advisor.Stored{At: time.Now(), Model: "m",
		Reviews: map[string]advisor.Review{
			"198.51.100.20": {Target: "198.51.100.20", Priority: "high", Reasoning: "passing farm"},
			"198.51.100.21": {Target: "198.51.100.21", Priority: "medium", Reasoning: "contained, nominated before the rule"},
			"198.51.100.22": {Target: "198.51.100.22", Priority: "medium", Reasoning: "contained, but a flood"},
		},
		Nominated: []advisor.Candidate{
			pick("198.51.100.20", 30, 40, 80),
			pick("198.51.100.21", 0, 500, 700),
			pick("198.51.100.22", 0, advisor.ContainedVolumeServes, advisor.ContainedVolumeServes+50),
		}})
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/?window=24", nil)
	rr := httptest.NewRecorder()
	h.AdminAdvisorIndex(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, `data-ip="198.51.100.20"`) {
		t.Error("a pick that passes must be shown")
	}
	if strings.Contains(body, `data-ip="198.51.100.21"`) || strings.Contains(body, "nominated before the rule") {
		t.Error("a stored pick the challenge already stops must not be shown")
	}
	if !strings.Contains(body, `data-ip="198.51.100.22"`) {
		t.Error("a contained pick past the cost floor is still shown: its volume is the case")
	}
}
