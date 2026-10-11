package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/advisor"
	"github.com/unmask-sh/unmask/admin/internal/db"
	"github.com/unmask-sh/unmask/admin/internal/i18n"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

func pickTestHandler(t *testing.T) *Handler {
	t.Helper()
	orig := ModelCachePath
	ModelCachePath = filepath.Join(t.TempDir(), "ai-models.json")
	t.Cleanup(func() { ModelCachePath = orig })
	if err := saveModelCache(aiModelCache{Provider: "anthropic", Endpoint: "http://127.0.0.1:9", Models: []advisor.ModelInfo{
		{ID: "claude-opus-5-5", Label: "Claude Opus 5.5"}, {ID: "claude-haiku-4-5", Label: "Claude Haiku 4.5"}, {ID: "claude-haiku-5-5", Label: "Claude Haiku 5.5"},
	}}); err != nil {
		t.Fatal(err)
	}
	h := newTestHandler(t)
	s := h.snapshotSettings()
	s.Server.BasePath = "/unmask"
	s.AIAdvisor = settings.AIAdvisorConfig{Enabled: true, Provider: "anthropic", APIKey: "k", Model: "claude-haiku-5-5", Endpoint: "http://127.0.0.1:9"}
	h.SetSettings(s)
	return h
}

// The effort's "default" says what runs: the picked model's own level, the
// configured effort over it, or that a model takes none.  The page's
// remembered picks are its cookies; one the provider or the model does not
// take is dropped.
func TestAIPicksNameTheDefault(t *testing.T) {
	h := pickTestHandler(t)
	req := askReq("GET", "/unmask/admin/ask/", "", "admin")
	v := h.aiPicks(req, "ask")
	if v.Model != "claude-haiku-5-5" || v.DefaultLabel != "既定 (medium)" || v.NoEffort || v.Effort != "" {
		t.Errorf("configured: %+v", v)
	}
	// The list in the pickers' order: families by name, newest first, the
	// configured model in its place.
	var order []string
	for _, m := range v.Models {
		order = append(order, m.ID)
	}
	if strings.Join(order, ",") != "claude-haiku-5-5,claude-haiku-4-5,claude-opus-5-5" {
		t.Errorf("order: %v", order)
	}
	labels, none := map[string]string{}, map[string]bool{}
	for _, m := range v.Models {
		labels[m.ID], none[m.ID] = m.DefaultLabel, m.NoEffort
	}
	if labels["claude-opus-5-5"] != "既定 (medium)" || labels["claude-haiku-4-5"] != "指定不可" || !none["claude-haiku-4-5"] || none["claude-opus-5-5"] {
		t.Errorf("per model: %v %v", labels, none)
	}

	pick := func(page, cookie string) aiPicksView {
		r := askReq("GET", "/unmask/admin/ask/", "", "admin")
		r.Header.Set("Cookie", "unmask_lang=ja; "+cookie)
		return h.aiPicks(r, page)
	}
	if v := pick("ask", "unmask_ask_model=claude-opus-5-5; unmask_ask_effort=low"); v.Model != "claude-opus-5-5" || v.Effort != "low" {
		t.Errorf("remembered: %+v", v)
	}
	if v := pick("advisor", "unmask_ask_model=claude-opus-5-5"); v.Model != "claude-haiku-5-5" {
		t.Errorf("the advisor read the ask page's pick: %s", v.Model)
	}
	if v := pick("ask", "unmask_ask_model=claude-opus-9; unmask_ask_effort=low"); v.Model != "claude-haiku-5-5" || v.Effort != "" {
		t.Errorf("a model off the list: %+v", v)
	}
	if v := pick("ask", "unmask_ask_model=claude-haiku-4-5; unmask_ask_effort=low"); v.Model != "claude-haiku-4-5" || v.Effort != "" || !v.NoEffort || v.DefaultLabel != "指定不可" {
		t.Errorf("a model that takes no effort: %+v", v)
	}

	s := h.snapshotSettings()
	s.AIAdvisor.Effort = "high"
	h.SetSettings(s)
	if v := h.aiPicks(askReq("GET", "/unmask/admin/ask/", "", "admin"), "ask"); v.DefaultLabel != "既定 (high)" {
		t.Errorf("a configured effort: %q", v.DefaultLabel)
	}

	cfg := s.AIAdvisor
	if err := h.applyAIPick(&cfg, "claude-opus-9", "", i18n.LangJA); err == nil {
		t.Error("a model off the list was taken")
	}
	if err := h.applyAIPick(&cfg, "claude-haiku-4-5", "low", i18n.LangJA); err == nil {
		t.Error("an effort for a model that takes none was taken")
	}
	cfg = s.AIAdvisor
	if err := h.applyAIPick(&cfg, "claude-opus-5-5", "xhigh", i18n.LangJA); err != nil || cfg.Model != "claude-opus-5-5" || cfg.Effort != "xhigh" {
		t.Errorf("a valid pick: %v %+v", err, cfg)
	}
}

// The advisor page carries the picks in its run form, shows the picked
// model's review (a review is kept per model), and refuses a pick the
// provider does not take.
func TestAdvisorPicks(t *testing.T) {
	h := pickTestHandler(t)
	page := func(cookie string) string {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/?window=24", nil)
		req.Header.Set("Cookie", "unmask_lang=ja; "+cookie)
		rr := httptest.NewRecorder()
		h.AdminAdvisorIndex(rr, req)
		return rr.Body.String()
	}
	body := page("")
	form := body[strings.Index(body, `id="ai-run-form"`):]
	form = form[:strings.Index(form, "</form>")]
	for _, want := range []string{`id="advisor-model"`, `id="advisor-effort"`, `<option value="claude-haiku-5-5" data-effort-default="既定 (medium)" selected>`, `data-no-effort="1"`} {
		if !strings.Contains(form, want) {
			t.Errorf("the run form lacks %q", want)
		}
	}

	// A review stored for Opus shows when the page picks Opus, not before.
	cfg := h.snapshotSettings().AIAdvisor
	cfg.Model = "claude-opus-5-5"
	advisor.StoreLast(h.DB, advisor.ResultKey(cfg, 24*60, "ja"), advisor.Stored{At: time.Now(), Model: "claude-opus-5-5", Reviewed: 1})
	status := func(cookie string) map[string]any {
		req := httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/ai-status?window=24", nil)
		req.Header.Set("Cookie", "unmask_lang=ja; "+cookie)
		rr := httptest.NewRecorder()
		h.AdminAdvisorAIStatus(rr, req)
		var out map[string]any
		_ = json.Unmarshal(rr.Body.Bytes(), &out)
		return out
	}
	if st := status(""); st["have"] == true {
		t.Error("the configured model shows the Opus review")
	}
	if st := status("unmask_advisor_model=claude-opus-5-5"); st["have"] != true {
		t.Errorf("the picked model's review is not found: %v", st)
	}

	// A run asked with a model off the list does not start.
	req := httptest.NewRequest(http.MethodPost, "/unmask/admin/advisor/ai-run", strings.NewReader("window=24&model=claude-opus-9"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Cookie", "unmask_lang=ja")
	rr := httptest.NewRecorder()
	h.AdminAdvisorAIRun(rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["running"] != false || !strings.Contains(out["error"].(string), "一覧にありません") {
		t.Errorf("a run with a model off the list: %d %s", rr.Code, rr.Body.String())
	}
}

// The bar prints what the last run and the last 30 days cost, estimated
// from the models' list prices; a model with no price adds none.
func TestAdvisorCost(t *testing.T) {
	h := pickTestHandler(t)
	cfg := h.snapshotSettings().AIAdvisor
	advisor.StoreLast(h.DB, advisor.ResultKey(cfg, 24*60, "ja"), advisor.Stored{At: time.Now(), Model: "claude-haiku-5-5", Reviewed: 2, InTokens: 59340, OutTokens: 2219})
	for _, r := range []db.AdvisorRun{
		{RanAt: time.Now().Add(-time.Hour).Unix(), ResultKey: "chat|anthropic|claude-opus-5-5", Model: "claude-opus-5-5", InTokens: 100000, OutTokens: 10000},
		{RanAt: time.Now().Add(-2 * time.Hour).Unix(), ResultKey: "chat|anthropic|local", Model: "some-local-model", InTokens: 5000, OutTokens: 500},
		{RanAt: time.Now().Add(-40 * 24 * time.Hour).Unix(), ResultKey: "chat|anthropic|claude-opus-5-5", Model: "claude-opus-5-5", InTokens: 1000000},
	} {
		if err := h.DB.Gorm.Create(&r).Error; err != nil {
			t.Fatal(err)
		}
	}
	tot := advisor.Totals(h.DB, time.Now().Add(-30*24*time.Hour))
	// $0.007 (haiku) + $0.60 (opus); the local model adds nothing, the
	// run 40 days back is out of the window.
	if tot.PricedRuns != 2 || tot.CostUSD < 0.6070 || tot.CostUSD > 0.6071 {
		t.Errorf("totals: %+v", tot)
	}
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/?window=24", nil)
	req.Header.Set("Cookie", "unmask_lang=ja")
	rr := httptest.NewRecorder()
	h.AdminAdvisorIndex(rr, req)
	body := rr.Body.String()
	for _, want := range []string{"出力 2,219 · 概算 $0.007", "· 概算 $0.61"} {
		if !strings.Contains(body, want) {
			t.Errorf("the bar lacks %q", want)
		}
	}
	if advisorMonthCost("ollama", tot) != "" || advisorMonthCost("anthropic", advisor.RunTotals{Runs: 3}) != "" {
		t.Error("a local provider, or a list of unpriced models, shows a cost")
	}
}
