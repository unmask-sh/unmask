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
	// Two chains on one row.  The JavaScript ran 38 times of 40 served.
	// pow_only shown 30: 28 passed, 2 not.  pow_then_captcha shown 8: the
	// proof-of-work was solved 33 times in all (28 pow_only passes + 5 in the
	// chain), so 5 cleared the chain's first gate and 3 stopped there; of
	// the 5 CAPTCHAs, 2 completed and 3 not.
	withKinds := func(c advisor.Candidate) advisor.Candidate {
		c.Loads, c.ShownPow, c.ShownBoth = 38, 30, 8
		c.PassPow, c.PassBoth, c.PowPassed, c.CaptchaShown = c.Passes-2, 2, c.Passes+3, 5
		return c
	}
	// One chain: pow_only shown 9 of 20 served, 7 passed.
	onlyPow := func(c advisor.Candidate) advisor.Candidate {
		c.Loads, c.ShownPow, c.PassPow = 9, 9, c.Passes
		return c
	}
	// pow_then_captcha alone, shown 3: every proof-of-work solved, one of
	// the three CAPTCHAs completed.
	chainOnly := func(c advisor.Candidate) advisor.Candidate {
		c.Loads, c.ShownBoth, c.PassBoth, c.PowPassed, c.CaptchaShown = 3, 3, 1, 3, 3
		return c
	}
	advisor.StoreLast(h.DB, key, advisor.Stored{At: time.Now(), Model: "m",
		Reviews: map[string]advisor.Review{
			"198.51.100.20": {Target: "198.51.100.20", Priority: "high", Reasoning: "passing farm"},
			"198.51.100.21": {Target: "198.51.100.21", Priority: "medium", Reasoning: "contained, nominated before the rule"},
			"198.51.100.22": {Target: "198.51.100.22", Priority: "medium", Reasoning: "contained, but a flood"},
		},
		Nominated: []advisor.Candidate{
			withKinds(pick("198.51.100.20", 30, 40, 80)),
			pick("198.51.100.21", 0, 500, 700),
			pick("198.51.100.22", 0, advisor.ContainedVolumeServes, advisor.ContainedVolumeServes+50),
			// A pick stored before the pool carried pass kinds: passes, no
			// breakdown.  The row must not render an empty "()" after them.
			pick("198.51.100.24", 5, 9, 12),
			// Every pass by the proof-of-work alone: the kind reads inline,
			// a breakdown line would only restate the count.
			onlyPow(pick("198.51.100.25", 7, 20, 30)),
			chainOnly(pick("198.51.100.26", 1, 4, 6)),
		}})
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/advisor/?window=24", nil)
	rr := httptest.NewRecorder()
	h.AdminAdvisorIndex(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, `data-ip="198.51.100.20"`) {
		t.Error("a pick that passes must be shown")
	}
	// The cell reads the challenge by chain, each as shown → passed · not
	// completed on its own ↳ line, the two gates of pow_then_captcha each,
	// and JS says how many were served and left without running it
	// (operator's design, 2026-09-13).  The chain names are the settings'.
	if !strings.Contains(body, `<span class="tf-stage">JS 38 · 未実行 2</span><span class="tf-stage">pow_only 30 提示</span><span class="tf-kinds tf-more">通過 28 · 不突破 2</span><span class="tf-stage">pow_then_captcha 8 提示</span><span class="tf-kinds tf-more">PoW 通過 5 · 不突破 3</span><span class="tf-kinds tf-more">CAPTCHA 通過 2 · 不突破 3</span></div>`) {
		t.Error("a two-chain row reads JS, then each chain shown with its outcome, the chain's two gates each")
	}
	// Mixed kinds: the main line carries no kind and no breakdown -- the
	// chain lines have it.
	if strings.Contains(body, `30</strong> 通過 <span class="tf-kinds">`) || strings.Contains(body, `tf-more">pow_only 28`) {
		t.Error("with two kinds of pass the main line names none; the chain lines split them")
	}
	if !strings.Contains(body, `7</strong> 通過 <span class="tf-kinds">(pow_only)</span>`) {
		t.Error("one pass kind reads inline beside the count")
	}
	if !strings.Contains(body, `<span class="tf-stage">JS 9 · 未実行 11</span><span class="tf-stage">pow_only 9 提示</span><span class="tf-kinds tf-more">通過 7 · 不突破 2</span></div>`) {
		t.Error("a pow_only row has the one chain line and nothing for the chains it never ran")
	}
	if !strings.Contains(body, `1</strong> 通過 <span class="tf-kinds">(pow_then_captcha)</span>`) ||
		!strings.Contains(body, `<span class="tf-stage">JS 3 · 未実行 1</span><span class="tf-stage">pow_then_captcha 3 提示</span><span class="tf-kinds tf-more">PoW 通過 3 · 不突破 0</span><span class="tf-kinds tf-more">CAPTCHA 通過 1 · 不突破 2</span></div>`) {
		t.Error("a pow_then_captcha row reads its two gates: every proof-of-work solved, one CAPTCHA of three completed")
	}
	if strings.Contains(body, `captcha_only 0 提示`) || strings.Contains(body, `pow_then_captcha 0 提示`) || strings.Contains(body, `pow_only 0 提示`) {
		t.Error("a chain that was neither shown nor passed has no line")
	}
	// A pick stored before the chains were counted: JS and the not-run count
	// only (9 served, none ran), no chain line, no empty "()".
	if !strings.Contains(body, `<span class="tf-stage">JS 0 · 未実行 9</span></div>`) {
		t.Error("a pick without chain counts reads JS 0 · not run 9 and nothing else")
	}
	if strings.Contains(body, `data-ip="198.51.100.21"`) || strings.Contains(body, "nominated before the rule") {
		t.Error("a stored pick the challenge already stops must not be shown")
	}
	if !strings.Contains(body, `data-ip="198.51.100.22"`) {
		t.Error("a contained pick past the cost floor is still shown: its volume is the case")
	}
	// Pass kinds: shown when known, and never an empty "()" when they are not
	// (operator, tool1-jp, 2026-09-12: "2 通過 () とおかしな表示").
	if strings.Contains(body, `class="tf-kinds">()`) || strings.Contains(body, `tf-more"></span>`) {
		t.Error("a pick with passes but no pass-kind breakdown must not render an empty ()")
	}
}
