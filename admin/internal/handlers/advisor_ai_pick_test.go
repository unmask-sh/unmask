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
	// 28 passed by proof-of-work alone, 2 by proof-of-work then CAPTCHA; the
	// proof-of-work was solved 33 times (28 pow_only passes + 5 that went on
	// to the CAPTCHA), the CAPTCHA reached 5 times, so 3 of those stopped there.
	withKinds := func(c advisor.Candidate) advisor.Candidate {
		c.PassPow, c.PassBoth, c.PowPassed, c.CaptchaShown = c.Passes-2, 2, c.Passes+3, 5
		return c
	}
	onlyPow := func(c advisor.Candidate) advisor.Candidate { c.PassPow = c.Passes; return c }
	// Every solve went on to the CAPTCHA (a pow_then_captcha chain): one of
	// three completed it.
	chainOnly := func(c advisor.Candidate) advisor.Candidate {
		c.PassBoth, c.PowPassed, c.CaptchaShown, c.Loads = 1, 3, 3, 3
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
	// Each breakdown is its own line under the figure it splits (operator,
	// 2026-09-13: the cell had grown too wide as one run of counts).
	// (html/template writes the "+" of the label as &#43;.)
	// The kinds are the chain names the settings use (operator, 2026-09-13:
	// "pow_then_captcha が表示されていない").
	if !strings.Contains(body, `<span class="tf-kinds tf-more">pow_only 28 · pow_then_captcha 2</span>`) {
		t.Error("mixed pass kinds show as a labelled breakdown line under the pass count")
	}
	if !strings.Contains(body, `7</strong> 通過 <span class="tf-kinds">(pow_only)</span>`) || strings.Contains(body, `tf-more">pow_only 7`) {
		t.Error("one pass kind reads inline beside the count, not as a line restating it")
	}
	// The PoW figure names the solves that went on to the CAPTCHA: split by
	// chain on its own line when some were pow_only passes, inline when all
	// of them went on.
	if !strings.Contains(body, `<span class="tf-stage">PoW 33</span><span class="tf-kinds tf-more">pow_only 28 · pow_then_captcha 5</span>`) {
		t.Error("the PoW stage splits its solves by chain when some went on to the CAPTCHA")
	}
	if !strings.Contains(body, `<span class="tf-stage">PoW 3 <span class="tf-kinds">(pow_then_captcha)</span></span><span class="tf-stage">CAPTCHA 3</span><span class="tf-kinds tf-more">通過 1 · 不突破 2</span>`) {
		t.Error("when every solve went on to the CAPTCHA the PoW stage says so inline")
	}
	if strings.Contains(body, `<span class="tf-stage">PoW 0 <span`) || strings.Contains(body, `<span class="tf-stage">PoW 0</span><span class="tf-kinds tf-more">`) {
		t.Error("a row without solves that went on to the CAPTCHA carries no chain line under PoW")
	}
	// Each stage on its own line; the CAPTCHA outcome under the CAPTCHA
	// figure: of 5 reached, 2 completed and 3 not (operator, 2026-09-13).
	if !strings.Contains(body, `<span class="tf-stage">CAPTCHA 5</span><span class="tf-kinds tf-more">通過 2 · 不突破 3</span>`) {
		t.Error("the CAPTCHA stage names how many completed it and how many did not")
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
