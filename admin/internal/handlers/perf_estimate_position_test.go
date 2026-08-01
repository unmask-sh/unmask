package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The estimate reflects BOTH the profile cards and the custom fields, so it
// renders below both.  Sitting directly under the cards, it read as belonging
// to them, and a number that moved while the operator typed in the custom
// boxes further down had no visible cause.
func TestPerfEstimateRendersBelowEveryControlThatMovesIt(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=performance", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("performance tab: %d", rr.Code)
	}
	body := rr.Body.String()

	cards := strings.Index(body, `id="perf-profiles"`)
	custom := strings.Index(body, `id="perf-custom"`)
	est := strings.Index(body, `id="perf-estimate"`)
	if cards < 0 || custom < 0 || est < 0 {
		t.Fatalf("performance controls missing (cards=%d custom=%d est=%d)", cards, custom, est)
	}
	if est < cards {
		t.Error("the estimate renders above the profile cards")
	}
	if est < custom {
		t.Error("the estimate renders above the custom fields, which also change it")
	}
	// Only one estimate element: a second copy would drift, since the JS
	// updates by id.
	if n := strings.Count(body, `id="perf-estimate"`); n != 1 {
		t.Errorf("found %d estimate elements, want exactly 1", n)
	}

	// The estimate names the profile it belongs to.  From the bottom of the
	// card the selection is off-screen, and under "custom" the figure also
	// moves as the operator types -- the label is what ties the number back
	// to a choice.
	if !strings.Contains(body, `id="perf-estimate-profile"`) {
		t.Error("the estimate does not name the active profile")
	}
	// Server-rendered, so it is right before any JS runs.
	seg := body[strings.Index(body, `id="perf-estimate-profile"`):]
	if end := strings.Index(seg, "</span>"); end > 0 && strings.TrimSpace(seg[strings.Index(seg, ">")+1:end]) == "" {
		t.Error("the profile name renders empty on first paint")
	}
	// Every radio carries its localized name for the script to swap in.
	if n := strings.Count(body, "data-label="); n < 4 {
		t.Errorf("only %d profile radios carry data-label; the name cannot follow the selection", n)
	}
}

// Custom with the cache field blank means auto, and auto is computable -- the
// same rule the automatic profiles use.  The card used to render "—" for that
// state, which is the state a fresh custom selection starts in, so the one
// profile an operator picks in order to see numbers was the one showing none.
func TestCustomProfileEstimatesTheAutoCase(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=performance", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("performance tab: %d", rr.Code)
	}
	body := rr.Body.String()

	i := strings.Index(body, `value="custom"`)
	if i < 0 {
		t.Fatal("the custom profile radio is missing")
	}
	seg := body[i:]
	if end := strings.Index(seg, ">"); end > 0 {
		seg = seg[:end]
	}
	if strings.Contains(seg, `data-est="—"`) {
		t.Errorf("custom carries no estimate for the blank/auto case: %s", seg)
	}
	if !strings.Contains(seg, "data-est=") || !strings.Contains(seg, "MB") && !strings.Contains(seg, "GB") {
		t.Errorf("custom's estimate does not look like a size: %s", seg)
	}
}

// "Leave it blank for auto" is only actionable if the operator can see what
// auto resolves to on this host -- the conns field already named its number,
// the cache field did not.
func TestAutoPlaceholderNamesTheResolvedValue(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=performance", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	body := rr.Body.String()

	i := strings.Index(body, `id="perf-cache"`)
	if i < 0 {
		t.Fatal("the cache field is missing")
	}
	seg := body[i:]
	if end := strings.Index(seg, ">"); end > 0 {
		seg = seg[:end]
	}
	ph := seg[strings.Index(seg, "placeholder=")+len("placeholder=\""):]
	ph = ph[:strings.Index(ph, `"`)]
	if !strings.ContainsAny(ph, "0123456789") {
		t.Errorf("the cache placeholder does not name the auto value: %q", ph)
	}
	if !strings.Contains(ph, "MB") && !strings.Contains(ph, "GB") {
		t.Errorf("the cache placeholder's auto value carries no unit: %q", ph)
	}
}

// The estimate is a budget for the SQLite pool, not a ceiling on the process:
// the Go heap and request handling sit on top of it.  The card has to say so,
// because "estimated memory use" next to a single figure reads as a cap.
func TestMemoryCardSaysTheFigureIsNotACap(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=performance", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	body := rr.Body.String()
	// The caveat rides in the memory card's help text.
	if !strings.Contains(body, "上限ではありません") && !strings.Contains(body, "not a cap on the process") {
		t.Error("the card does not say the figure is a budget rather than a cap on total memory")
	}
}

// The host line pairs two numbers, and only the CPU one carried a label --
// "This host: 11.42 GB · CPU 4" left the first figure unattributed.
func TestHostLineLabelsTheMemoryFigure(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=performance", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	body := rr.Body.String()

	i := strings.Index(body, `class="perf-host"`)
	if i < 0 {
		t.Fatal("the host line is missing")
	}
	seg := body[i:]
	if end := strings.Index(seg, "</div>"); end > 0 {
		seg = seg[:end]
	}
	// Both figures on the line are attributed.
	if !strings.Contains(seg, "メモリ") && !strings.Contains(seg, "memory") {
		t.Errorf("the memory figure has no label: %s", seg)
	}
	if !strings.Contains(seg, "CPU") {
		t.Errorf("the CPU figure lost its label: %s", seg)
	}
	// The CPU label says whose CPUs these are.  A bare "CPU 4" left the
	// operator guessing physical cores vs logical vs the container's share --
	// it is GOMAXPROCS, the logical CPUs this process may use.
	if !strings.Contains(seg, "unmask") && !strings.Contains(seg, "available to") {
		t.Errorf("the CPU count does not say it is what unmask may use: %s", seg)
	}
}

// The card explains what the CPU number counts, since the pool size is derived
// from it and "CPU 4" alone is ambiguous between cores, threads and quota.
func TestMemoryCardExplainsTheCPUCount(t *testing.T) {
	h := newTestHandler(t)
	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/settings/?tab=performance", nil)
	rr := httptest.NewRecorder()
	h.AdminSettingsIndex(rr, req)
	body := rr.Body.String()
	if !strings.Contains(body, "論理 CPU") && !strings.Contains(body, "logical CPUs") {
		t.Error("the card never says the count is logical CPUs rather than physical cores")
	}
	if !strings.Contains(body, "cgroup") {
		t.Error("the card does not mention that a cgroup CPU limit is followed")
	}
}
