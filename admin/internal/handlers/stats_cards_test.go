package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A card that outlasts the overall deadline is left to finish on its own:
// the page renders at the deadline from a copy of what the cards had
// returned, and the late card's result, committed under the lock after
// that, is never read.  Meaningful under -race: before the results were
// gathered behind the lock, the late card wrote into the very slice the
// template was walking.
func TestStatsLateCardDoesNotRaceTheRender(t *testing.T) {
	h := newTestHandler(t)
	prevTimeout, prevHook := statsOverallTimeout, statsCardHook
	t.Cleanup(func() { statsOverallTimeout, statsCardHook = prevTimeout, prevHook })
	statsOverallTimeout = 200 * time.Millisecond
	release := make(chan struct{})
	slow := make(chan struct{}, 1)
	statsCardHook = func(name string) {
		if name == "FlagsDistribution" {
			slow <- struct{}{}
			<-release // held past the deadline, until the page has rendered
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/unmask/admin/stats/default/?range=24h", nil)
	req.SetPathValue("site", "default")
	rr := httptest.NewRecorder()
	start := time.Now()
	h.AdminStats(rr, req)
	took := time.Since(start)
	if rr.Code != http.StatusOK {
		t.Fatalf("stats page status %d", rr.Code)
	}
	select {
	case <-slow:
	default:
		t.Fatal("the slow card never ran; the test holds nothing")
	}
	if took > 5*time.Second {
		t.Errorf("the page waited %v for the held card; it must render at the deadline", took)
	}
	if !strings.Contains(rr.Body.String(), `id="chart"`) {
		t.Error("the page did not render its cards")
	}
	// Let the held card finish and commit its result, now that the render
	// is done: a write into what was rendered would be the race.
	close(release)
	time.Sleep(300 * time.Millisecond)
}
