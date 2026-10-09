package handlers

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/events"
)

// The pages of one paging session show the ranking tables page 1 computed.
//
// The rankings ignore the row filters and the offset, so every page of a
// session used to run the same four scans again -- on a large database the
// second page felt "better" only because the first had warmed the cache.  A
// page that carries page 1's freeze id must reuse page 1's tables, and a fresh
// page 1 (a new freeze id) must compute them anew.
func TestHuntRankingsReusedWhilePaging(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	h.SetSettings(cur)
	ctx := context.Background()
	now := time.Now().UTC()
	seed := func(ip string, n int) {
		for i := 0; i < n; i++ {
			if err := events.Insert(ctx, h.DB, &events.Event{
				IPPacked:   events.PackIP(ip),
				Phase:      "serve",
				OccurredAt: now,
			}); err != nil {
				t.Fatal(err)
			}
		}
	}
	render := func(url string) string {
		r := httptest.NewRequest(http.MethodGet, url, nil)
		rr := httptest.NewRecorder()
		h.AdminHuntIndex(rr, r)
		if rr.Code != http.StatusOK {
			t.Fatalf("%s: status %d", url, rr.Code)
		}
		return rr.Body.String()
	}

	seed("10.0.0.1", 120) // more than a page, so page 2 exists
	page1 := render("/unmask/admin/hunt/?range=1h")
	if !strings.Contains(page1, "10.0.0.1") {
		t.Fatal("page 1 does not rank the seeded address")
	}
	asof, err := events.MaxEventID(ctx, h.DB)
	if err != nil || asof == 0 {
		t.Fatalf("freeze id: %d %v", asof, err)
	}

	// Traffic that arrives while the operator reads page 1.  It outranks the
	// first address, so a recomputed table would put it on top.
	seed("10.0.0.2", 300)

	page2 := render(fmt.Sprintf("/unmask/admin/hunt/?range=1h&offset=100&asof=%d", asof))
	if strings.Contains(page2, "10.0.0.2") {
		t.Error("page 2 recomputed the rankings: an address that arrived after page 1 is on it")
	}
	if !strings.Contains(page2, "10.0.0.1") {
		t.Error("page 2 lost page 1's ranking")
	}

	// A fresh page 1 is live.
	fresh := render("/unmask/admin/hunt/?range=1h")
	if !strings.Contains(fresh, "10.0.0.2") {
		t.Error("a fresh page 1 must rank the traffic that arrived since the last one")
	}

	// A set with a table that could not be read is not kept: the next page
	// tries again instead of showing the gap for the rest of the session.
	orig := rankQueryTimeout
	rankQueryTimeout = time.Nanosecond
	broken := render("/unmask/admin/hunt/?range=1h")
	rankQueryTimeout = orig
	if !strings.Contains(broken, rankNotice) {
		t.Fatal("the rankings did not fail under a zero budget; the cache check below proves nothing")
	}
	brokenAsof, _ := events.MaxEventID(ctx, h.DB)
	retry := render(fmt.Sprintf("/unmask/admin/hunt/?range=1h&offset=100&asof=%d", brokenAsof))
	if strings.Contains(retry, rankNotice) {
		t.Error("a failed ranking set was cached: page 2 shows the failure instead of retrying")
	}
	if !strings.Contains(retry, "10.0.0.2") {
		t.Error("the retried rankings are empty")
	}
}

// Expired and surplus sets leave the cache; a complete set within its
// lifetime is returned as stored.
func TestHuntRankCacheBounds(t *testing.T) {
	var c huntRankCache
	set := huntRankSet{ip: []events.RankRow{{Key: "10.0.0.1", Count: 3}}, failed: map[string]bool{"ip": false}}
	c.put("k", set)
	if got, ok := c.get("k"); !ok || len(got.ip) != 1 || got.ip[0].Key != "10.0.0.1" {
		t.Fatalf("stored set not returned: %+v %v", got, ok)
	}
	c.put("broken", huntRankSet{failed: map[string]bool{"ua": true}})
	if _, ok := c.get("broken"); ok {
		t.Error("a set with a failed table was kept")
	}
	for i := 0; i < huntRankMax+5; i++ {
		c.put(fmt.Sprintf("k%d", i), set)
	}
	c.mu.Lock()
	n := len(c.entries)
	c.mu.Unlock()
	if n > huntRankMax {
		t.Errorf("cache holds %d sets, cap is %d", n, huntRankMax)
	}
	c.mu.Lock()
	c.entries["k"] = huntRankEntry{set: set, at: time.Now().Add(-huntRankTTL - time.Second)}
	c.mu.Unlock()
	if _, ok := c.get("k"); ok {
		t.Error("an expired set was returned")
	}
}

// A page that has spent its whole ranking budget skips the tables it has not
// started, and says so the way it says a table timed out.
func TestHuntRankPageBudgetSkipsLateTables(t *testing.T) {
	h := newTestHandler(t)
	cur := h.snapshotSettings()
	cur.Server.BasePath = "/unmask"
	h.SetSettings(cur)
	orig := rankPageBudget
	rankPageBudget = -time.Second // already spent before the first table
	defer func() { rankPageBudget = orig }()
	r := httptest.NewRequest(http.MethodGet, "/unmask/admin/hunt/?range=1h", nil)
	rr := httptest.NewRecorder()
	h.AdminHuntIndex(rr, r)
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), rankNotice) {
		t.Error("skipped tables must be reported as unavailable, not as empty")
	}
}
