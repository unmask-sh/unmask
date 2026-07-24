package handlers

import (
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestBypassMatchersCacheHits pins the snapshot-pointer cache: the same
// published snapshot must NOT rebuild the matcher set (the original key was a
// per-call copy address that never matched, so every /api/check rebuilt ~100
// matchers), while a new snapshot pointer or a different site must rebuild.
func TestBypassMatchersCacheHits(t *testing.T) {
	h := newTestHandler(t)

	snap := &settings.Settings{}
	snap.Nginx.BypassPaths.EnabledPresets = []string{"well-known"}
	snap.Nginx.SeenVersion = "v0.1.7"

	a := h.bypassMatchers(snap, "site-a")
	b := h.bypassMatchers(snap, "site-a")
	// A cache hit returns the identical pathMatchers value; slice headers
	// compare by data pointer, so same backing array = not rebuilt.
	if len(a.bypass) == 0 || len(b.bypass) == 0 {
		t.Fatal("expected non-empty bypass matchers from the well-known preset")
	}
	if &a.bypass[0] != &b.bypass[0] {
		t.Error("same snapshot pointer + site must hit the cache (matchers were rebuilt)")
	}

	// Different site with the same snapshot: rebuild.
	c := h.bypassMatchers(snap, "site-b")
	if len(c.bypass) > 0 && &a.bypass[0] == &c.bypass[0] {
		t.Error("different site must not reuse the cached matchers")
	}

	// New snapshot pointer (a settings save republishes): rebuild.
	snap2 := &settings.Settings{}
	snap2.Nginx = snap.Nginx
	d := h.bypassMatchers(snap2, "site-a")
	if len(d.bypass) > 0 && &a.bypass[0] == &d.bypass[0] {
		t.Error("a new snapshot pointer must rebuild the matchers")
	}
}
