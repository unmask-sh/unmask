package handlers

import (
	"context"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestGhostSites checks the ghost-site classification: in "defined" mode an
// observed site that is not in Sites.Defined is a ghost; in "auto" mode nothing
// is a ghost; a defined site never is.
func TestGhostSites(t *testing.T) {
	h := newTestHandler(t)
	ip := []byte{1, 2, 3, 4}
	for _, site := range []string{"shop.example.com", "shop.example.com", "blog.example.com"} {
		if _, err := h.DB.Exec(
			`INSERT INTO unmask_event (site, ip_address, phase) VALUES (?, ?, 'serve')`,
			site, ip); err != nil {
			t.Fatalf("insert %s: %v", site, err)
		}
	}
	ctx := context.Background()

	// auto mode: no ghosts.
	h.Settings.Sites = settings.SiteAcceptanceConfig{Mode: settings.SiteModeAuto}
	if g := h.ghostSites(ctx, 24); len(g) != 0 {
		t.Fatalf("auto mode: want 0 ghosts, got %d", len(g))
	}

	// defined mode, shop defined: blog is the only ghost.
	h.Settings.Sites = settings.SiteAcceptanceConfig{
		Mode:    settings.SiteModeDefined,
		Defined: []string{"shop.example.com"},
	}
	g := h.ghostSites(ctx, 24)
	if len(g) != 1 {
		t.Fatalf("defined mode: want 1 ghost, got %d (%+v)", len(g), g)
	}
	if g[0].Site != "blog.example.com" {
		t.Errorf("ghost site = %q, want blog.example.com", g[0].Site)
	}
	if g[0].Events != 1 {
		t.Errorf("ghost events = %d, want 1", g[0].Events)
	}

	// defined mode, both defined: no ghosts.
	h.Settings.Sites = settings.SiteAcceptanceConfig{
		Mode:    settings.SiteModeDefined,
		Defined: []string{"shop.example.com", "blog.example.com"},
	}
	if g := h.ghostSites(ctx, 24); len(g) != 0 {
		t.Fatalf("all defined: want 0 ghosts, got %d", len(g))
	}
}
