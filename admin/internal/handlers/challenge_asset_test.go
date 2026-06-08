package handlers

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// A stale packaged challenge.html -- one that predates the seed-bound PoW and so
// lacks the __POW_SEED__ placeholder -- must NOT be served: challenge.js would
// solve a seedless PoW the plugin rejects, looping every visitor.  This is the
// tool1-jp production loop (a 2026-05-25 asset left in place across a plugin
// upgrade).  loadChallengeHTML must fall back to the embedded copy.
func TestLoadChallengeHTML_StaleAssetFallsBackToEmbedded(t *testing.T) {
	h := newTestHandler(t)

	dir := t.TempDir()
	stale := filepath.Join(dir, "challenge.html")
	if err := os.WriteFile(stale, []byte("<html><body>old challenge, no seed placeholder</body></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := challengeHTMLPackagePath
	challengeHTMLPackagePath = stale
	defer func() { challengeHTMLPackagePath = old }()

	b, err := h.loadChallengeHTML()
	if err != nil {
		t.Fatalf("loadChallengeHTML: %v", err)
	}
	if !bytes.Contains(b, []byte("__POW_SEED__")) {
		t.Error("a stale packaged challenge.html (no __POW_SEED__) was served; must fall back to the embedded copy carrying the seed placeholder")
	}
}
