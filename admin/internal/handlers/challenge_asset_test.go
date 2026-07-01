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

// Likewise a stale packaged challenge.js -- an old djb2 build that never reads
// window.UNMASK.pow_seed -- must fall back to the embedded copy.  Serving it
// makes the browser solve a PoW the seed-bound plugin rejects, looping every
// visitor (this shipped to tool1 alongside the stale HTML and is what kept the
// loop alive after only the HTML was removed).
func TestLoadChallengeJS_StaleAssetFallsBackToEmbedded(t *testing.T) {
	h := newTestHandler(t)

	dir := t.TempDir()
	stale := filepath.Join(dir, "challenge.js")
	if err := os.WriteFile(stale, []byte("function djb2(s){var h=5381;return h;} // old PoW, no seed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := challengeJSPackagePath
	challengeJSPackagePath = stale
	defer func() { challengeJSPackagePath = old }()

	b, err := h.loadChallengeJS()
	if err != nil {
		t.Fatalf("loadChallengeJS: %v", err)
	}
	if !bytes.Contains(b, []byte("pow_seed")) {
		t.Error("a stale packaged challenge.js (no pow_seed handling) was served; must fall back to the embedded seed-bound copy")
	}
}
