package main

import (
	"os"
	"path/filepath"
	"testing"
)

// Lowering the PoW difficulty breaks the site until nginx reloads, and does it
// silently: the daemon serves the easier puzzle immediately while the native
// plugin keeps verifying against the value nginx parsed at its last reload, so
// a solve short of the old gate clears only 1 time in 2^delta.  Production
// 2026-08-04 went 18 -> 16 with a daemon restart and no reload; three quarters
// of the solves were refused and visitors reported "the PoW screen loops about
// five times" (the geometric mean is four).  renderedPowDifficulty is what lets
// render-nginx see the drop coming, so it has to read the real directive out of
// a real rendered file.
func TestRenderedPowDifficultyReadsTheLiveGate(t *testing.T) {
	dir := t.TempDir()
	write := func(body string) string {
		p := filepath.Join(dir, "http.inc")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}

	// The directive as Render emits it (padded, trailing semicolon).
	p := write("# header\nunmask_bv_secret \"x\";\nunmask_bv_pow_difficulty        18;\nmap $x $y { default 0; }\n")
	if got := renderedPowDifficulty(p); got != 18 {
		t.Errorf("difficulty = %d, want 18 -- the drop warning cannot fire without it", got)
	}

	// Absent file / no directive / unparseable value all mean "nothing to
	// compare": the warning must stay silent rather than guess.
	if got := renderedPowDifficulty(filepath.Join(dir, "absent.inc")); got != 0 {
		t.Errorf("missing file returned %d, want 0", got)
	}
	if got := renderedPowDifficulty(write("upstream unmask_daemon { server 127.0.0.1:9477; }\n")); got != 0 {
		t.Errorf("forward-auth conf (no plugin directives) returned %d, want 0", got)
	}
	if got := renderedPowDifficulty(write("unmask_bv_pow_difficulty abc;\n")); got != 0 {
		t.Errorf("unparseable value returned %d, want 0", got)
	}
}
