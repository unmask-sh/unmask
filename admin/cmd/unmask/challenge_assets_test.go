package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
)

// A deployed challenge asset is IGNORED: 0.1.32 made the embedded copies
// authoritative, precisely because a deployed one used to win and 2026-08-02
// happened -- the whole fleet ran a new binary while serving the previous
// day's challenge.js.
//
// This test asserted the old contract for three weeks after that flip, which
// is how the warning kept telling operators the deployed file was the one
// visitors got.  A test that pins the wrong claim is what lets a message rot
// in place, so the assertion here is now the runtime's actual behaviour.
func TestChallengeAssetDivergenceIsReported(t *testing.T) {
	dir := t.TempDir()
	htmlPath := filepath.Join(dir, "challenge.html")
	jsPath := filepath.Join(dir, "challenge.js")

	// Point the check at the temp copies for the duration of the test.
	origHTML, origJS := challengeAssetHTMLPath, challengeAssetJSPath
	challengeAssetHTMLPath, challengeAssetJSPath = htmlPath, jsPath
	t.Cleanup(func() { challengeAssetHTMLPath, challengeAssetJSPath = origHTML, origJS })

	collect := func() (oks, warns []string) {
		checkChallengeAssets(
			func(_, m string) { oks = append(oks, m) },
			func(_, m string) { warns = append(warns, m) },
		)
		return
	}

	t.Run("nothing deployed is fine", func(t *testing.T) {
		oks, warns := collect()
		if len(warns) != 0 {
			t.Errorf("a binary install with no deployed assets must not warn: %v", warns)
		}
		if len(oks) == 0 || !strings.Contains(oks[0], "embedded") {
			t.Errorf("expected an OK naming the embedded copies, got %v", oks)
		}
	})

	// Deploy byte-identical copies: that is a correctly-upgraded package.
	embHTML, err := assets.Static.ReadFile("static/challenge.html")
	if err != nil {
		t.Fatal(err)
	}
	embJS, err := assets.Static.ReadFile("static/challenge.js")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(htmlPath, embHTML, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(jsPath, embJS, 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("matching copies are fine", func(t *testing.T) {
		_, warns := collect()
		if len(warns) != 0 {
			t.Errorf("assets that match the binary must not warn: %v", warns)
		}
	})

	t.Run("a diverged copy is reported by name", func(t *testing.T) {
		// The realistic shape: an operator's edit, or simply the file the
		// previous release's package installed.
		edited := append([]byte("// somebody's edit\n"), embJS...)
		if err := os.WriteFile(jsPath, edited, 0o644); err != nil {
			t.Fatal(err)
		}
		oks, warns := collect()
		// Not a warning: nothing needs the operator's attention, and on a
		// binary-swap fleet this is every node forever.
		if len(warns) != 0 {
			t.Errorf("a diverged copy must not warn -- the install serves correct assets: %v", warns)
		}
		if len(oks) != 1 {
			t.Fatalf("expected exactly one report, got %v", oks)
		}
		if !strings.Contains(oks[0], "challenge.js") {
			t.Errorf("the report does not name the file: %s", oks[0])
		}
		// The operator has to learn two things: that this file reaches nobody,
		// and how to customise deliberately instead.
		if !strings.Contains(oks[0], "NOT being served") {
			t.Errorf("the report does not say the deployed copy is ignored: %s", oks[0])
		}
		if strings.Contains(oks[0], "WINS at serve time") {
			t.Errorf("the report still claims the deployed copy wins, which it has not since 0.1.32: %s", oks[0])
		}
		if !strings.Contains(oks[0], "challenge_html_path") {
			t.Error("the report does not point at the supported override")
		}
	})
}

// The runtime's own startup log fires on the same condition but only once per
// path per process, so doctor is where an operator can ask about it on demand.
// The feature-marker guard cannot stand in for either: yesterday's asset
// carries every marker and still differs.
func TestFeatureMarkerGuardIsNotEnoughOnItsOwn(t *testing.T) {
	embJS, err := assets.Static.ReadFile("static/challenge.js")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(embJS), "pow_seed") {
		t.Fatal("the embedded challenge.js lost the pow_seed marker the runtime guard tests for")
	}
	// A file that keeps the marker but drops a later fix passes the runtime
	// guard -- exactly the case the byte comparison exists for.
	stale := strings.Replace(string(embJS), "solveInWorker", "solveInWorkerOLD", 1)
	if !strings.Contains(stale, "pow_seed") {
		t.Error("the constructed stale file lost the marker, which would make this test prove nothing")
	}
	if stale == string(embJS) {
		t.Error("the constructed stale file is identical; the byte check would not fire")
	}
}
