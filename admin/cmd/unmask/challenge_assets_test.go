package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
)

// A deployed challenge asset WINS over the embedded one at serve time, so an
// asset left behind by an earlier release keeps running after an upgrade --
// silently, because everything else reports the new version.  This is the
// check that would have caught 2026-08-02, when the whole fleet ran a new
// binary while serving the previous day's challenge.js.
func TestChallengeAssetStalenessIsReported(t *testing.T) {
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

	t.Run("a stale copy is reported by name", func(t *testing.T) {
		// The realistic shape: yesterday's file, which still carries every
		// feature marker the runtime guard tests for and so passes it.
		stale := append([]byte("// yesterday's build\n"), embJS...)
		if err := os.WriteFile(jsPath, stale, 0o644); err != nil {
			t.Fatal(err)
		}
		_, warns := collect()
		if len(warns) != 1 {
			t.Fatalf("expected exactly one warning, got %v", warns)
		}
		if !strings.Contains(warns[0], "challenge.js") {
			t.Errorf("the warning does not name the stale file: %s", warns[0])
		}
		// The operator has to learn two things: which version visitors get,
		// and how to customise deliberately without hitting this again.
		if !strings.Contains(warns[0], "WINS at serve time") {
			t.Error("the warning does not say the deployed copy is the one being served")
		}
		if !strings.Contains(warns[0], "challenge_html_path") {
			t.Error("the warning does not point at the supported override")
		}
	})
}

// The runtime guard tests for a feature marker, which is why it cannot stand
// in for this check: yesterday's asset carries every marker and still ships
// the wrong behaviour.
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
