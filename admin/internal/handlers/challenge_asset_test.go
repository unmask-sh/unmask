package handlers

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"testing"
)

// The packaged copy under /usr/share/unmask/challenge/ is never served, even
// when it is perfectly valid.
//
// It used to win automatically, and the history of that is a list of outages:
// a 2026-05-25 asset left in place across a plugin upgrade looped every visitor
// on tool1-jp (it solved a seedless proof of work the plugin then rejected),
// and a marker guard was added to catch assets that old.  The guard only ever
// caught the ancient ones.  A copy one release behind carries every marker and
// was trusted, so an upgrade that swapped the binary changed nothing the
// visitor saw -- silently, across a whole fleet, which is exactly what happened
// again on 2026-08-15.
//
// The rule is now the simple one: the built-in copy is what runs, unless the
// operator names a file.
func TestPackagedChallengeAssetIsNotServed(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()

	// Not a stale file: a valid one, carrying the markers the old guard looked
	// for.  Being valid is precisely why it used to be served.
	pkgHTML := filepath.Join(dir, "challenge.html")
	if err := os.WriteFile(pkgHTML, []byte("<html><!--__POW_SEED__--><body>PACKAGED-HTML</body></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgJS := filepath.Join(dir, "challenge.js")
	if err := os.WriteFile(pkgJS, []byte("/* PACKAGED-JS */ var s = window.UNMASK.pow_seed;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldH, oldJ := challengeHTMLPackagePath, challengeJSPackagePath
	challengeHTMLPackagePath, challengeJSPackagePath = pkgHTML, pkgJS
	defer func() { challengeHTMLPackagePath, challengeJSPackagePath = oldH, oldJ }()

	html, err := h.loadChallengeHTML()
	if err != nil {
		t.Fatalf("loadChallengeHTML: %v", err)
	}
	if bytes.Contains(html, []byte("PACKAGED-HTML")) {
		t.Error("the packaged challenge.html was served; the built-in copy must win")
	}
	if !bytes.Contains(html, []byte("__POW_SEED__")) {
		t.Error("the built-in challenge.html lost its seed placeholder")
	}

	js, err := h.loadChallengeJS()
	if err != nil {
		t.Fatalf("loadChallengeJS: %v", err)
	}
	if bytes.Contains(js, []byte("PACKAGED-JS")) {
		t.Error("the packaged challenge.js was served; the built-in copy must win")
	}
	if !bytes.Contains(js, []byte("pow_seed")) {
		t.Error("the built-in challenge.js lost its seed handling")
	}
}

// Naming a path is how an override happens now, so it has to actually work --
// otherwise removing the implicit one would leave operators no way at all.
func TestNamedChallengeAssetPathIsServed(t *testing.T) {
	h := newTestHandler(t)
	dir := t.TempDir()

	mine := filepath.Join(dir, "mine.html")
	if err := os.WriteFile(mine, []byte("<html><body>OPERATORS-OWN</body></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	myJS := filepath.Join(dir, "mine.js")
	if err := os.WriteFile(myJS, []byte("/* OPERATORS-OWN-JS */\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	cur := h.snapshotSettings()
	cur.Challenge.Default.ChallengeHTMLPath = mine
	cur.Challenge.Default.ChallengeJSPath = myJS
	h.SetSettings(cur)

	html, err := h.loadChallengeHTML()
	if err != nil {
		t.Fatalf("loadChallengeHTML: %v", err)
	}
	if !bytes.Contains(html, []byte("OPERATORS-OWN")) {
		t.Error("challenge_html_path was set and ignored")
	}
	js, err := h.loadChallengeJS()
	if err != nil {
		t.Fatalf("loadChallengeJS: %v", err)
	}
	if !bytes.Contains(js, []byte("OPERATORS-OWN-JS")) {
		t.Error("challenge_js_path was set and ignored")
	}
}

// An operator who had edited the packaged file gets told once that it is no
// longer used.  Their page still looks right, so without this the edit just
// stops applying and nothing anywhere says why.  A copy that still matches the
// built-in one is the package's own default and is not worth a word.
func TestEditedPackagedAssetIsAnnouncedOnce(t *testing.T) {
	dir := t.TempDir()
	embedded := []byte("BUILT-IN")

	same := filepath.Join(dir, "same.js")
	if err := os.WriteFile(same, embedded, 0o644); err != nil {
		t.Fatal(err)
	}
	edited := filepath.Join(dir, "edited.js")
	if err := os.WriteFile(edited, []byte("BUILT-IN + the operator's change"), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	restore := captureLog(&out)
	defer restore()

	warnIgnoredPackagedAsset(same, "challenge_js_path", embedded)
	if out.Len() != 0 {
		t.Errorf("an untouched packaged copy was reported: %q", out.String())
	}

	warnIgnoredPackagedAsset(edited, "challenge_js_path", embedded)
	first := out.String()
	if !bytes.Contains([]byte(first), []byte("challenge_js_path")) {
		t.Errorf("the notice does not say how to keep using the file: %q", first)
	}

	// Served on every challenge, so a line per request would be a log nobody
	// can read.
	warnIgnoredPackagedAsset(edited, "challenge_js_path", embedded)
	if out.String() != first {
		t.Error("the notice repeated; it must be said once per path")
	}
}

// captureLog redirects the standard logger into buf until the returned
// function is called.
func captureLog(buf *bytes.Buffer) func() {
	out, flags := log.Writer(), log.Flags()
	log.SetOutput(buf)
	log.SetFlags(0)
	return func() { log.SetOutput(out); log.SetFlags(flags) }
}
