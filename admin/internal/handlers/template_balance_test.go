package handlers

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// Every template closes the <div>s it opens.  A missing close slips past
// the rendering tests (an id is found wherever it nests) and shows up only
// in a browser, where the elements after it end up inside the one left
// open and a redraw of that region wipes them: the 2026-10-10 tile row lost
// its grid's close and took the day section's error note with it.  The
// count is over the whole file, branches included, since each branch of an
// {{ if }} is balanced on its own in well-formed markup.
func TestTemplatesBalanceDivs(t *testing.T) {
	files, err := filepath.Glob("../../assets/templates/*.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("templates: %v (%d files)", err, len(files))
	}
	open, closed := regexp.MustCompile(`<div\b`), regexp.MustCompile(`</div>`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if o, c := len(open.FindAll(b, -1)), len(closed.FindAll(b, -1)); o != c {
			t.Errorf("%s opens %d <div> and closes %d", filepath.Base(f), o, c)
		}
	}
}
