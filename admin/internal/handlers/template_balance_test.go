package handlers

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
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

// html/template reads a data attribute whose name contains "src", "url" or
// "uri" (after the data- prefix) as a URL and percent-encodes its value, and
// one that starts with "on" as a script: text put there arrives mangled
// (2026-10-10: data-txt-src-hub showed the hub's name as %e5%85%b1...).
// Only a genuine URL may sit in such an attribute.
func TestDataAttributeNamesDoNotTriggerURLEscaping(t *testing.T) {
	files, err := filepath.Glob("../../assets/templates/*.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("templates: %v", err)
	}
	attr := regexp.MustCompile(`data-([a-z0-9-]+)="(\{\{[^}]*\}\})`)
	urlish := regexp.MustCompile(`src|url|uri`)
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range attr.FindAllStringSubmatch(string(b), -1) {
			name, value := m[1], m[2]
			// A value built from the base path is a URL, where the escaping
			// is right.
			if strings.Contains(value, "BasePath") {
				continue
			}
			if urlish.MatchString(name) || strings.HasPrefix(name, "on") {
				t.Errorf("%s: data-%s carries a template value but html/template treats the name as a URL or script attribute; rename it", filepath.Base(f), name)
			}
		}
	}
}
