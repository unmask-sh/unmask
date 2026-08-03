package handlers

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
)

// Every value the server injects into the challenge page is a literal in the
// HTML that the handler finds by exact string and replaces.  If the two drift,
// the replacement silently never fires and the page ships whatever the HTML
// happened to say -- no error, no log line, just the wrong behaviour in
// production.
//
// That is what happened to the PoW spinner floor: the handler looked for
// `/*__POW_MIN_DISPLAY_MS__*/0` (its comment: "Production traffic always sees
// the real PoW solve time") while the HTML carried 1500, so every visitor was
// held for an extra 1.5 seconds after a solve that takes 30-100ms, and the
// /unmask/test/ override that was the whole point could not fire either.
// Measured on the fleet: a median load-to-pass of 1,508ms against a 1,500ms
// floor.
func TestChallengePlaceholdersMatchTheHandlersConstants(t *testing.T) {
	html, err := assets.Static.ReadFile("static/challenge.html")
	if err != nil {
		t.Fatal(err)
	}
	page := string(html)

	b, err := os.ReadFile("handlers.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	// Constants of the form `name = "/*__FOO__*/literal"` (or backquoted).
	re := regexp.MustCompile(`(?m)^\s*\w+\s+=\s+["` + "`" + `](/\*__[A-Z_]+__\*/[^"` + "`" + `]*)["` + "`" + `]`)
	found := 0
	for _, m := range re.FindAllStringSubmatch(src, -1) {
		lit := m[1]
		if strings.Contains(lit, "%") { // format string, not a search literal
			continue
		}
		found++
		if !strings.Contains(page, lit) {
			name := regexp.MustCompile(`__([A-Z_]+)__`).FindStringSubmatch(lit)
			t.Errorf("the handler searches for %q but challenge.html does not contain it -- "+
				"%s is never substituted and the page ships the HTML's own value",
				lit, name[1])
		}
	}
	if found < 4 {
		t.Fatalf("only %d placeholder constants matched; this test is not looking at the right thing", found)
	}
}
