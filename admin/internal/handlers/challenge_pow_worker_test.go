package handlers

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The PoW worker's source is assembled from functions defined elsewhere in
// challenge.js, so it is possible to inject a function without injecting what
// that function calls.  That happened: sha256 reached for TextEncoder, the
// worker scope had none on EdgeHTML, and the worker died on its first message.
//
// The failure is silent by construction -- solveInWorker rejects, the catch
// falls back to the yielding UI-thread loop, and nothing says the fast path is
// gone.  On the browser in question the fallback then failed the same way, so
// the visitor sat on a challenge that could never finish, reloaded, and got it
// again.  Seen in production as `'TextEncoder' is not defined` at line 3 of the
// worker blob.
func TestPoWWorkerSourceCarriesEveryFunctionItCalls(t *testing.T) {
	b, err := os.ReadFile("../../assets/static/challenge.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)

	// What the worker source injects: `name.toString()` inside the src build.
	start := strings.Index(js, "var src='var SHA256_K=")
	if start < 0 {
		t.Fatal("cannot find the worker source assembly in challenge.js")
	}
	end := strings.Index(js[start:], "var url, w;")
	if end < 0 {
		t.Fatal("cannot find the end of the worker source assembly")
	}
	assembly := js[start : start+end]
	injected := map[string]bool{}
	for _, m := range regexp.MustCompile(`(\w+)\.toString\(\)`).FindAllStringSubmatch(assembly, -1) {
		injected[m[1]] = true
	}
	if len(injected) == 0 {
		t.Fatal("the worker source injects no functions at all")
	}

	// Every function challenge.js defines at module scope, so a call can be
	// told apart from a built-in.  Comments come out first: they discuss the
	// very names this scans for -- including the one that caused all this.
	stripComments := regexp.MustCompile(`(?m)//.*$`)
	defined := map[string]string{}
	for _, m := range regexp.MustCompile(`(?m)^  function (\w+)\(`).FindAllStringSubmatchIndex(js, -1) {
		name := js[m[2]:m[3]]
		body := js[m[0]:]
		if i := strings.Index(body, "\n  }\n"); i > 0 {
			body = body[:i]
		}
		defined[name] = stripComments.ReplaceAllString(body, "")
	}

	// Walk what is injected, following calls, and require the callee to be
	// injected too.  Transitive: utf8Bytes could grow a helper of its own.
	seen := map[string]bool{}
	var walk func(name string)
	walk = func(name string) {
		if seen[name] {
			return
		}
		seen[name] = true
		body, ok := defined[name]
		if !ok {
			return
		}
		for _, m := range regexp.MustCompile(`\b([A-Za-z_$][\w$]*)\s*\(`).FindAllStringSubmatch(body, -1) {
			callee := m[1]
			if callee == name || defined[callee] == "" {
				continue // a built-in, or a keyword like if / for
			}
			if !injected[callee] {
				t.Errorf("the worker calls %s() from %s() but never injects it: the worker dies on its first message and every visitor silently drops to the slow UI-thread loop",
					callee, name)
			}
			walk(callee)
		}
	}
	for name := range injected {
		walk(name)
	}

	// Globals the worker cannot count on.  TextEncoder is the one that bit:
	// present in every current browser's worker scope, absent in EdgeHTML's --
	// and unlike a missing convenience, a missing one here means the proof of
	// work cannot be computed at all, on the main thread either.
	for name := range injected {
		for _, global := range []string{"TextEncoder", "TextDecoder", "document", "window", "localStorage"} {
			if regexp.MustCompile(`\b` + global + `\b`).MatchString(defined[name]) {
				t.Errorf("%s() reaches for %s, which a worker scope may not have", name, global)
			}
		}
	}
}

// The same dependency was fatal on the main thread too, so it is not enough to
// have fixed the worker: nothing in challenge.js may need TextEncoder.
func TestChallengeDoesNotDependOnTextEncoder(t *testing.T) {
	b, err := os.ReadFile("../../assets/static/challenge.js")
	if err != nil {
		t.Fatal(err)
	}
	if regexp.MustCompile(`\bnew TextEncoder\b`).Match(b) {
		t.Error("challenge.js constructs a TextEncoder; browsers without one cannot solve the PoW at all, on any path")
	}
}
