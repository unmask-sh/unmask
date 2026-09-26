// Package repocheck holds tests that guard repository invariants rather than
// program behaviour -- the places where two files have to agree and nothing at
// build time notices when they stop.
package repocheck

import (
	"os"
	"regexp"
	"testing"
)

// TestLintPinsMatchCI: `make lint` runs golangci-lint under the Go version
// CI uses, so a developer box reproduces CI.  Both sides read that version
// from admin/go.mod (the workflows through go-version-file, the Makefile by
// reading the file); the linter version is pinned in both and must agree.
// The failure when they drift is not a lint difference but a crash, because
// golangci-lint embeds a go/types built against the Go it shipped with and
// cannot type-check standard-library sources from a newer one ("file requires
// newer Go version go1.NN"), which reads like a broken tool rather than a
// version mismatch.  Bumping one side without the other should fail here.
func TestLintPinsMatchCI(t *testing.T) {
	ci, err := os.ReadFile("../../../.github/workflows/ci.yml")
	if err != nil {
		t.Skipf("workflow not readable from this checkout: %v", err)
	}
	mk, err := os.ReadFile("../../../Makefile")
	if err != nil {
		t.Skipf("Makefile not readable from this checkout: %v", err)
	}

	first := func(src []byte, pat string) string {
		m := regexp.MustCompile(pat).FindSubmatch(src)
		if m == nil {
			return ""
		}
		return string(m[1])
	}

	if lit := first(ci, `go-version:\s*"([0-9.]+)"`); lit != "" {
		t.Errorf("ci.yml pins Go %s by hand; the version lives in admin/go.mod (go-version-file)", lit)
	}
	if !regexp.MustCompile(`(?m)^LINT_GO\s+\?=.*admin/go\.mod`).Match(mk) {
		t.Error("Makefile LINT_GO does not read admin/go.mod; `make lint` would not reproduce CI after a Go bump")
	}

	ciLint := first(ci, `version:\s*(v[0-9.]+)`)
	mkLint := first(mk, `(?m)^LINT_VERSION\s+\?=\s*(v[0-9.]+)`)
	if ciLint == "" || mkLint == "" {
		t.Fatalf("could not read both linter pins (ci=%q make=%q)", ciLint, mkLint)
	}
	if ciLint != mkLint {
		t.Errorf("golangci-lint pin drift: ci.yml uses %s, `make lint` suggests %s", ciLint, mkLint)
	}
}

// TestGoModMatchesCIGo: every setup-go step in the workflows must take its
// version from admin/go.mod, so go.mod is the one place the Go version is
// set -- for the build, the release, CodeQL and the lint alike.
func TestGoModMatchesCIGo(t *testing.T) {
	for _, wf := range []string{"ci.yml", "release.yml", "codeql.yml"} {
		src, err := os.ReadFile("../../../.github/workflows/" + wf)
		if err != nil {
			t.Skipf("workflow not readable: %v", err)
		}
		uses := len(regexp.MustCompile(`actions/setup-go@`).FindAll(src, -1))
		fromMod := len(regexp.MustCompile(`go-version-file:\s*admin/go\.mod`).FindAll(src, -1))
		if uses == 0 {
			continue
		}
		if fromMod != uses {
			t.Errorf("%s: %d setup-go steps, %d read admin/go.mod", wf, uses, fromMod)
		}
	}
	mod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Skipf("go.mod not readable: %v", err)
	}
	if !regexp.MustCompile(`(?m)^go\s+[0-9]+\.[0-9]+\.[0-9]+$`).Match(mod) {
		t.Error("go.mod's go directive is not a full x.y.z version; go-version-file would resolve a moving target")
	}
}
