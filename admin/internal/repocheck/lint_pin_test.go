// Package repocheck holds tests that guard repository invariants rather than
// program behaviour -- the places where two files have to agree and nothing at
// build time notices when they stop.
package repocheck

import (
	"os"
	"regexp"
	"testing"
)

// TestLintPinsMatchCI: `make lint` pins the Go toolchain and the golangci-lint
// version so a developer box reproduces CI.  The pin is only useful while it
// agrees with the workflow -- and the failure when it drifts is not a lint
// difference but a crash, because golangci-lint embeds a go/types built against
// the Go it shipped with and cannot type-check standard-library sources from a
// newer one ("file requires newer Go version go1.NN"), which reads like a
// broken tool rather than a version mismatch.  Bumping one side without the
// other should fail here, not on someone's afternoon.
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

	ciGo := first(ci, `go-version:\s*"([0-9.]+)"`)
	mkGo := first(mk, `(?m)^LINT_GO\s+\?=\s*([0-9.]+)`)
	if ciGo == "" || mkGo == "" {
		t.Fatalf("could not read both Go pins (ci=%q make=%q)", ciGo, mkGo)
	}
	if ciGo != mkGo {
		t.Errorf("Go pin drift: ci.yml uses %s, `make lint` uses %s — the local run will not reproduce CI", ciGo, mkGo)
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

// TestGoModMatchesCIGo: go.mod's version is what every other build path
// resolves, so if it disagrees with the workflow the linter pin is aligned with
// the wrong thing.
func TestGoModMatchesCIGo(t *testing.T) {
	ci, err := os.ReadFile("../../../.github/workflows/ci.yml")
	if err != nil {
		t.Skipf("workflow not readable: %v", err)
	}
	mod, err := os.ReadFile("../../go.mod")
	if err != nil {
		t.Skipf("go.mod not readable: %v", err)
	}
	ciGo := regexp.MustCompile(`go-version:\s*"([0-9.]+)"`).FindSubmatch(ci)
	modGo := regexp.MustCompile(`(?m)^go\s+([0-9.]+)`).FindSubmatch(mod)
	if ciGo == nil || modGo == nil {
		t.Fatal("could not read both versions")
	}
	if string(ciGo[1]) != string(modGo[1]) {
		t.Errorf("go.mod says go %s but CI builds with %s", modGo[1], ciGo[1])
	}
}
