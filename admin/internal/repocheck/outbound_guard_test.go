package repocheck

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// A package that dials through internal/outbound knows some service by its
// real address -- the hub, an AI provider, a CAPTCHA provider, a mail relay
// -- and its tests point the code at servers of their own.  A test that
// forgets to has reached the real one: a Community Bans test registered an
// install that does not exist with the published hub (2026-11-18).  So the
// suite of every such package switches outbound.SetOnlyLoopbackForTests on,
// and this holds the rule for a package that starts to dial tomorrow.
func TestSuitesThatDialReachLoopbackOnly(t *testing.T) {
	const imp = `"github.com/unmask-sh/unmask/admin/internal/outbound"`
	root := filepath.Join("..", "..")
	dials := map[string]bool{}  // package dir -> a non-test file imports outbound
	guards := map[string]bool{} // package dir -> a test file switches the guard on
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		dir := filepath.ToSlash(filepath.Dir(path))
		src := string(b)
		if strings.HasSuffix(path, "_test.go") {
			if strings.Contains(src, "outbound.SetOnlyLoopbackForTests(true)") {
				guards[dir] = true
			}
		} else if strings.Contains(src, imp) {
			dials[dir] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for dir := range dials {
		if !guards[dir] {
			missing = append(missing, strings.TrimPrefix(dir, filepath.ToSlash(root)+"/"))
		}
	}
	sort.Strings(missing)
	for _, dir := range missing {
		t.Errorf("%s dials through internal/outbound and its tests do not call outbound.SetOnlyLoopbackForTests(true) (in a TestMain): a test there can reach a real service", dir)
	}
	if len(dials) < 8 {
		t.Errorf("found %d packages that import internal/outbound: the scan no longer sees them", len(dials))
	}
}
