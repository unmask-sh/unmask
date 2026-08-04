package i18n

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// Every key a template asks for must exist in the catalog.  A missing one does
// not error -- the page renders the key itself, so the operator reads
// "settings.challenge.display_visible" where a label belongs.  The parity test
// cannot catch it: a key absent from BOTH locales is perfectly symmetric, which
// is exactly how the challenge display-style radio shipped with raw keys as its
// labels (2026-08-04).
func TestEveryTemplateKeyExists(t *testing.T) {
	dir := "../../assets/templates"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	// {{ t .Lang "key" }} and {{ tf .Lang "key" ... }}, including the $.Lang
	// form used inside range blocks.
	// Requires a dotted namespace: catalog keys always have one, and the
	// pattern would otherwise match prose in a comment that spells out the call
	// form (dashboard.html documents `{{ t .Lang "key" }}`).
	re := regexp.MustCompile(`\b(?:t|tf)\s+\$?\.?\w*\.?Lang\s+"([a-z0-9_]+(?:\.[a-z0-9_]+)+)"`)
	missing := map[string][]string{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			key := m[1]
			// T falls back to the key itself when it is unknown, which is the
			// very failure being tested for -- so compare against that.
			if T(LangEN, key) == key || T(LangJA, key) == key {
				missing[key] = append(missing[key], e.Name())
			}
		}
	}
	if len(missing) == 0 {
		return
	}
	keys := make([]string, 0, len(missing))
	for k := range missing {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		t.Errorf("%s is used by %v but is not in the catalog -- the page shows the key instead of a label",
			k, missing[k])
	}
}
