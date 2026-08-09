package repocheck

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// A translation that carries markup only works through {{ safeHTML (t ...) }};
// rendered bare, html/template escapes it and the operator reads literal
// "<code>$request_uri</code>" in the UI.  Nothing at build time connects the
// two files, so a tag added to a string whose call sites are bare -- or a new
// bare call site for a tagged string -- ships as visible angle brackets.
// Found live on the redirect-exempt lead; this walks every template so the
// class of bug dies rather than the instance.

// i18nTaggedKeys returns the set of translation keys whose value (in any
// language) contains markup.
func i18nTaggedKeys(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(repoAdminDir(t), "internal", "i18n", "i18n.go"))
	if err != nil {
		t.Fatalf("read i18n.go: %v", err)
	}
	tagged := map[string]bool{}
	// Entries are machine-regular: `"key": "value",` with Go string escapes.
	entry := regexp.MustCompile(`(?m)^\t\t("(?:[^"\\]|\\.)*"):\s+("(?:[^"\\]|\\.)*"),`)
	for _, m := range entry.FindAllSubmatch(src, -1) {
		key, err1 := strconv.Unquote(string(m[1]))
		val, err2 := strconv.Unquote(string(m[2]))
		if err1 != nil || err2 != nil {
			continue
		}
		if strings.Contains(val, "<") {
			tagged[key] = true
		}
	}
	if len(tagged) == 0 {
		t.Fatal("found no tagged i18n entries at all — the extraction regex no longer matches i18n.go")
	}
	return tagged
}

func repoAdminDir(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Join(filepath.Dir(self), "..", "..")
}

// TestTaggedTranslationsRenderThroughSafeHTML: every bare {{ t ... "key" }}
// call site must name a markup-free translation.
func TestTaggedTranslationsRenderThroughSafeHTML(t *testing.T) {
	tagged := i18nTaggedKeys(t)

	tmplDir := filepath.Join(repoAdminDir(t), "assets", "templates")
	files, err := filepath.Glob(filepath.Join(tmplDir, "*.html"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no templates under %s (%v)", tmplDir, err)
	}

	// A bare call: {{ t .Lang "key" ... }} / {{ t $.Lang "key" ... }} not
	// wrapped in safeHTML.  The wrapped form is a parenthesized argument —
	// "(t .Lang ...)" — so matching on "{{ t " cannot hit it.
	bare := regexp.MustCompile(`\{\{-?\s*t\s+\$?\.?[A-Za-z.]*Lang\s+"([^"]+)"`)
	// data-info / data-info-after hold popover HTML by convention — their
	// consumer reads the attribute back and assigns it via innerHTML, so the
	// attribute escaping round-trips and tags DO render.  Markup inside them
	// is therefore fine; anywhere else in attribute-land it is not.  The value
	// cannot be delimited by the next quote — template quotes ({{ t $.Lang
	// "key" }}) live inside it — so the region runs to the first quote that is
	// followed by another attribute or the tag closing.
	infoStart := regexp.MustCompile(`data-info(?:-after)?="`)
	infoEnd := regexp.MustCompile(`"(?:\s+[a-zA-Z-]+=|\s*/?>)`)

	for _, f := range files {
		body, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var infoRanges [][]int
		for _, m := range infoStart.FindAllIndex(body, -1) {
			end := infoEnd.FindIndex(body[m[1]:])
			if end == nil {
				continue
			}
			infoRanges = append(infoRanges, []int{m[0], m[1] + end[0]})
		}
		inInfoAttr := func(pos int) bool {
			for _, r := range infoRanges {
				if pos >= r[0] && pos < r[1] {
					return true
				}
			}
			return false
		}
		for _, loc := range bare.FindAllSubmatchIndex(body, -1) {
			key := string(body[loc[2]:loc[3]])
			if !tagged[key] || inInfoAttr(loc[0]) {
				continue
			}
			line := 1 + strings.Count(string(body[:loc[0]]), "\n")
			t.Errorf("%s:%d: %q carries markup but renders without safeHTML — the operator sees literal tags",
				filepath.Base(f), line, key)
		}
	}
}
