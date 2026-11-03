package handlers

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The challenge page's language tables are object literals in challenge.js,
// one language per line, and nothing checked that every language carried
// every key: thirteen of the eighteen rows had no label for the checkbox, so
// their visitors read "I'm not a robot" in English under a card otherwise in
// their language, and the fallback for a site without a name was "this site"
// in every language but Japanese.  Every row of a table carries the same
// keys as its English row, and the preset tables name every language the
// baseline does.
func TestChallengeLanguageTablesCarryEveryKey(t *testing.T) {
	b, err := os.ReadFile("../../assets/static/challenge.js")
	if err != nil {
		t.Fatal(err)
	}
	js := string(b)

	rows := func(table string) map[string][]string {
		start := strings.Index(js, table)
		if start < 0 {
			t.Fatalf("cannot find %q in challenge.js", table)
		}
		body := js[start+len(table):]
		// The table ends at its closing brace, on its own line at the
		// table's own indent (the rows sit one indent further in).
		indent := table[:len(table)-len(strings.TrimLeft(table, " "))]
		end := strings.Index(body, "\n"+indent+"}")
		if end < 0 {
			t.Fatalf("cannot find the end of %q", table)
		}
		out := map[string][]string{}
		row := regexp.MustCompile(`(?m)^\s+(\w+):\s*\{(.*)\},?$`)
		for _, m := range row.FindAllStringSubmatch(body[:end], -1) {
			keys := objectKeys(m[2])
			sort.Strings(keys) // the same set, in whatever order the row writes them
			out[m[1]] = keys
		}
		return out
	}
	same := func(table string, got map[string][]string, langs []string) {
		t.Helper()
		en, ok := got["en"]
		if !ok {
			t.Fatalf("%s has no en row (rows: %v)", table, got)
		}
		for _, lang := range langs {
			keys, ok := got[lang]
			if !ok {
				t.Errorf("%s has no %s row", table, lang)
				continue
			}
			if strings.Join(keys, ",") != strings.Join(en, ",") {
				t.Errorf("%s %s carries %v, en carries %v", table, lang, keys, en)
			}
		}
		for lang := range got {
			if !hasString(langs, lang) {
				t.Errorf("%s has a row %s the baseline does not", table, lang)
			}
		}
	}

	base := rows("  var L={")
	langs := make([]string, 0, len(base))
	for l := range base {
		langs = append(langs, l)
	}
	sort.Strings(langs)
	if len(langs) < 18 {
		t.Fatalf("the baseline table has %d languages, want 18: %v", len(langs), langs)
	}
	same("L", base, langs)
	for _, want := range []string{"verify", "title", "desc", "note", "notRobot", "subject", "wrong", "error", "solveMath", "enterNum", "expired", "reload", "checking", "verified", "connecting"} {
		if !hasString(base["en"], want) {
			t.Errorf("L.en has no %s", want)
		}
	}
	// detectLang's path prefix names the same languages.
	if m := regexp.MustCompile(`match\(/\^\\/\(([a-z|]+)\)\\//\)`).FindStringSubmatch(js); m == nil {
		t.Error("cannot find detectLang's path prefix list")
	} else if got := strings.Split(m[1], "|"); len(got) != len(langs) {
		sort.Strings(got)
		t.Errorf("detectLang's path prefixes %v, the table's languages %v", got, langs)
	}

	for _, preset := range []string{"friendly", "neutral", "minimal"} {
		same("P."+preset, rows("    "+preset+":{"), langs)
	}
	same("COOKIE_ERR_I18N", rows("  var COOKIE_ERR_I18N = {"), langs)
}

// objectKeys: the keys of one object literal's body, at depth one, with
// string values skipped over (a value may carry a colon or a comma).
func objectKeys(body string) []string {
	var keys []string
	i := 0
	for i < len(body) {
		c := body[i]
		switch {
		case c == ' ' || c == ',':
			i++
		case c == '\'' || c == '"':
			q := c
			i++
			for i < len(body) && body[i] != q {
				if body[i] == '\\' {
					i++
				}
				i++
			}
			i++
		default:
			j := i
			for j < len(body) && body[j] != ':' {
				j++
			}
			keys = append(keys, strings.TrimSpace(body[i:j]))
			i = j + 1
			// skip to the value's end: a string, or a bare token
			for i < len(body) && body[i] == ' ' {
				i++
			}
			if i < len(body) && (body[i] == '\'' || body[i] == '"') {
				continue
			}
			for i < len(body) && body[i] != ',' {
				i++
			}
		}
	}
	return keys
}

func hasString(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
