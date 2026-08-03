package i18n

import (
	"regexp"
	"slices"
	"strings"
	"testing"
)

// TestLocaleParity guards that every dict key exists in both ja and en.  A
// key present in only one locale silently falls back to the other (T() prefers
// the requested lang, then ja, then the key name itself), so a key added to
// only one block renders Japanese to an English visitor — or the raw key when
// neither has it.  This catches both drift directions at build time, which
// matters because the catalog is edited by hand in two large blocks.
//
// Empty *values* are intentionally allowed: e.g. overview.hero.unit is "件"
// in ja but "" in en (the English KPI reads "123", no unit suffix), so this
// checks key presence, not value emptiness.
func TestLocaleParity(t *testing.T) {
	ja := dict[LangJA]
	en := dict[LangEN]
	if len(ja) == 0 || len(en) == 0 {
		t.Fatalf("dict missing a locale: ja=%d en=%d", len(ja), len(en))
	}
	for k := range ja {
		if _, ok := en[k]; !ok {
			t.Errorf("key %q present in JA but missing in EN", k)
		}
	}
	for k := range en {
		if _, ok := ja[k]; !ok {
			t.Errorf("key %q present in EN but missing in JA", k)
		}
	}
}

// formatVerbRE matches a Go fmt directive (%s, %d, %q, %5.2f, %#x, ...).  A
// space is deliberately NOT allowed as a flag so prose like "100% increase"
// (a space after the percent) is not mistaken for a verb.  The catalog uses no
// %% escapes or explicit %[n] indices, so neither needs special handling.
var formatVerbRE = regexp.MustCompile(`%[#+\-0-9.]*[bcdeEfFgGopqstvxXU]`)

// verbsOf returns the ordered verb letters of every fmt directive in s
// (e.g. "%d-%d 件" -> ["d","d"]).
func verbsOf(s string) []string {
	m := formatVerbRE.FindAllString(s, -1)
	out := make([]string, len(m))
	for i, v := range m {
		out[i] = v[len(v)-1:] // the trailing verb letter
	}
	return out
}

// TestLocaleFormatVerbParity guards that a key's ja and en strings carry the
// SAME ordered fmt verbs.  Tf(lang, key, args...) runs ONE args list through
// fmt.Sprintf against whichever locale's string is selected, so if a
// translation drops a %d, gains a %s, or swaps %s/%d order, the other locale
// renders garbage for the same call -- Go appends "%!(EXTRA ...)" when the
// string has fewer verbs than args and "%!d(MISSING)" when it has more.
// TestLocaleParity proves the keys line up; this proves their verbs do too.
func TestLocaleFormatVerbParity(t *testing.T) {
	ja := dict[LangJA]
	en := dict[LangEN]
	for k, jv := range ja {
		ev, ok := en[k]
		if !ok {
			continue // key-presence drift is TestLocaleParity's job
		}
		jverbs := verbsOf(jv)
		everbs := verbsOf(ev)
		if !slices.Equal(jverbs, everbs) {
			t.Errorf("key %q: fmt-verb mismatch ja=%v en=%v\n  ja=%q\n  en=%q",
				k, jverbs, everbs, jv, ev)
		}
	}
}

// An arrow on a rank-card action meant "this leaves the page": the ASN and UA
// buttons went to the settings tab, taking the range, the filters and the fold
// state with them.  Both open a dialog now, like BAN beside them, and a label
// that still promises a jump is describing the old behaviour.
func TestRankActionLabelsDoNotPromiseANavigation(t *testing.T) {
	for _, lang := range []Lang{LangJA, LangEN} {
		for k, v := range dict[lang] {
			if !strings.HasPrefix(k, "hunt.btn.") {
				continue
			}
			for _, arrow := range []string{"→", "↗", "->"} {
				if strings.Contains(v, arrow) {
					t.Errorf("%s/%s = %q: the arrow reads as a link away from hunt, but the button opens a dialog", lang, k, v)
				}
			}
		}
	}
}

// The composition legend renders "<label> <count>" from the catalog and then
// appends the share, so the count has to be the LAST thing the string emits or
// the two figures end up on either side of the label: EN read "326,466 benign
// bots 69.5%" while JA read "良性 bot 326,466 69.5%", and only one of those is
// scannable.  Nothing in the template can enforce it -- the placement lives in
// the translation.
func TestCompositionLegendEndsWithItsCount(t *testing.T) {
	keys := []string{
		"overview.kpi.nonhuman_benign",
		"overview.kpi.nonhuman_bad",
		"overview.kpi.nonhuman_bypass",
		"overview.kpi.nonhuman_human",
	}
	for _, lang := range []Lang{LangJA, LangEN} {
		for _, k := range keys {
			s, ok := dict[lang][k]
			if !ok {
				t.Errorf("%s/%s: missing", lang, k)
				continue
			}
			if !strings.HasSuffix(s, "%s") {
				t.Errorf("%s/%s = %q: must end with the count so the share reads next to it", lang, k, s)
			}
		}
	}
}
