package i18n

import "testing"

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
