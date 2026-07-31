package i18n

import (
	"testing"
	"unicode"
)

// A value in the English catalog written in Japanese means an edit picked the
// wrong locale.  That is easy to do when a script decides "is this the JA
// copy?" from the value it is about to overwrite -- after the first pass both
// copies read as Japanese, so the second edit lands on whichever it sees
// first.  It happened twice while reworking the UA-filter copy, and it is
// invisible until someone views the admin in English.
//
// Kana and CJK punctuation are the tell.  Kanji alone would false-positive on
// an English string that legitimately quotes a Japanese term.
func TestEnglishCatalogHasNoJapaneseValues(t *testing.T) {
	en, ja := dict[LangEN], dict[LangJA]
	if len(en) == 0 || len(ja) == 0 {
		t.Fatal("catalogs are empty")
	}
	for key, val := range en {
		if !hasJapaneseScript(val) {
			continue
		}
		// Report only when the JA catalog holds the same text: that is the
		// signature of a value copied across locales, as opposed to English
		// copy that deliberately quotes something Japanese.
		if ja[key] == val {
			t.Errorf("en[%q] is identical to the Japanese value -- the locale was mixed up:\n  %.140s", key, val)
		}
	}
}

func hasJapaneseScript(s string) bool {
	for _, r := range s {
		if unicode.In(r, unicode.Hiragana, unicode.Katakana) {
			return true
		}
		switch r {
		case '「', '」', '、', '。':
			return true
		}
	}
	return false
}
