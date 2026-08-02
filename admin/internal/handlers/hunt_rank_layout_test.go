package handlers

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The rank row is flex, not grid, and that is load-bearing rather than a style
// preference: any card can be folded away, and a grid track sized for the card
// that used to live in it leaves dead space beside the folded strip.  Folding
// the UA card, which held the 1fr, blanked the row's whole right half.
//
// Measured in a browser after the change: folding the IP card moved its 227px
// to the network card (384 -> 576), folding the UA card left 42px of strip and
// no gap between the cards that remained, and the row wraps on its own instead
// of at two hand-tuned breakpoints.
func TestRankRowIsFlexAndFoldsBeatTheGrowRules(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/hunt.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(b)

	if !regexp.MustCompile(`\.rank-grid\{[^}]*display:flex`).MatchString(tpl) {
		t.Error("the rank row is not flex; a folded card cannot give up its track")
	}
	if regexp.MustCompile(`\.rank-grid\{[^}]*grid-template-columns`).MatchString(tpl) {
		t.Error("the row still declares grid columns, which fixes each card's footprint")
	}

	// Every card has to be foldable, or the cookie has nothing to name.
	body := tpl[strings.Index(tpl, `<div class="rank-grid">`):]
	body = body[:strings.Index(body, "\n</div>")]
	cards := strings.Count(body, `<div class="rank-card`)
	keys := strings.Count(body, `data-rank-card="`)
	if cards != keys {
		t.Errorf("%d cards but %d fold keys: a card cannot be folded", cards, keys)
	}

	// .rank-card-ua and .rank-card-asn carry a flex-grow of their own and have
	// the same specificity as .rank-card.folded, so the fold rule has to name
	// them -- otherwise a folded UA card stays full width (it did: 1376px).
	fold := regexp.MustCompile(`[^\n]*\.rank-card\.folded[^{]*\{flex:0 0`).FindString(tpl)
	if fold == "" {
		t.Fatal("no rule gives a folded card back its share of the row")
	}
	for _, cls := range []string{".rank-card-ua.folded", ".rank-card-asn.folded"} {
		if !strings.Contains(fold, cls) {
			t.Errorf("the fold rule does not name %s, which has an equal-specificity flex of its own", cls)
		}
	}
}

// The rank cards hold three values an operator reads by their leading
// characters and nothing else: a JA4 (36 chars, of which the transport and
// cipher hashes are the first 23), a User-Agent (100+ chars of boilerplate
// around a platform and a version), and a network name.  Showing them in full
// spent the column width the other cards needed -- the JA4 card alone was
// 623px.  Each is now clipped with the whole value one click away.
func TestRankCardsClipTheirLongValues(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/hunt.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(b)
	card := func(cls string) string {
		i := strings.Index(tpl, cls)
		if i < 0 {
			t.Fatalf("no %s card", cls)
		}
		return tpl[i : i+strings.Index(tpl[i:], "</table>")]
	}

	ja4 := card(`<!-- JA4 ranking -->`)
	if !strings.Contains(ja4, `{{ clip 25 .Key }}`) {
		t.Error("the JA4 is no longer clipped, so its full 36 characters size the column again")
	}
	if !strings.Contains(ja4, `data-full-value="{{ .Key }}"`) {
		t.Error("the clipped JA4 has no popover carrying the full value")
	}

	ua := card(`rank-card rank-card-ua`)
	if !strings.Contains(ua, `uaSummary .Key`) {
		t.Error("the UA card shows the raw string rather than the same summary the log uses")
	}
	if !strings.Contains(ua, `data-full-value="{{ .Key }}"`) {
		t.Error("the summarised UA has no popover carrying the full string")
	}
	// The filter link must still carry the raw value: the summary is a label,
	// not something the log can be searched by.
	if !strings.Contains(ua, `&ua={{ urlquery .Key }}`) {
		t.Error("the UA drill-down now searches for the summary instead of the UA")
	}
}

// The IP card's "already banned" marker repeats on every banned row, so its
// length is column width spent thirty times over -- and the hunt card had the
// English string hardcoded, so a Japanese operator read "already BANned" in a
// column already translated around it.
func TestBannedMarkerIsTranslatedAndShort(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/hunt.html")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), ">already BANned<") {
		t.Error("the banned marker is a hardcoded English string; the JA UI shows it untranslated")
	}
	if !strings.Contains(string(b), `{{ t $.Lang "hunt.already_banned" }}`) {
		t.Error("the banned marker no longer goes through i18n")
	}
	for _, lang := range []i18n.Lang{i18n.LangJA, i18n.LangEN} {
		v := i18n.T(lang, "hunt.already_banned")
		if v == "" {
			t.Fatalf("%s: no banned marker", lang)
		}
		// It sits in a narrow column beside an IP and a count; anything longer
		// starts deciding how wide that column is.
		if len([]rune(v)) > 8 {
			t.Errorf("%s banned marker is %q (%d chars): too long for the column it repeats in",
				lang, v, len([]rune(v)))
		}
	}
}
