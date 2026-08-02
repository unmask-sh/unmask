package handlers

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The rank grid has to have a column for every card it holds.  It was written
// for three (IP / JA4 / UA) and the ASN card made four, so the newcomer wrapped
// onto a row of its own -- and, sharing an auto track with the IP card, its
// prose note set that track's max-content width to the note's unwrapped length:
// the IP card stretched to 1129px and the 1fr UA card was crushed to 31px.
//
// Measured in a browser against a live install's own page: four across from
// 1425px up (1536 -- a 1920 screen at 125% scaling, the common Windows case --
// leaves the UA card 325px), a balanced 2x2 at or below 1424, and no card
// overflowing its column at any width tested.  Before, the UA card was 31px.
func TestRankGridHasAColumnForEveryCard(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/hunt.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(b)

	grid := regexp.MustCompile(`\.rank-grid\{[^}]*grid-template-columns:([^;]+);`).FindStringSubmatch(tpl)
	if grid == nil {
		t.Fatal("could not read the rank-grid column template")
	}
	cols := len(strings.Fields(grid[1]))
	// Count the cards inside the grid, not the whole page.
	body := tpl[strings.Index(tpl, `<div class="rank-grid">`):]
	cards := strings.Count(body[:strings.Index(body, "\n</div>")], `<div class="rank-card`)
	if cards != cols {
		t.Errorf("%d cards in a %d-column grid: the extra card wraps onto a row of its own", cards, cols)
	}

	// The note is prose in a content-sized track.  Without a cap it decides how
	// wide that column is, which is how the IP card ended up at 1129px.
	if !regexp.MustCompile(`\.rank-card-asn\{[^}]*max-width:`).MatchString(tpl) {
		t.Error("the ASN card has no width cap, so its note sizes the whole column")
	}
	// The note carries markup, and t() escapes -- it rendered as literal
	// "<strong>IP 数</strong>" on the page.
	if !strings.Contains(tpl, `{{ safeHTML (t .Lang "hunt.rank.asn_note") }}`) {
		t.Error("the ASN note is not rendered as HTML; its <strong> tags show as text")
	}
	// The UA card is the one designed to absorb slack (ellipsis, min-width:0),
	// so it must stay in the fr column -- last.
	if !strings.Contains(grid[1], "fr") || !strings.HasSuffix(strings.TrimSpace(grid[1]), "1fr") {
		t.Errorf("the flexible column is not last (%q); the UA card no longer absorbs the slack", grid[1])
	}
	if strings.LastIndex(tpl, `rank-card-ua`) < strings.LastIndex(tpl, `rank-card-asn`) {
		t.Error("the UA card is no longer the last card, so it is not in the fr column")
	}

	// A JA4 banned from this page is named hunt_<ja4>: 40 characters of
	// machine-generated text in a content-sized column.  One such row widened
	// the JA4 card to 623px and left the UA card 31px.
	if !regexp.MustCompile(`\.rank-registered\{[^}]*text-overflow:ellipsis`).MatchString(tpl) {
		t.Error("the rank cards' verdict is not clipped; one auto-generated name sizes the whole column")
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
