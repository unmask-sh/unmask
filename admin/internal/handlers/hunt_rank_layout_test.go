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
// 1441px up (1536 -- a 1920 screen at 125% scaling, the common Windows case --
// leaves the UA card 284px), a balanced 2x2 at or below 1440, and no card
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
