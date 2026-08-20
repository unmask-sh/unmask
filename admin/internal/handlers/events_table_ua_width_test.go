package handlers

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
)

// The UA column used to render the raw user agent, which is ~740px wide and
// opens with the same "Mozilla/5.0 (...) AppleWebKit/537.36 (KHTML, like
// Gecko)" run on every human visitor -- so it filled whatever width it was
// given and still distinguished almost nothing, while being cut at the end
// where the useful part lives.  It now renders classify.UASummary
// ("Windows · Edge 126") with the untouched string handed to the popover via
// data-full-value, which is the attribute cellpop reads before falling back to
// the cell's text.
//
// Both halves have to stay wired: the summary without data-full-value would
// silently drop the real UA from the page, and data-full-value without the
// summary is just the old behaviour.
func TestEventsTableUARendersSummaryWithFullValueForPopover(t *testing.T) {
	raw, err := assets.Templates.ReadFile("templates/partial_events_table.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(raw)

	if !strings.Contains(tpl, `{{ $uaShort := uaSummary .UA }}`) {
		t.Error("the UA cell no longer computes a summary")
	}
	if !strings.Contains(tpl, `{{ if $uaShort }} data-full-value="{{ .UA }}"{{ end }}`) {
		t.Error("the summarised UA cell must carry the raw string as data-full-value, " +
			"or the full UA is not reachable from the page at all")
	}
	// A UA that does not summarise (curl, an unknown library) must keep its
	// raw bytes on the row: on a bot-hunting surface that is the row the
	// operator most wants to read in full.  Listed crawlers are the exception
	// -- they summarise to their name and render marked, see
	// TestHuntMarksCrawlerRows.  (The cell innards live in the shared
	// "ua_cell" define, whose dot is the raw UA string -- the stats page
	// renders the same define, see TestStatsUAColumnsShareTheHuntCell.)
	if !strings.Contains(tpl, `{{ $br }}{{ else }}{{ . }}{{ end }}`) {
		t.Error("a non-summarisable UA must fall back to the raw string in the cell")
	}
	// Each half of the summary carries its own marker, in front of its own
	// text: the platform glyph before the platform, the browser mark before
	// the browser.  Markers decorate, never replace.
	if !strings.Contains(tpl, `{{ with uaPlatformIcon $uaShort }}<span class="ua-os"`) {
		t.Error("the summary lost its platform icon")
	}
	if !strings.Contains(tpl, `{{ with uaBrowserIcon $uaShort }}<svg class="ua-bi"`) {
		t.Error("the summary lost its drawn browser mark")
	}
	if !strings.Contains(tpl, `{{ if $plat }}{{ $plat }} · {{ end }}`) {
		t.Error("the platform half is no longer rendered before the browser half")
	}
	// Bot rows are marked, and the two kinds are told apart by class:
	// listed (a known vendor, so its name here means it did not verify) vs
	// self-declared (nothing to verify against).
	if !strings.Contains(tpl, `{{ if $uaBot }}<span class="ua-bot ua-bot-{{ $uaBot }}"`) {
		t.Error("a bot row must render marked, with its kind in the class")
	}

	// The three properties that clip an over-long (raw) UA must stay, and the
	// dead max-width must not come back: under the table's auto layout a
	// cell's own max-width is only a hint, so the 24rem this once carried
	// bound nothing while reading as the place the UA gets cut.
	for _, page := range []string{"templates/hunt.html", "templates/overview.html"} {
		pageRaw, err := assets.Templates.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		css := string(pageRaw)
		if strings.Contains(css, "table.events td.ua{max-width:") {
			t.Errorf("%s: td.ua has a max-width again; it does nothing here but suggest a cap that is not real", page)
		}
		if !strings.Contains(css, "table.events td.ua{overflow:hidden;text-overflow:ellipsis;white-space:nowrap") {
			t.Errorf("%s: td.ua lost the properties that clip a raw UA", page)
		}
	}
}

// The phase column holds the collapsed session chain, which carries
// overflow:visible so it never wraps -- and therefore contributes nothing to
// auto layout's column sizing (min-width:max-content on a table cell is
// ignored).  Whatever the th says IS the column, so the width has to cover the
// longest pill run the product can emit.
//
// Adding the rebind refusal to the chain pushed the CAPTCHA path
// (bv_rej > serve > load > captcha > bv_pc) to a browser-measured 245px, past
// the 192px the column used to have: the chain spilled over the URL cell next
// to it.  This pins the width against that measurement so the next phase added
// to a chain has to re-check it rather than silently overflow.
func TestEventsTablePhaseColumnFitsTheLongestChain(t *testing.T) {
	partial, err := assets.Templates.ReadFile("templates/partial_events_table.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(partial), `<th style="width:15.5rem">phase `) {
		t.Error("the phase column is no longer 15.5rem -- measure the longest chain again before changing it " +
			"(bv_rej>serve>load>captcha>bv_pc needs 245px; 12rem = 192px overflowed into the URL cell)")
	}
}

// The actions column holds one BAN button, measured at 39px.  At 7rem it took
// 112px, so 65px of empty column sat immediately to the right of the UA -- and
// since that is exactly where the UA got cut, it read as space the UA was
// being denied ("it is not even reaching the edge and it is already
// ellipsised").
func TestEventsTableActionsColumnIsNotPaddedWithEmptySpace(t *testing.T) {
	partial, err := assets.Templates.ReadFile("templates/partial_events_table.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(partial), `{{ if not .HideActions }}<th style="width:4rem"></th>{{ end }}`) {
		t.Error("the actions column is no longer 4rem -- it holds a 39px button, and any excess shows up " +
			"as blank space next to the UA")
	}
}
