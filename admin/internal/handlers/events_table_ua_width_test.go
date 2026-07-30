package handlers

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
)

// The events table lays out with `table-layout: auto`, where a cell's own
// max-width is only a hint -- td.ua carried max-width:24rem for a long time and
// it bound nothing (raising it, or removing it outright, left the measured
// column width unchanged).  What actually splits the leftover width is the th
// set: with neither URL nor UA carrying one, auto layout divides the remainder
// evenly, so a short path sat in exactly as much space as a 200-character user
// agent that had to be cut.
//
// Capping URL from the th fixes that -- but only above a breakpoint.  Measured
// with a real browser at 1280px, capping URL unconditionally starves the UA
// column down to 33px; leaving the even split there keeps it at 129px.  So the
// cap is behind a media query, and this pins all three parts: the hook on the
// th, the query that uses it, and the absence of the misleading max-width.
func TestEventsTableUAColumnGetsTheSlackOnWideViewports(t *testing.T) {
	partial, err := assets.Templates.ReadFile("templates/partial_events_table.html")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(partial), `<th class="th-url">URL</th>`) {
		t.Error("the URL header lost its th-url hook -- the media query below has nothing to select")
	}

	// Both pages that render this partial must carry the rule; overview.html
	// has drifted from hunt.html before (the phase-pill colours), which is why
	// the pill CSS now lives in the partial itself.
	for _, page := range []string{"templates/hunt.html", "templates/overview.html"} {
		raw, err := assets.Templates.ReadFile(page)
		if err != nil {
			t.Fatal(err)
		}
		css := string(raw)
		if !strings.Contains(css, `@media (min-width:1600px){table.events th.th-url{width:14rem}}`) {
			t.Errorf("%s: missing the wide-viewport URL cap -- the UA column keeps only half the leftover width", page)
		}
		if strings.Contains(css, "table.events td.ua{max-width:") {
			t.Errorf("%s: td.ua has a max-width again; under auto layout it does nothing but suggest the column is capped there", page)
		}
		// The three properties that DO the truncating must stay.
		if !strings.Contains(css, "table.events td.ua{overflow:hidden;text-overflow:ellipsis;white-space:nowrap") {
			t.Errorf("%s: td.ua lost the properties that actually clip an over-long UA", page)
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
