package handlers

import (
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/assets"
)

// TestStatsUAColumnsShareTheHuntCell: the stats page's UA columns render
// through the same "ua_cell" define the hunt table uses -- platform glyph +
// summary in the cell, the raw string on data-full-value for the popover --
// instead of the raw ~740px user agent the cells used to hold.  The sprite
// and the cell CSS ride the "ua_assets" define, which each page includes
// exactly once; a second include would duplicate SVG ids, a missing one
// renders every <use> reference as nothing.
func TestStatsUAColumnsShareTheHuntCell(t *testing.T) {
	raw, err := assets.Templates.ReadFile("templates/dashboard.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(raw)

	if n := strings.Count(tpl, `{{ template "ua_assets" }}`); n != 1 {
		t.Errorf("dashboard includes ua_assets %d times; the sprite and CSS must land exactly once", n)
	}
	if n := strings.Count(tpl, `{{ template "ua_cell" `); n < 8 {
		t.Errorf("only %d UA cells render through the shared define; the stats tables lost it", n)
	}
	if strings.Contains(tpl, "bcd-mono bcd-ua") {
		t.Error("a raw-UA cell survived; every UA column renders through ua_cell now")
	}
	// The summary hides the raw string, so a summarised cell must hand it to
	// the popover -- same contract the hunt cell pins.
	if !strings.Contains(tpl, `data-full-value="{{ $r.UAFull }}"`) &&
		!strings.Contains(tpl, `data-full-value="{{ .UAFull }}"`) {
		t.Error("no stats UA cell carries data-full-value; the full UA is unreachable")
	}

	// Functional: the shared define really renders the hunt shapes.
	tmpl, err := loadDashboardTemplate()
	if err != nil {
		t.Fatal(err)
	}
	var sb strings.Builder
	const win = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
	if err := tmpl.ExecuteTemplate(&sb, "ua_cell", win); err != nil {
		t.Fatal(err)
	}
	if out := sb.String(); !strings.Contains(out, `class="ua-os"`) || !strings.Contains(out, "Windows 10") {
		t.Errorf("ua_cell did not summarise a desktop browser: %q", out)
	}
	sb.Reset()
	if err := tmpl.ExecuteTemplate(&sb, "ua_cell", ""); err != nil {
		t.Fatal(err)
	}
	if out := sb.String(); !strings.Contains(out, `<span class="muted">-</span>`) {
		t.Errorf("an empty UA must render the muted dash: %q", out)
	}
}
