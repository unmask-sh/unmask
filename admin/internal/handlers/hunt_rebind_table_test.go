package handlers

import (
	"bytes"
	"strings"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/i18n"
)

// The lineage table has to actually render, and render nothing when there is
// nothing to say.
//
// Parsing the template proves the braces balance, not that the block executes:
// a field named wrong on the row struct is a runtime error inside {{ range }},
// which surfaces as a half-written page in production and as a passing parse
// test here.  So this executes the real template against the real row type.
func TestHuntRebindLineageTable(t *testing.T) {
	tpl, err := loadDashboardTemplate()
	if err != nil {
		t.Fatalf("templates: %v", err)
	}
	render := func(rows []rebindLineageRow) string {
		var buf bytes.Buffer
		data := map[string]any{
			"Lang": i18n.LangEN, "RebindLineages": rows,
		}
		if err := tpl.ExecuteTemplate(&buf, "rebind_lineage_table", data); err != nil {
			t.Fatalf("the lineage table failed to execute: %v", err)
		}
		return buf.String()
	}

	out := render([]rebindLineageRow{{
		Lineage: "abcdef0123456789", Short: "abcdef01",
		IPs: 419, Rebinds: 900, Rejects: 12,
		Total: 900, Window: 4, CapKnown: true, AtCap: true,
		HourLimit: 4, CapLimit: 50, LastSeen: "2026-08-06 13:00:00",
	}})
	// The purpose line and the column help are part of the contract, not
	// decoration: the first cut of this card led with the mechanism and the
	// operator's first question was "what is this for".
	for _, want := range []string{"abcdef01", "419", "at-cap", "4/4",
		"lineage-purpose", "info-tip"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered table is missing %q", want)
		}
	}
	if strings.Contains(out, "abcdef0123456789") {
		t.Error("the full lineage id is opaque and long; the table shows the short form")
	}

	// A cap row that has been pruned must read as unknown, never as zero --
	// zero says "never re-bound", which is the opposite of being listed here.
	out = render([]rebindLineageRow{{
		Short: "deadbeef", IPs: 3, Rebinds: 3, CapKnown: false, HourLimit: 4,
	}})
	if !strings.Contains(out, "—") {
		t.Error("an unknown cap must render as an em dash, not a number")
	}

	// Nothing re-bound: no table at all.  An always-present empty table is one
	// the operator learns to skip.
	if out := render(nil); strings.Contains(out, "lineage-table") {
		t.Error("the table must not render when no lineage re-bound")
	}
}
