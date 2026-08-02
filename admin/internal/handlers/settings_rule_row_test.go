package handlers

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// A committed rule row shows its values and offers no inputs -- that is what
// committing means.  The chain-action select was left out of the rule that
// hides the others, so every confirmed row on the protected, honeypot and JA4
// tabs still presented an editable "inherit the default" dropdown, which reads
// as if the row had never been committed.
//
// Worse, opening it toggled the row: the whole-row click handler treats a click
// outside the buttons as "toggle enabled", and its exemption list named input
// and label but not select.
func TestCommittedRuleRowsOfferNoInputs(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(b)

	hide := regexp.MustCompile(`(?s)\.rule-row:not\(\.editing\)[^{]*\{display:none\}`).FindString(tpl)
	if hide == "" {
		t.Fatal("could not find the rule that hides a committed row's inputs")
	}
	if !strings.Contains(hide, ".extra-action-sel") {
		t.Error("the chain-action select stays visible on a committed row, which reads as an uncommitted row")
	}

	// Every control the row carries has to be in that rule or be a button.
	for _, cls := range []string{".rule-title", ".rule-pat", ".extra-action-sel"} {
		if !strings.Contains(hide, cls) {
			t.Errorf("%s is not hidden on a committed row", cls)
		}
	}

	// Anchor on the handler itself: several other click handlers on this page
	// have exemption lists of their own.
	h := strings.Index(tpl, "treat as a whole-row click")
	if h < 0 {
		t.Fatal("could not find the whole-row click handler")
	}
	ignore := regexp.MustCompile(`e\.target\.closest\('([^']*)'\)\) return;`).FindStringSubmatch(tpl[h:])
	if ignore == nil {
		t.Fatal("the whole-row click handler has no exemption list")
	}
	for _, sel := range []string{"input", "select", "label"} {
		if !strings.Contains(ignore[1], sel) {
			t.Errorf("a click on <%s> falls through to the row handler and toggles the row: %q", sel, ignore[1])
		}
	}
}

// Hiding the select is only correct if the value it held is still readable, so
// each of the three tabs shows the chain override in the row's own summary.
func TestCommittedRowsShowTheirChainAction(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(b)
	for _, tc := range []struct{ name, marker, action string }{
		{"protected", `settings.protected.empty_pattern`, `{{ with $r.Action }}`},
		{"honeypot", `settings.honeypot.empty_pattern`, `{{ with $r.Action }}`},
		// Anchor inside the editable row: the same key also renders the
		// collapsed all-rules summary further up the page.
		{"ja4", `$jea := index $.JA4ExtraAction`, `{{ with $jea }}`},
	} {
		i := strings.Index(tpl, tc.marker)
		if i < 0 {
			t.Fatalf("%s: could not find the row summary", tc.name)
		}
		if tc.name == "ja4" {
			// The summary is the next .pat line after the variable binding.
			i += strings.Index(tpl[i:], `class="pat`)
		}
		// The summary is one line; look at the line the marker sits on.
		start := strings.LastIndex(tpl[:i], "\n") + 1
		line := tpl[start : start+strings.Index(tpl[start:], "\n")]
		if !strings.Contains(line, tc.action) {
			t.Errorf("%s: the row summary does not show the chain override, so hiding the select loses it", tc.name)
		}
	}
}
