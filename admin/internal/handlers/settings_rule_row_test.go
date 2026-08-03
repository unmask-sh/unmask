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

// Confirming a row updates the row summary in place, and the summary carries
// pills the row can still change: the match mode, the chain action, the site.
// The sync wrote the pattern with textContent, which wiped all of them, so a
// confirmed row read as a bare path until the page was reloaded -- and a row
// added in this session never showed them at all.
func TestConfirmingARowKeepsItsPills(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(b)

	sync := tpl[strings.Index(tpl, "function syncPatValue("):]
	sync = sync[:strings.Index(sync, "\n  function ")+len("\n  function ")]
	if strings.Contains(sync, "patView.textContent =") {
		t.Error("the summary is still rewritten wholesale; the mode / action / site pills are wiped on confirm")
	}
	if !strings.Contains(sync, "syncRowPills(") {
		t.Error("the summary sync no longer rebuilds the pills from the row's inputs")
	}

	if !strings.Contains(tpl, "function syncRowPills(") {
		t.Fatal("syncRowPills is gone")
	}
	pills := tpl[strings.Index(tpl, "function syncRowPills("):]
	pills = pills[:strings.Index(pills, "\n  }\n")]
	// Each pill has to be created, updated or removed -- a row added in this
	// session starts with none, and clearing a value has to drop its pill.
	for _, src := range []string{`input[name$="_mode"]`, `select.extra-action-sel`, `input.rule-action[name$="_site"]`} {
		if !strings.Contains(pills, src) {
			t.Errorf("the pill sync does not read %s, so that value disappears from a confirmed row", src)
		}
	}
	// Setting an action back to inherit must not leave the old value behind.
	// Both spellings of "inherit" count: most lists use an empty option value,
	// the upstream-rescue one uses the literal string.
	if !strings.Contains(pills, `act.value !== 'inherit'`) {
		t.Error("an action set back to inherit would leave a stale pill behind")
	}
	// A list may instead choose to KEEP a pill for inherit, naming the chain
	// the row will actually run -- but only where the option opts in, so the
	// lists that drop the pill keep doing so.
	if !strings.Contains(pills, "data-inherit-pill") {
		t.Error("the inherit-pill opt-in is gone; an inherit row shows no action at all")
	}

	// The server-rendered pills need the same marker the sync looks them up by,
	// or confirming a row appends a second copy beside the first.
	if n := strings.Count(tpl, `data-pill="site"`); n < 3 {
		t.Errorf("only %d site pills carry the marker; the others get duplicated on confirm", n)
	}
	for _, kind := range []string{"mode", "action"} {
		if !strings.Contains(tpl, `data-pill="`+kind+`"`) {
			t.Errorf("the %s pill has no marker for the sync to find", kind)
		}
	}
}

// A row whose pattern is still blank is incomplete, not empty: its mode,
// action and site are set and the operator can see them everywhere except in
// the one place that summarises the row.  Both the server render and the
// confirm handler kept the pills inside the "has a pattern" branch, so filling
// in everything but the path made those values disappear, which reads as the
// settings having been lost rather than as one field still being blank.
func TestARowWithNoPatternStillShowsItsValues(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(b)

	// Server side: the placeholder and the pills are siblings, not alternatives.
	for _, marker := range []string{
		`settings.protected.empty_pattern" }}{{ end }} <span class="action-pill`,
		`settings.honeypot.empty_pattern" }}{{ end }}{{ with $r.Action }}`,
		`settings.bypass_paths.empty_pattern" }}{{ end }}{{ if .Site }}`,
	} {
		if !strings.Contains(tpl, marker) {
			t.Errorf("a row with no pattern hides its own values: %s", marker)
		}
	}

	// Client side: the blank branch has to restore the placeholder and sync the
	// pills, not just flag the cell and leave whatever text was there.
	i := strings.Index(tpl, `if (patInput.value.trim() === '') {`)
	if i < 0 {
		t.Fatal("could not find the confirm handler's blank-pattern branch")
	}
	branch := tpl[i : i+strings.Index(tpl[i:], "} else {")]
	if !strings.Contains(branch, "syncRowPills(") {
		t.Error("confirming a row with a blank pattern drops its pills")
	}
	if !strings.Contains(branch, "data-empty") {
		t.Error("the blank branch leaves the previous pattern on screen instead of the placeholder")
	}
	// The placeholder has to come from the row itself: each tab words it
	// differently, and the handler is shared.
	if n := strings.Count(tpl, `data-empty="`); n < 6 {
		t.Errorf("only %d row summaries carry their placeholder text; the shared handler cannot restore the rest", n)
	}
}
