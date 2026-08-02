package handlers

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The row's edit timestamp arrives from the form -- the UI stamps it when the
// operator confirms an edit -- so a value that could not be true is dropped
// rather than displayed.  "Not edited" is the honest reading of a bad one.
func TestClampUpdatedAt(t *testing.T) {
	const added, now = 1000, 2000
	for _, tc := range []struct {
		name    string
		changed int64
		want    int64
	}{
		{"an ordinary edit", 1500, 1500},
		{"never edited", 0, 0},
		{"negative", -5, 0},
		{"before the row existed", 900, 0},
		{"in the future", 2001, 0},
		{"exactly now", 2000, 2000},
		{"exactly when added", 1000, 1000},
	} {
		if got := clampUpdatedAt(tc.changed, added, now); got != tc.want {
			t.Errorf("%s: clampUpdatedAt(%d, %d, %d) = %d, want %d",
				tc.name, tc.changed, added, now, got, tc.want)
		}
	}
}

// Two dates per row, and neither is self-describing, so both carry a label.
// The first one has always been stored -- the save path only fills it when it
// is absent, so it holds the add time and never moves, despite the field being
// named updated_at.
func TestRuleRowsShowBothDates(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(b)

	if n := strings.Count(tpl, `settings.rule.added`); n < 8 {
		t.Errorf("only %d row summaries label their add date", n)
	}
	if n := strings.Count(tpl, `settings.rule.updated`); n < 8 {
		t.Errorf("only %d row summaries show an edit date", n)
	}
	// The edit date is absent until there is one -- a row that has never been
	// touched must not read as edited at the moment it was added.
	if !strings.Contains(tpl, `{{ if gt $r.UpdatedAt 0 }}`) && !strings.Contains(tpl, `{{ if gt .UpdatedAt 0 }}`) {
		t.Error("an untouched row would show an edit date")
	}
	if n := strings.Count(tpl, `_updated_at" value=`); n < 8 {
		t.Errorf("only %d rows round-trip their edit date; the rest lose it on save", n)
	}
}

// Confirming a row stamps the edit time only when something actually changed:
// stamping on every confirm would make the date mean "looked at".  And a row
// added with the + button is new, so it must not inherit the dates of the row
// it was cloned from -- the server only fills an absent value, so an inherited
// date is kept and a rule added today reads as months old.
func TestEditStampingAndCloning(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(b)

	if !strings.Contains(tpl, "function rowSignature(row)") {
		t.Fatal("the row-signature helper is gone; the stamp cannot tell an edit from a confirm")
	}
	sig := tpl[strings.Index(tpl, "function rowSignature(row)"):]
	sig = sig[:strings.Index(sig, "\n  }")]
	// The signature must skip the timestamps, or every row looks edited.
	if !strings.Contains(sig, `_created_at`) || !strings.Contains(sig, `_updated_at`) {
		t.Error("the signature includes the timestamps themselves, so every confirm looks like an edit")
	}
	if !strings.Contains(tpl, `row.dataset.snapshot !== rowSignature(row)`) {
		t.Error("the confirm handler stamps unconditionally; the date would mean 'opened', not 'changed'")
	}
	// The stamp goes in the edit field.  A rename once pointed it at the add
	// date instead, which moved the row's creation date on every edit and left
	// the edit date empty.
	stamp := tpl[strings.Index(tpl, "Stamp the edit time"):]
	stamp = stamp[:strings.Index(stamp, "\n        }")]
	if !strings.Contains(stamp, `name$="_updated_at"`) || strings.Contains(stamp, `name$="_created_at"`) {
		t.Error("the edit stamp is written to the wrong field")
	}

	clone := tpl[strings.Index(tpl, "clone the existing row"):]
	clone = clone[:strings.Index(clone, "row.after(clone)")]
	if !strings.Contains(clone, `_created_at"], input[type=hidden][name$="_updated_at"]`) {
		t.Error("a cloned row keeps the dates of the row it was copied from")
	}
}

// Every row that posts an add date must post an edit date beside it, or that
// list can never record one -- and a hidden field pinned to a constant is
// worse than missing: the redirect-exempt rows carried value="0", so every
// save of that tab restamped them as added today.
func TestEveryRowRoundTripsBothDates(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	tpl := string(b)

	names := func(suffix string) map[string]bool {
		out := map[string]bool{}
		for _, m := range regexp.MustCompile(`name="([a-z_]+)`+suffix+`"`).FindAllStringSubmatch(tpl, -1) {
			out[m[1]] = true
		}
		return out
	}
	created, updated := names("_created_at"), names("_updated_at")
	for n := range created {
		if !updated[n] {
			t.Errorf("%s posts an add date but no edit date; that list can never record one", n)
		}
	}
	for n := range updated {
		if !created[n] {
			t.Errorf("%s posts an edit date but no add date", n)
		}
	}

	// A hidden date pinned to a literal never carries the row's own value.
	for _, m := range regexp.MustCompile(`name="[a-z_]+_(?:created|updated)_at" value="([^"]*)"`).FindAllStringSubmatch(tpl, -1) {
		v := m[1]
		if v == "" || strings.HasPrefix(v, "{{") {
			continue
		}
		t.Errorf("a date field is pinned to %q instead of the row's value; saving would overwrite it", v)
	}
}

// The + button clones the row it was pressed on, data-* attributes included.
// Pressing it while another row is being edited handed the new row that row's
// snapshot, and confirming it then stamped an edit date on a row that had just
// been created.
func TestCloningDoesNotInheritTheEditSnapshot(t *testing.T) {
	b, err := os.ReadFile("../../assets/templates/settings.html")
	if err != nil {
		t.Fatal(err)
	}
	clone := string(b)[strings.Index(string(b), "clone the existing row"):]
	clone = clone[:strings.Index(clone, "row.after(clone)")]
	if !strings.Contains(clone, "delete clone.dataset.snapshot") {
		t.Error("a row cloned from one being edited inherits its snapshot and is stamped as edited")
	}
}
