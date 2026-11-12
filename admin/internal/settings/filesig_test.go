package settings

import "testing"

// SavedYAML is what the config watch compares: settings that differ only in
// what Save normalizes away are the same settings.
func TestSavedYAMLIgnoresWhatSaveNormalizes(t *testing.T) {
	var a, b Settings
	b.Challenge.Default.ObserveOnly = BoolPtr(false) // an explicit false on Default is "unset"
	ya, err := SavedYAML(a)
	if err != nil {
		t.Fatal(err)
	}
	yb, err := SavedYAML(b)
	if err != nil {
		t.Fatal(err)
	}
	if ya != yb {
		t.Error("an explicit false on the Default record reads as a change")
	}
	if b.Challenge.Default.ObserveOnly == nil {
		t.Error("SavedYAML changed the settings it was given")
	}
	b.Challenge.Default.ObserveOnly = BoolPtr(true)
	if yc, _ := SavedYAML(b); yc == ya {
		t.Error("monitor mode on reads as no change")
	}
}
