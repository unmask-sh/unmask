package settings

import (
	"strings"
	"testing"
)

func TestMerge3TakesEachSidesOwnChanges(t *testing.T) {
	base := "nginx:\n  a: 1\n  b: x\n  list:\n    - p\n    - q\nserver:\n  port: 9477\n"
	ours := "nginx:\n  a: 2\n  b: x\n  list:\n    - p\n    - q\nserver:\n  port: 9477\n"   // the page changed a
	theirs := "nginx:\n  a: 1\n  b: y\n  list:\n    - p\n    - q\nserver:\n  port: 9478\n" // others changed b and the port
	merged, conflicts, err := Merge3(base, ours, theirs)
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("Merge3: conflicts=%v err=%v", conflicts, err)
	}
	for _, want := range []string{"a: 2", "b: y", "port: 9478"} {
		if !strings.Contains(merged, want) {
			t.Errorf("merged lacks %q:\n%s", want, merged)
		}
	}
}

func TestMerge3ConflictNamesThePath(t *testing.T) {
	base := "nginx:\n  a: 1\n  b: x\n"
	ours := "nginx:\n  a: 2\n  b: x\n"
	theirs := "nginx:\n  a: 3\n  b: z\n"
	merged, conflicts, err := Merge3(base, ours, theirs)
	if err != nil {
		t.Fatal(err)
	}
	if merged != "" || len(conflicts) != 1 || conflicts[0] != "nginx.a" {
		t.Fatalf("want one conflict at nginx.a and nothing merged, got %v / %q", conflicts, merged)
	}
}

func TestMerge3SameChangeOnBothSides(t *testing.T) {
	base := "x: 1\n"
	merged, conflicts, err := Merge3(base, "x: 5\n", "x: 5\n")
	if err != nil || len(conflicts) != 0 || !strings.Contains(merged, "x: 5") {
		t.Fatalf("an alike change: %v %v %q", conflicts, err, merged)
	}
}

// A list is one value: a row added on each side is a conflict, not a merge.
func TestMerge3ListsAreOneValue(t *testing.T) {
	base := "rows:\n  - a\n"
	_, conflicts, err := Merge3(base, "rows:\n  - a\n  - b\n", "rows:\n  - a\n  - c\n")
	if err != nil || len(conflicts) != 1 || conflicts[0] != "rows" {
		t.Fatalf("two edits of one list: %v %v", conflicts, err)
	}
	// One side's edit of a list, the other side untouched: that edit.
	merged, conflicts, err := Merge3(base, "rows:\n  - a\n  - b\n", base)
	if err != nil || len(conflicts) != 0 || !strings.Contains(merged, "- b") {
		t.Fatalf("one edit of a list: %v %v %q", conflicts, err, merged)
	}
}

// A key one side removed and the other left alone is removed; one side
// removed, the other changed: a conflict.  A key both added differently is
// merged when both values are mappings.
func TestMerge3KeysComingAndGoing(t *testing.T) {
	merged, conflicts, err := Merge3("a: 1\nb: 2\n", "a: 1\n", "a: 1\nb: 2\nc: 3\n")
	if err != nil || len(conflicts) != 0 || strings.Contains(merged, "b:") || !strings.Contains(merged, "c: 3") {
		t.Fatalf("removed on one side, added on the other: %v %v %q", conflicts, err, merged)
	}
	if _, conflicts, _ := Merge3("a: 1\nb: 2\n", "a: 1\n", "a: 1\nb: 9\n"); len(conflicts) != 1 || conflicts[0] != "b" {
		t.Fatalf("removed against changed: %v", conflicts)
	}
	merged, conflicts, err = Merge3("a: 1\n", "a: 1\nm:\n  x: 1\n", "a: 1\nm:\n  y: 2\n")
	if err != nil || len(conflicts) != 0 || !strings.Contains(merged, "x: 1") || !strings.Contains(merged, "y: 2") {
		t.Fatalf("a mapping added on both sides: %v %v %q", conflicts, err, merged)
	}
}

// Layout does not count: the same values written differently are equal.
func TestMerge3IgnoresHowValuesAreWritten(t *testing.T) {
	base := "a: \"1x\"\nb: 2\n"
	merged, conflicts, err := Merge3(base, "a: 1x\nb: 3\n", "a: '1x'\nb: 2\n")
	if err != nil || len(conflicts) != 0 || !strings.Contains(merged, "b: 3") {
		t.Fatalf("quoting is no change: %v %v %q", conflicts, err, merged)
	}
}

// Real settings round-trip: two edits of different sections, merged, load
// back with both.
func TestMerge3OnSavedYAML(t *testing.T) {
	s, err := LoadFromYAML("secret:\n  bv_secret: \"0123456789abcdef0123456789abcdef\"\n")
	if err != nil {
		t.Fatal(err)
	}
	base, err := SavedYAML(s)
	if err != nil {
		t.Fatal(err)
	}
	o := s
	o.VersionCheckDisabled = !s.VersionCheckDisabled
	th := s
	th.Server.Port = s.Server.Port + 1
	ours, _ := SavedYAML(o)
	theirs, _ := SavedYAML(th)
	merged, conflicts, err := Merge3(base, ours, theirs)
	if err != nil || len(conflicts) != 0 {
		t.Fatalf("Merge3: %v %v", conflicts, err)
	}
	got, err := LoadFromYAML(merged)
	if err != nil {
		t.Fatal(err)
	}
	if got.VersionCheckDisabled != o.VersionCheckDisabled || got.Server.Port != th.Server.Port {
		t.Errorf("merged settings: version check %v (want %v), port %d (want %d)",
			got.VersionCheckDisabled, o.VersionCheckDisabled, got.Server.Port, th.Server.Port)
	}
	if Version(base) == Version(merged) || len(Version(base)) != 16 {
		t.Errorf("versions: %q %q", Version(base), Version(merged))
	}
}
