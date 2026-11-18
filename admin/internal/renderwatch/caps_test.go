package renderwatch

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The rule a form of pass is held back by: nginx's lines say what the module
// in front verifies, and one line that does not answer for the form is
// enough while it is the latest word, or was logged within the grace.
func TestCapLacks(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	var never time.Time
	for _, c := range []struct {
		what       string
		have, lack time.Time
		want       bool
	}{
		{"no line at all", never, never, false},
		{"only lines with the word", ago(time.Second), never, false},
		{"only lines without it", never, ago(time.Hour), true},
		{"only lines without it, just now", never, now, true},
		{"the latest line is without it", ago(10 * time.Minute), ago(5 * time.Minute), true},
		{"both in the same second", ago(5 * time.Minute), ago(5 * time.Minute), true},
		{"with it since, but one without inside the grace", ago(time.Second), ago(30 * time.Second), true},
		{"with it since, and the last without at the grace", ago(time.Second), ago(Grace), false},
		{"with it since, long after the last without", ago(time.Second), ago(time.Hour), false},
		{"with it long ago, nothing since the old line", ago(time.Hour), ago(2 * time.Hour), false},
	} {
		if got := CapLacks(c.have, c.lack, now); got != c.want {
			t.Errorf("%s: CapLacks = %v, want %v", c.what, got, c.want)
		}
	}
}

func TestHasCap(t *testing.T) {
	for _, c := range []struct {
		caps, word string
		want       bool
	}{
		{"sig128", "sig128", true},
		{"other,sig128", "sig128", true},
		{"sig128,other", "sig128", true},
		{"a,sig128,b", "sig128", true},
		{"", "sig128", false},
		{"sig1280", "sig128", false},
		{"xsig128", "sig128", false},
		{"sig12,8", "sig128", false},
		{",", "sig128", false},
		{"sig128", "", false},
	} {
		if got := hasCap(c.caps, c.word); got != c.want {
			t.Errorf("hasCap(%q, %q) = %v, want %v", c.caps, c.word, got, c.want)
		}
	}
}

// The watch hears what each line says the module verifies and answers by
// the rule; what it heard outlives a restart of the daemon, and a state
// file from before the field reads as lines that answered for nothing.
func TestModuleLacks(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	w := New(func() string { return dir })

	if w.ModuleLacks(CapSig128, now) {
		t.Error("no line yet: the watch says the module lacks the form")
	}
	var none *Watch
	if none.ModuleLacks(CapSig128, now) {
		t.Error("no watch at all: lacks")
	}

	// A module from before the word, with and without an id.
	w.SawModule("", "", now.Add(-10*time.Minute))
	if !w.ModuleLacks(CapSig128, now) {
		t.Error("a line with no module id and no word: not held back")
	}
	w.SawModule("0123456789abcdef", "", now.Add(-9*time.Minute))
	if !w.ModuleLacks(CapSig128, now) {
		t.Error("a line from a module that does not say: not held back")
	}
	// nginx restarted onto a module that verifies the form.
	w.SawModule("fedcba9876543210", "sig128", now.Add(-5*time.Minute))
	if w.ModuleLacks(CapSig128, now) {
		t.Error("the module answers for the form since, and the last line without it is minutes old: still held back")
	}
	// An old worker still finishing: the form is held back again, for the grace.
	w.SawModule("0123456789abcdef", "", now.Add(-20*time.Second))
	w.SawModule("fedcba9876543210", "sig128", now.Add(-19*time.Second))
	if !w.ModuleLacks(CapSig128, now) {
		t.Error("a line without the word twenty seconds ago: not held back")
	}
	if w.ModuleLacks(CapSig128, now.Add(Grace)) {
		t.Error("a minute after the last line without the word: still held back")
	}
	// Other words in the field do not answer for this one, and this one is
	// found among others.
	w2 := New(func() string { return dir })
	w2.SawModule("fedcba9876543210", "other", now)
	if !w2.ModuleLacks(CapSig128, now.Add(time.Hour)) {
		t.Error(`mc=other: answers for "sig128"`)
	}
	w2.SawModule("fedcba9876543210", "other,sig128", now.Add(time.Second))
	if w2.ModuleLacks(CapSig128, now.Add(time.Hour)) {
		t.Error(`mc=other,sig128: does not answer for "sig128"`)
	}

	// Saved and read back by another run, and by doctor.
	if err := w.Save(); err != nil {
		t.Fatal(err)
	}
	r := New(func() string { return dir })
	r.Load()
	if !r.ModuleLacks(CapSig128, now) || r.ModuleLacks(CapSig128, now.Add(Grace)) {
		t.Error("after a restart of the daemon the watch does not answer as before")
	}
	have, lack, err := LoadModuleCaps(dir, CapSig128)
	if err != nil || have.IsZero() || lack.IsZero() || !have.After(lack) {
		t.Errorf("LoadModuleCaps: have %v lack %v err %v", have, lack, err)
	}
	if !CapLacks(have, lack, now) || CapLacks(have, lack, now.Add(Grace)) {
		t.Error("doctor's reading of the state file differs from the watch's")
	}

	// A state file written before 0.1.58: module ids, no word of what they
	// verify.  Those lines answered for nothing, so the form is held back
	// from the daemon's first pass, not from the first line it hears.
	old := t.TempDir()
	at := now.Add(-3 * time.Hour).UTC().Format(time.RFC3339)
	if err := os.WriteFile(filepath.Join(old, StateFile),
		[]byte(`{"seen":{"0123456789ab":"`+at+`"},"module":{"0123456789abcdef":"`+at+`","":"`+now.Add(-4*time.Hour).UTC().Format(time.RFC3339)+`"}}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	o := New(func() string { return old })
	o.Load()
	if !o.ModuleLacks(CapSig128, now) {
		t.Error("a state file from before 0.1.58 with module lines: the form is not held back")
	}
	have, lack, err = LoadModuleCaps(old, CapSig128)
	if err != nil || !have.IsZero() || lack.Format(time.RFC3339) != at {
		t.Errorf("a state file from before 0.1.58: have %v lack %v err %v, want lack at the latest module line %s", have, lack, err, at)
	}
	o.SawModule("fedcba9876543210", "sig128", now)
	if o.ModuleLacks(CapSig128, now) {
		t.Error("the module answered since: still held back")
	}

	// A state file with no module lines at all says nothing.
	empty := t.TempDir()
	if err := os.WriteFile(filepath.Join(empty, StateFile), []byte(`{"seen":{"0123456789ab":"`+at+`"}}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e := New(func() string { return empty })
	e.Load()
	if e.ModuleLacks(CapSig128, now) {
		t.Error("a state file with no module lines: held back")
	}
}
