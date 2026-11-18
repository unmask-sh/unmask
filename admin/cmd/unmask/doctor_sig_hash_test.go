package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/renderwatch"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Signing with SHA-256 while nginx logs lines without a module id is a
// WARN (an older module, or an older configuration, refuses what is issued);
// a module id logged since is OK; sha1, or no state to read, is silent.
func TestCheckSigHashModule(t *testing.T) {
	dir := t.TempDir()
	s := settings.Settings{}
	s.Nginx.OutputDir = dir
	s.Secret.SigHash = "sha256"

	cap, addOK, addWarn, _ := newCaptures()
	checkSigHashModule(s, addOK, addWarn)
	if len(cap.ok)+len(cap.warn) != 0 {
		t.Errorf("no state file yet: %+v", cap)
	}

	w := renderwatch.New(func() string { return dir })
	w.SawModule("", "", time.Now().Add(-time.Minute))
	if err := w.Save(); err != nil {
		t.Fatal(err)
	}
	cap, addOK, addWarn, _ = newCaptures()
	checkSigHashModule(s, addOK, addWarn)
	if len(cap.warn) != 1 || !strings.Contains(cap.warn[0], "cookie signature") || !strings.Contains(cap.warn[0], "sig_hash back to sha1") {
		t.Errorf("lines without a module id: %+v, want one warning naming the way back", cap)
	}

	w.SawModule("0123456789abcdef", "", time.Now())
	if err := w.Save(); err != nil {
		t.Fatal(err)
	}
	cap, addOK, addWarn, _ = newCaptures()
	checkSigHashModule(s, addOK, addWarn)
	if len(cap.warn) != 0 || len(cap.ok) != 1 {
		t.Errorf("a module id logged since: %+v, want OK", cap)
	}

	s.Secret.SigHash = "sha1"
	cap, addOK, addWarn, _ = newCaptures()
	checkSigHashModule(s, addOK, addWarn)
	if len(cap.ok)+len(cap.warn) != 0 {
		t.Errorf("sha1: %+v, want silence", cap)
	}
}

// Signing with the 128-bit form while nginx's lines say the module in front
// does not verify it is a WARN that says the setting is not in effect (the
// daemon holds the form back; nobody is refused); lines that answer for the
// form are OK; no state to read is silence, as is a state file with no
// module line in it.
func TestCheckSigHashModuleWide(t *testing.T) {
	dir := t.TempDir()
	s := settings.Settings{}
	s.Nginx.OutputDir = dir
	s.Secret.SigHash = "sha256-128"

	cap, addOK, addWarn, _ := newCaptures()
	checkSigHashModule(s, addOK, addWarn)
	if len(cap.ok)+len(cap.warn) != 0 {
		t.Errorf("no state file yet: %+v", cap)
	}

	// A module from before 0.1.58: it logs its id and no word.
	w := renderwatch.New(func() string { return dir })
	w.SawModule("0123456789abcdef", "", time.Now().Add(-3*time.Minute))
	if err := w.Save(); err != nil {
		t.Fatal(err)
	}
	cap, addOK, addWarn, _ = newCaptures()
	checkSigHashModule(s, addOK, addWarn)
	if len(cap.warn) != 1 || len(cap.ok) != 0 ||
		!strings.Contains(cap.warn[0], "cookie signature") || !strings.Contains(cap.warn[0], "sha256-128") ||
		!strings.Contains(cap.warn[0], "no visitor is refused") || !strings.Contains(cap.warn[0], "restarted onto the 0.1.58 module") {
		t.Errorf("a module that does not say it verifies the form: %+v, want one warning that names the restart", cap)
	}
	// The same lines are fine for the 64-bit HMAC-SHA256 form, which that
	// module verifies.
	s.Secret.SigHash = "sha256"
	cap, addOK, addWarn, _ = newCaptures()
	checkSigHashModule(s, addOK, addWarn)
	if len(cap.warn) != 0 || len(cap.ok) != 1 {
		t.Errorf("sha256 with a module that logs its id: %+v, want OK", cap)
	}
	s.Secret.SigHash = "sha256-128"

	// nginx restarted onto the 0.1.58 module, two minutes ago.
	w.SawModule("fedcba9876543210", "sig128", time.Now().Add(-2*time.Minute))
	if err := w.Save(); err != nil {
		t.Fatal(err)
	}
	cap, addOK, addWarn, _ = newCaptures()
	checkSigHashModule(s, addOK, addWarn)
	if len(cap.warn) != 0 || len(cap.ok) != 1 || !strings.Contains(cap.ok[0], "sha256-128") {
		t.Errorf("the module answers for the form: %+v, want OK", cap)
	}

	// A line without the word since (an old worker, another nginx): held
	// back again, and doctor says so.
	w.SawModule("0123456789abcdef", "", time.Now().Add(-5*time.Second))
	if err := w.Save(); err != nil {
		t.Fatal(err)
	}
	cap, addOK, addWarn, _ = newCaptures()
	checkSigHashModule(s, addOK, addWarn)
	if len(cap.warn) != 1 {
		t.Errorf("a line without the word five seconds ago: %+v, want a warning", cap)
	}

	// A state file from before 0.1.58 -- module lines, no word of what they
	// verify -- reads as lines that answered for nothing.
	old := t.TempDir()
	at := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	if err := os.WriteFile(filepath.Join(old, renderwatch.StateFile), []byte(`{"seen":{},"module":{"0123456789abcdef":"`+at+`"}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	s.Nginx.OutputDir = old
	cap, addOK, addWarn, _ = newCaptures()
	checkSigHashModule(s, addOK, addWarn)
	if len(cap.warn) != 1 {
		t.Errorf("a state file from before 0.1.58: %+v, want a warning", cap)
	}
}
