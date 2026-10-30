package main

import (
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
	w.SawModule("", time.Now().Add(-time.Minute))
	if err := w.Save(); err != nil {
		t.Fatal(err)
	}
	cap, addOK, addWarn, _ = newCaptures()
	checkSigHashModule(s, addOK, addWarn)
	if len(cap.warn) != 1 || !strings.Contains(cap.warn[0], "cookie signature") || !strings.Contains(cap.warn[0], "sig_hash back to sha1") {
		t.Errorf("lines without a module id: %+v, want one warning naming the way back", cap)
	}

	w.SawModule("0123456789abcdef", time.Now())
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
