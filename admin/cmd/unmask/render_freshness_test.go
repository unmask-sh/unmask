package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestRenderFreshnessReportsWhatChanged: the warning used to say only that
// something was out of date, with the actual difference printed to stderr as
// leftover DBG lines.  An operator reading "http.inc is out of date" has no way
// to tell a real pending config change from a check that rendered under
// different inputs -- which is exactly what happened when doctor rendered
// without the hub-pulled crawler ranges and declared every node stale.
func TestRenderFreshnessReportsWhatChanged(t *testing.T) {
	fresh, live := t.TempDir(), t.TempDir()
	write := func(dir, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "http.inc"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(live, "map $a $b {\n    172.253.181.0/27 1;\n}\n")
	write(fresh, "map $a $b {\n    192.178.10.0/27 1;\n}\n")

	var warns []string
	checkRenderFreshness(fresh, live, func(_, msg string) { warns = append(warns, msg) }, func(string, string) {})

	if len(warns) != 1 {
		t.Fatalf("expected one warning, got %v", warns)
	}
	w := warns[0]
	if !strings.Contains(w, "line 2") {
		t.Errorf("the warning does not locate the change: %s", w)
	}
	if !strings.Contains(w, "172.253.181.0/27") || !strings.Contains(w, "192.178.10.0/27") {
		t.Errorf("the warning does not show what changed: %s", w)
	}
}

// TestRenderFreshnessQuietWhenEqual: the daemon re-renders on every save, so a
// match is the normal state and must stay silent.
func TestRenderFreshnessQuietWhenEqual(t *testing.T) {
	fresh, live := t.TempDir(), t.TempDir()
	const body = "# generated_at: 2026-01-01\nmap $a $b {\n    1.2.3.0/24 1;\n}\n"
	for _, d := range []string{fresh, live} {
		if err := os.WriteFile(filepath.Join(d, "http.inc"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var warns, oks int
	checkRenderFreshness(fresh, live, func(string, string) { warns++ }, func(string, string) { oks++ })
	if warns != 0 || oks != 1 {
		t.Errorf("identical confs: warns=%d oks=%d, want 0/1", warns, oks)
	}
}

// TestRenderFreshnessLengthOnlyDifference: when one conf is a prefix of the
// other there is no differing line to point at, and the report must still say
// something an operator can act on rather than falling through to silence.
func TestRenderFreshnessLengthOnlyDifference(t *testing.T) {
	fresh, live := t.TempDir(), t.TempDir()
	// No trailing newline: with one the split yields a final "" on both sides
	// and the shorter file's extra "" becomes a differing LINE, which is
	// reported (correctly) as a change rather than a length gap.  A true prefix
	// is the case with no differing index at all.
	if err := os.WriteFile(filepath.Join(live, "http.inc"), []byte("a\nb"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(fresh, "http.inc"), []byte("a\nb\nc"), 0o600); err != nil {
		t.Fatal(err)
	}
	var warns []string
	checkRenderFreshness(fresh, live, func(_, msg string) { warns = append(warns, msg) }, func(string, string) {})
	if len(warns) != 1 || !strings.Contains(warns[0], "lines live vs") {
		t.Fatalf("length-only difference not reported usefully: %v", warns)
	}
}

// TestTruncLineMarksBlank: "-> " with nothing after it reads as a truncated
// message rather than "this line became empty".
func TestTruncLineMarksBlank(t *testing.T) {
	if got := truncLine("   "); got != "(blank)" {
		t.Errorf("truncLine(blank) = %q", got)
	}
	long := strings.Repeat("x", 100)
	if got := truncLine(long); len(got) > 60 || !strings.HasSuffix(got, "...") {
		t.Errorf("truncLine(long) = %q (len %d)", got, len(got))
	}
}
