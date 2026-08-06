package settings

import (
	"bytes"
	"log"
	"testing"
)

// The generic unknown-key warning is easy to read as harmless; a leftover
// `challenge_targets.all: true` is not, so it gets its own message naming
// the consequence and the replacement (an explicit row with action deny).
func TestWarnRemovedChallengeAll(t *testing.T) {
	capture := func(raw string) string {
		var buf bytes.Buffer
		old := log.Writer()
		log.SetOutput(&buf)
		defer log.SetOutput(old)
		warnRemovedChallengeAll("/etc/unmask/config.yml", []byte(raw))
		return buf.String()
	}

	got := capture("nginx:\n  challenge_targets:\n    all: true\n    extra: []\n")
	for _, want := range []string{"REMOVED in 0.1.19", "deny", "render-nginx"} {
		if !bytes.Contains([]byte(got), []byte(want)) {
			t.Fatalf("all:true warning must mention %q, got: %s", want, got)
		}
	}

	if got := capture("nginx:\n  challenge_targets:\n    all: false\n"); got == "" {
		t.Fatal("all:false leftover should still warn (the key is dead either way)")
	} else if bytes.Contains([]byte(got), []byte("deny")) {
		t.Fatalf("all:false is not a defense downgrade; the strong wording is for true only, got: %s", got)
	}

	if got := capture("nginx:\n  challenge_targets:\n    extra: []\n"); got != "" {
		t.Fatalf("no leftover key -> no warning, got: %s", got)
	}
	if got := capture(":: not yaml ::"); got != "" {
		t.Fatalf("unparsable yaml must stay silent here (Load already errors), got: %s", got)
	}
}
