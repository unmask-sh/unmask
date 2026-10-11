package settings

import (
	"bytes"
	"log"
	"testing"
)

// A leftover global.passthrough: true was an emergency hold; the operator who
// set it has to learn from the log that enforcement is back on and where the
// one remaining switch lives.
func TestWarnRemovedGlobalPassthrough(t *testing.T) {
	capture := func(raw string) string {
		var buf bytes.Buffer
		old := log.Writer()
		log.SetOutput(&buf)
		defer log.SetOutput(old)
		warnRemovedGlobalPassthrough("/etc/unmask/config.yml", []byte(raw))
		return buf.String()
	}

	got := capture("global:\n  passthrough: true\n  known_browser_action: pass\n")
	for _, want := range []string{"REMOVED in 0.1.51", "enforcement is ON", "observe_only", "render-nginx"} {
		if !bytes.Contains([]byte(got), []byte(want)) {
			t.Fatalf("passthrough:true warning must mention %q, got: %s", want, got)
		}
	}

	if got := capture("global:\n  passthrough: false\n"); got == "" {
		t.Fatal("passthrough:false leftover should still warn (the key is dead either way)")
	} else if bytes.Contains([]byte(got), []byte("enforcement is ON")) {
		t.Fatalf("passthrough:false changes nothing; the strong wording is for true only, got: %s", got)
	}

	if got := capture("global:\n  known_browser_action: pass\n"); got != "" {
		t.Fatalf("no leftover key -> no warning, got: %s", got)
	}
	if got := capture(":: not yaml ::"); got != "" {
		t.Fatalf("unparsable yaml must stay silent here (Load already errors), got: %s", got)
	}
}
