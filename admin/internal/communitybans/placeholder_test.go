package communitybans

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A fresh install whose first feed fetch fails (hub unreachable) must still end
// up with valid, includable map files, or `nginx -t` aborts on the dangling
// community-bans-*.map includes and nginx won't start.
func TestEnsureMapPlaceholders(t *testing.T) {
	dir := t.TempDir()
	maps := []string{
		"community-bans-ipja4.map",
		"community-bans-ja4.map",
		"community-bans-ip.map",
	}

	// Absent -> all three placeholders created.
	ensureMapPlaceholders(dir)
	for _, f := range maps {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Fatalf("expected placeholder %s to exist: %v", f, err)
		}
	}

	// Already populated -> never clobbered (a later real pull wrote entries).
	populated := filepath.Join(dir, "community-bans-ipja4.map")
	if err := os.WriteFile(populated, []byte("\"1.2.3.4:abc\" 1;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ensureMapPlaceholders(dir)
	b, err := os.ReadFile(populated)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "1.2.3.4") {
		t.Fatalf("ensureMapPlaceholders clobbered a populated map: %q", b)
	}

	// Empty dir is a no-op, not a panic.
	ensureMapPlaceholders("")
}
