package nginxconf

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Rendering the same settings twice must leave the files alone.
//
// It did not: every render rewrote every file, so an .inc mtime meant "a
// render ran" -- and a package upgrade runs one on install.  That made the
// mtimes useless for the only question worth asking of them, "is the running
// nginx behind the config", and the first version of doctor's reload check
// read them and called all seven fleet nodes stale minutes after an upgrade
// that changed nothing.
func TestRenderIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	s := settings.Settings{}
	s.Nginx.OutputDir = dir

	if err := Render(s, dir, "0.1.22"); err != nil {
		t.Fatalf("first render: %v", err)
	}
	marker := filepath.Join(dir, SubstantiveRenderMarker)
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("first render must record the marker: %v", err)
	}

	before := map[string]time.Time{}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		// Backdate everything so an unchanged file is provably untouched
		// rather than merely re-stamped within the same clock second.
		old := time.Now().Add(-2 * time.Hour)
		if err := os.Chtimes(filepath.Join(dir, e.Name()), old, old); err != nil {
			t.Fatal(err)
		}
		before[e.Name()] = old
	}

	// Same settings, different version string: the stamps differ, the config
	// does not.  Nothing may be rewritten.
	if err := Render(s, dir, "0.1.23"); err != nil {
		t.Fatalf("second render: %v", err)
	}
	for name, was := range before {
		fi, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if !fi.ModTime().Equal(was) {
			t.Errorf("%s was rewritten by a render that changed nothing", name)
		}
	}

	// A real change must come through -- both the file and the marker.
	s.Nginx.ChallengeTargets.Extra = []string{"contains:SomeNewBot"}
	if err := Render(s, dir, "0.1.23"); err != nil {
		t.Fatalf("third render: %v", err)
	}
	fi, err := os.Stat(filepath.Join(dir, "http.inc"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.ModTime().Equal(before["http.inc"]) {
		t.Fatal("a substantive change did not reach http.inc")
	}
	if mi, err := os.Stat(marker); err != nil {
		t.Fatal(err)
	} else if mi.ModTime().Equal(before[SubstantiveRenderMarker]) {
		t.Fatal("a substantive change did not advance the marker")
	}
}
