package renderwatch

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestEvaluate pins the rule: behind = a line from another configuration
// after the file was written (plus the grace), and none from the current one
// since.  Everything else says nothing.
func TestEvaluate(t *testing.T) {
	w0 := time.Date(2026, 10, 12, 15, 0, 0, 0, time.UTC)
	at := func(d time.Duration) time.Time { return w0.Add(d) }
	cases := []struct {
		name    string
		current string
		seen    map[string]time.Time
		pending bool
		fresh   bool
		running string
	}{
		{"no lines at all: nothing to say", "bbb", map[string]time.Time{}, false, false, ""},
		{"no id on disk: nothing to compare", "", map[string]time.Time{"aaa": at(time.Hour)}, false, false, ""},
		{"older id after the grace: behind", "bbb", map[string]time.Time{"aaa": at(2 * time.Minute)}, true, false, "aaa"},
		{"a line without rv= after the grace: behind (a config from before ids)", "bbb", map[string]time.Time{"": at(2 * time.Minute)}, true, false, ""},
		{"older id inside the grace: not yet", "bbb", map[string]time.Time{"aaa": at(30 * time.Second)}, false, false, ""},
		{"current id since the write: up to date", "bbb", map[string]time.Time{"bbb": at(10 * time.Second)}, false, true, ""},
		{"current id since the write, old workers still draining: up to date", "bbb",
			map[string]time.Time{"bbb": at(10 * time.Second), "aaa": at(5 * time.Minute)}, false, true, ""},
		{"current id seen only before this write (A, B, back to A), older id after: behind", "aaa",
			map[string]time.Time{"aaa": at(-time.Hour), "bbb": at(3 * time.Minute)}, true, false, "bbb"},
		{"the latest of two older ids is named", "ccc",
			map[string]time.Time{"aaa": at(2 * time.Minute), "bbb": at(4 * time.Minute)}, true, false, "bbb"},
	}
	for _, c := range cases {
		st := Evaluate(c.current, w0, c.seen)
		if st.Pending != c.pending || st.Fresh() != c.fresh || st.Running != c.running {
			t.Errorf("%s: pending=%v fresh=%v running=%q, want pending=%v fresh=%v running=%q",
				c.name, st.Pending, st.Fresh(), st.Running, c.pending, c.fresh, c.running)
		}
	}
}

// renderTo renders a minimal configuration into dir, as the daemon does.
func renderTo(t *testing.T, dir string, observe bool) {
	t.Helper()
	conf := filepath.Join(dir, "nginx.conf")
	if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var s settings.Settings
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	if observe {
		s.Challenge.Default.ObserveOnly = settings.BoolPtr(true)
	}
	if err := nginxconf.Render(s, dir, "test"); err != nil {
		t.Fatalf("Render: %v", err)
	}
}

// TestWatchOverARender: the watch reads the id from the http.inc a render
// wrote, and a re-render that changes the configuration is noticed (the
// file is looked at again, not the cached id kept).
func TestWatchOverARender(t *testing.T) {
	dir := t.TempDir()
	renderTo(t, dir, false)
	first, written := nginxconf.RenderIDOnDisk(dir)
	if first == "" {
		t.Fatal("the render wrote no id")
	}
	w := New(func() string { return dir })
	w.Saw(first, written.Add(5*time.Second))
	if st := w.State(); !st.Fresh() || st.Pending {
		t.Fatalf("nginx logs the rendered id: want fresh, got %+v", st)
	}

	// The settings change; nginx keeps logging the first id.
	time.Sleep(20 * time.Millisecond) // a distinct mtime
	renderTo(t, dir, true)
	second, written2 := nginxconf.RenderIDOnDisk(dir)
	if second == first {
		t.Fatal("a changed configuration kept its id")
	}
	w.statAt = time.Time{} // look at the file now rather than in statEvery
	w.Saw(first, written2.Add(2*time.Minute))
	st := w.State()
	if !st.Pending || st.Current != second || st.Running != first {
		t.Fatalf("nginx still logs the first id: want pending (running %s, current %s), got %+v", first, second, st)
	}

	// The reload: the new id appears, old workers drain.
	w.Saw(second, written2.Add(3*time.Minute))
	w.Saw(first, written2.Add(4*time.Minute))
	if st := w.State(); st.Pending || !st.Fresh() {
		t.Fatalf("after the reload: want fresh, got %+v", st)
	}
}

// TestSaveLoad: what the daemon saw survives in the state file, for
// `unmask doctor` and for the daemon's next start.
func TestSaveLoad(t *testing.T) {
	dir := t.TempDir()
	w := New(func() string { return dir })
	t0 := time.Date(2026, 10, 12, 15, 0, 0, 0, time.UTC)
	w.Saw("aaaaaaaaaaaa", t0)
	w.Saw("", t0.Add(time.Minute))
	if err := w.Save(); err != nil {
		t.Fatal(err)
	}
	seen, err := LoadSeen(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !seen["aaaaaaaaaaaa"].Equal(t0) || !seen[""].Equal(t0.Add(time.Minute)) || len(seen) != 2 {
		t.Fatalf("state file round trip: %v", seen)
	}
	// Nothing new: no write (the file keeps its content even if removed
	// from under us -- Save only writes when it saw something).
	if err := os.Remove(filepath.Join(dir, StateFile)); err != nil {
		t.Fatal(err)
	}
	if err := w.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, StateFile)); !os.IsNotExist(err) {
		t.Error("Save wrote although nothing was seen since the last one")
	}

	w2 := New(func() string { return dir })
	w2.Saw("bbbbbbbbbbbb", t0.Add(2*time.Minute))
	if err := w.Save(); err != nil { // nothing new for w: still no file
		t.Fatal(err)
	}
	w.Saw("aaaaaaaaaaaa", t0.Add(5*time.Minute))
	if err := w.Save(); err != nil {
		t.Fatal(err)
	}
	w2.Load()
	w2.mu.Lock()
	defer w2.mu.Unlock()
	if !w2.seen["aaaaaaaaaaaa"].Equal(t0.Add(5*time.Minute)) || !w2.seen["bbbbbbbbbbbb"].Equal(t0.Add(2*time.Minute)) {
		t.Fatalf("Load merged %v", w2.seen)
	}
}

// TestSawIsBounded: ids made up by whatever writes to the socket cannot
// grow the map without end.
func TestSawIsBounded(t *testing.T) {
	w := New(nil)
	t0 := time.Date(2026, 10, 12, 15, 0, 0, 0, time.UTC)
	for i := 0; i < 100; i++ {
		w.Saw(fmt.Sprintf("%012x", i), t0.Add(time.Duration(i)*time.Second))
	}
	if len(w.seen) > maxIDs {
		t.Fatalf("%d ids kept, want at most %d", len(w.seen), maxIDs)
	}
	if _, ok := w.seen[fmt.Sprintf("%012x", 99)]; !ok {
		t.Error("the newest id was dropped")
	}
}
