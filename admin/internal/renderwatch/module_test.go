package renderwatch

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The module is compared the way the configuration is: the file at
// load_module's path hashes to the id nginx should log (the module's own
// $unmask_module_id); a line naming another id -- or none, from a module
// before ids -- after the file was placed plus the grace says nginx runs an
// older module; a line with the file's id since then says it loaded it; and
// with no path to a module there is nothing to compare.
func TestModuleBehindUntilNginxLogsTheFileOnDisk(t *testing.T) {
	dir := t.TempDir()
	so := filepath.Join(dir, "ngx_http_unmask_module.so")
	if err := os.WriteFile(so, []byte("the new module's bytes"), 0o755); err != nil {
		t.Fatal(err)
	}
	placed := time.Now().Add(-3 * time.Minute)
	if err := os.Chtimes(so, placed, placed); err != nil {
		t.Fatal(err)
	}
	onDisk, at := ModuleIDOnDisk(so)
	if len(onDisk) != 16 || !at.Equal(placed) {
		t.Fatalf("ModuleIDOnDisk: %q at %v, want 16 hex digits placed at %v", onDisk, at, placed)
	}

	w := New(func() string { return dir })
	w.SetModulePath(func() string { return so })
	if st := w.State(); st.ModuleCurrent != onDisk || st.ModulePending {
		t.Errorf("no lines yet: %+v, want the file's id and nothing pending", st)
	}
	// The running nginx keeps logging the module it loaded before the file
	// was placed.
	w.SawModule("0123456789abcdef", placed.Add(2*time.Minute))
	st := w.State()
	if !st.ModulePending || st.ModuleRunning != "0123456789abcdef" || !st.ModulePlaced.Equal(placed) {
		t.Errorf("older module after the grace: %+v, want pending, running 0123456789abcdef", st)
	}
	// A line without the field -- a module from before module ids -- is
	// older too.
	w2 := New(func() string { return dir })
	w2.SetModulePath(func() string { return so })
	w2.SawModule("", placed.Add(2*time.Minute))
	if st := w2.State(); !st.ModulePending || st.ModuleRunning != "" {
		t.Errorf("a line without mo= after the grace: %+v, want pending", st)
	}
	// Once nginx logs the file on disk, it is up to date -- old lines or not.
	w.SawModule(onDisk, placed.Add(4*time.Minute))
	if st := w.State(); st.ModulePending {
		t.Errorf("the file's own id logged: %+v, want nothing pending", st)
	}
	// The render comparison stays its own: no http.inc here, nothing pending.
	if st := w.State(); st.Pending || st.Current != "" {
		t.Errorf("the configuration side: %+v, want nothing (no http.inc)", st)
	}

	// No module wired: nothing to compare, whatever the lines say.
	w3 := New(func() string { return dir })
	w3.SetModulePath(func() string { return "" })
	w3.SawModule("0123456789abcdef", time.Now())
	if st := w3.State(); st.ModulePending || st.ModuleCurrent != "" {
		t.Errorf("no module path: %+v, want nothing", st)
	}
	w4 := New(func() string { return dir })
	w4.SawModule("0123456789abcdef", time.Now())
	if st := w4.State(); st.ModulePending {
		t.Errorf("no path function: %+v, want nothing", st)
	}

	// What was seen survives a save and a load.
	if err := w.Save(); err != nil {
		t.Fatal(err)
	}
	w5 := New(func() string { return dir })
	w5.SetModulePath(func() string { return so })
	w5.Load()
	if st := w5.State(); st.ModulePending {
		t.Errorf("after load: %+v, want the logged file's id remembered", st)
	}
	w5.mu.Lock()
	_, remembered := w5.modSeen[onDisk]
	w5.mu.Unlock()
	if !remembered {
		t.Error("the state file did not carry the module ids")
	}
}
