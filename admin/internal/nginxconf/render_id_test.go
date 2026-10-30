package nginxconf

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// renderInto renders s into dir (an existing scratch dir with a stub
// nginx.conf) under the given build version.
func renderInto(t *testing.T, dir, version string, mutate func(*settings.Settings)) {
	t.Helper()
	conf := filepath.Join(dir, "nginx.conf")
	if _, err := os.Stat(conf); err != nil {
		if err := os.WriteFile(conf, []byte("http {\n}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var s settings.Settings
	s.Nginx.OutputDir = dir
	s.Nginx.ConfPath = conf
	if mutate != nil {
		mutate(&s)
	}
	if err := Render(s, dir, version); err != nil {
		t.Fatalf("Render: %v", err)
	}
}

// TestRenderIDNamesTheConfiguration: every log line carries the id of the
// render nginx loaded (rv=), and the id is a function of what nginx is told
// to do -- nothing else.  The same settings give the same id from another
// build (an upgrade that changes nothing must not read as "reload pending"),
// a setting nginx sees gives a new one, and going back gives the old one
// back (nginx never reloaded in between is then up to date again).
func TestRenderIDNamesTheConfiguration(t *testing.T) {
	dir := t.TempDir()
	renderInto(t, dir, "0.1.50", nil)
	id1, written1 := RenderIDOnDisk(dir)
	if !regexp.MustCompile(`^[0-9a-f]{12}$`).MatchString(id1) {
		t.Fatalf("render id %q: want 12 hex digits", id1)
	}
	b, err := os.ReadFile(filepath.Join(dir, "http.inc"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), " rv="+id1+" pv=$unmask_preview_verified sb=$is_search_bot sfs=$unmask_sfs_log sfd=$unmask_sfd_log rh=$unmask_ref_host bv=$unmask_bv_log mo=$unmask_module_id ua=$http_user_agent';") {
		t.Errorf("the log format does not carry rv=%s ahead of pv=, sb= and ua=", id1)
	}

	// Another build, same settings: same id, and http.inc is not rewritten.
	time.Sleep(10 * time.Millisecond)
	renderInto(t, dir, "0.1.51", nil)
	id2, written2 := RenderIDOnDisk(dir)
	if id2 != id1 {
		t.Errorf("an upgrade that changes nothing changed the id: %s -> %s", id1, id2)
	}
	if !written2.Equal(written1) {
		t.Errorf("an upgrade that changes nothing rewrote http.inc (%s -> %s)", written1, written2)
	}

	// A setting nginx sees: a new id.
	renderInto(t, dir, "0.1.51", func(s *settings.Settings) {
		s.Challenge.Default.ObserveOnly = settings.BoolPtr(true)
	})
	id3, _ := RenderIDOnDisk(dir)
	if id3 == id1 || id3 == "" {
		t.Errorf("monitor mode on: id %q, want a new one (was %s)", id3, id1)
	}

	// And back: the first id again.
	renderInto(t, dir, "0.1.51", nil)
	if id4, _ := RenderIDOnDisk(dir); id4 != id1 {
		t.Errorf("back to the first settings: id %s, want %s", id4, id1)
	}
}

// TestRenderIDOnDiskWithoutOne: no http.inc, or one from a build that wrote
// no id, reads as "" -- the daemon then has nothing to compare and says
// nothing.
func TestRenderIDOnDiskWithoutOne(t *testing.T) {
	dir := t.TempDir()
	if id, _ := RenderIDOnDisk(dir); id != "" {
		t.Errorf("no http.inc: id %q, want empty", id)
	}
	old := "log_format unmask_minimal '$msec site=$host kind=$bv_kind cr=$unmask_cr_id ua=$http_user_agent';\n"
	if err := os.WriteFile(filepath.Join(dir, "http.inc"), []byte(old), 0o640); err != nil {
		t.Fatal(err)
	}
	if id, written := RenderIDOnDisk(dir); id != "" || written.IsZero() {
		t.Errorf("http.inc without rv=: id %q written %v, want empty id and the file's time", id, written)
	}
}

// TestRenderSignatureCarriesNoID: the settings page compares two signatures
// to decide whether to ask for a reload.  The id is derived from the same
// output, so it must not be part of it (it would be circular, and it adds
// nothing: the id changes exactly when the rest does).
func TestRenderSignatureCarriesNoID(t *testing.T) {
	dir := t.TempDir()
	var s settings.Settings
	s.Nginx.OutputDir = dir
	sig, err := RenderSignature(s, dir, "test")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sig, " rv=") {
		t.Error("RenderSignature output carries rv=")
	}
}
