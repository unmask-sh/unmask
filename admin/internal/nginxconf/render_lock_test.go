package nginxconf

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// holdRenderLock takes the directory's render lock the way another process's
// render does (a descriptor of its own), and returns what lets it go.
func holdRenderLock(t *testing.T, dir string) func() {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(dir, ".render.lock"), os.O_RDONLY|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}
}

// A render waits for another process's render of the same directory: the
// CLI's render-nginx and the daemon each replace several files, and
// interleaved they could leave files of two renders side by side.  The mutex
// the renders of one process share says nothing to the other process.
func TestRenderWaitsForAnotherProcessesRender(t *testing.T) {
	dir := t.TempDir()
	var s settings.Settings
	s.Nginx.OutputDir = dir
	release := holdRenderLock(t, dir)

	done := make(chan error, 1)
	go func() { done <- Render(s, dir, "test") }()
	select {
	case err := <-done:
		t.Fatalf("the render went ahead while another held the directory's lock (err=%v)", err)
	case <-time.After(400 * time.Millisecond):
	}
	if _, err := os.Stat(filepath.Join(dir, "http.inc")); err == nil {
		t.Fatal("http.inc was written while another render held the lock")
	}
	release()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Render: %v", err)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the render did not go on after the lock was released")
	}
	if _, err := os.Stat(filepath.Join(dir, "http.inc")); err != nil {
		t.Errorf("no http.inc after the render: %v", err)
	}
}

// A lock that is not let go -- a process stopped in the middle of a render --
// does not hold a settings save for ever: past the wait, the render goes
// ahead as every render did before there was a lock.
func TestRenderGoesAheadPastAStuckLock(t *testing.T) {
	old := renderLockWait
	renderLockWait = 200 * time.Millisecond
	t.Cleanup(func() { renderLockWait = old })

	dir := t.TempDir()
	var s settings.Settings
	s.Nginx.OutputDir = dir
	release := holdRenderLock(t, dir)
	defer release()
	start := time.Now()
	if err := Render(s, dir, "test"); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if waited := time.Since(start); waited < 200*time.Millisecond {
		t.Errorf("the render waited %v, less than the %v it gives another render", waited, renderLockWait)
	}
	if _, err := os.Stat(filepath.Join(dir, "http.inc")); err != nil {
		t.Errorf("no http.inc after the render: %v", err)
	}
}
