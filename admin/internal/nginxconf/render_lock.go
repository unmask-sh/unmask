package nginxconf

import (
	"errors"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// renderLockWait: how long a render waits for another process's render of
// the same directory before it goes ahead beside it.  A render is a fraction
// of a second, a few seconds where the GeoIP walk is long; a lock held past
// this is a process that stopped mid-render, and a settings save must not
// wait on that for ever.
var renderLockWait = 30 * time.Second

// lockRenderDir takes the render lock of outDir -- flock on ".render.lock"
// in it -- and returns what releases it.
//
// renderMu serialises the renders of one process.  `unmask render-nginx` is
// another process, and it runs beside the daemon's own renders: on an
// upgrade (the package's script) while a save or the IP-range pull renders,
// and after an edit of config.yml, where the operator renders by hand at
// about the moment the daemon's config watch does.  Each file is replaced
// by rename, but the files of one render are several, and two renders
// interleaved could leave an http.inc of one beside a protect.inc of the
// other -- which nginx refuses when the two disagree on a variable.
//
// Best effort: a directory the lock file cannot be opened in (read-only,
// another owner's) and a lock not had within renderLockWait both go ahead
// unlocked, as every render did before.  The file is opened read-only, so a
// lock file the root CLI created serves the daemon's user too.
func lockRenderDir(outDir string) func() {
	path := filepath.Join(outDir, ".render.lock")
	f, err := os.OpenFile(path, os.O_RDONLY|os.O_CREATE, 0o644)
	if err != nil {
		return func() {}
	}
	deadline := time.Now().Add(renderLockWait)
	for {
		err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			return func() {
				_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
				_ = f.Close()
			}
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) || time.Now().After(deadline) {
			log.Printf("render: %s is still held by another render after %s (%v); rendering beside it", path, renderLockWait, err)
			_ = f.Close()
			return func() {}
		}
		time.Sleep(50 * time.Millisecond)
	}
}
