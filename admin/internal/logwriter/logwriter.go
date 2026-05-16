// Package logwriter: append-mode writer for log files + SIGHUP reopen support.
//
// Purpose: open the log output file for unmask-admin ourselves, and reopen
// the file fd when logrotate (or similar) sends SIGHUP after renaming /
// truncating the file.
//
// Background:
//   - systemd's StandardOutput=append:FILE holds the fd on the systemd side,
//     so unmask-admin can't do anything for logrotate (= it keeps writing to
//     the old inode after rename).
//   - Pointing Go's log package directly at the file and reopening on SIGHUP
//     is the conventional daemon pattern.
package logwriter

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
)

// LogWriter: io.Writer compatible + Reopen() swaps the fd.  If Reopen runs
// during a Write, the in-flight Write completes against the "previous fd"
// and subsequent Writes go to the new fd.
type LogWriter struct {
	mu   sync.Mutex
	path string
	f    *os.File
}

// New: open path in append mode.  Creates the parent dir if missing (= 0750).
func New(path string) (*LogWriter, error) {
	lw := &LogWriter{path: path}
	if err := lw.open(); err != nil {
		return nil, err
	}
	return lw, nil
}

func (lw *LogWriter) open() error {
	if lw.path == "" {
		return fmt.Errorf("logwriter: empty path")
	}
	if dir := filepath.Dir(lw.path); dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o750)
	}
	f, err := os.OpenFile(lw.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("logwriter: open %s: %w", lw.path, err)
	}
	lw.f = f
	return nil
}

func (lw *LogWriter) Write(p []byte) (int, error) {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if lw.f == nil {
		return 0, io.ErrClosedPipe
	}
	return lw.f.Write(p)
}

// Reopen: close the current fd + reopen the same path.  Call this on SIGHUP
// from logrotate's postrotate.  On failure, keep the old fd alive and return
// the error (= so we don't lose the write target when opening the new fd fails).
func (lw *LogWriter) Reopen() error {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	old := lw.f
	f, err := os.OpenFile(lw.path, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o640)
	if err != nil {
		return fmt.Errorf("logwriter: reopen %s: %w", lw.path, err)
	}
	lw.f = f
	if old != nil {
		_ = old.Close()
	}
	return nil
}

func (lw *LogWriter) Close() error {
	lw.mu.Lock()
	defer lw.mu.Unlock()
	if lw.f == nil {
		return nil
	}
	err := lw.f.Close()
	lw.f = nil
	return err
}

// Path: returns the current path (= for debugging).
func (lw *LogWriter) Path() string { return lw.path }
