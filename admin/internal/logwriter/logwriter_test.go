package logwriter

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestWriteAndReopen(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "x.log")

	lw, err := New(path)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer lw.Close()

	if _, err := lw.Write([]byte("first\n")); err != nil {
		t.Fatalf("write1: %v", err)
	}

	// Mimic logrotate: rename the file, leaving the original path empty.
	rotated := path + ".1"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatalf("rename: %v", err)
	}
	// After rename, writes before reopen go to the old inode (= the rotated file).
	if _, err := lw.Write([]byte("between\n")); err != nil {
		t.Fatalf("write2: %v", err)
	}
	// reopen creates a new inode.
	if err := lw.Reopen(); err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if _, err := lw.Write([]byte("after\n")); err != nil {
		t.Fatalf("write3: %v", err)
	}

	rotatedBytes, _ := os.ReadFile(rotated)
	if !bytes.Equal(rotatedBytes, []byte("first\nbetween\n")) {
		t.Errorf("rotated content unexpected: %q", rotatedBytes)
	}
	freshBytes, _ := os.ReadFile(path)
	if !bytes.Equal(freshBytes, []byte("after\n")) {
		t.Errorf("fresh content unexpected: %q", freshBytes)
	}
}

func TestReopenFailureKeepsOldFd(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "y.log")
	lw, err := New(path)
	if err != nil {
		t.Fatalf("new: %v", err)
	}
	defer lw.Close()

	// Make the parent dir read-only to force reopen to fail.  Verify that the
	// existing fd is preserved (= the write destination is not lost).
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	defer os.Chmod(dir, 0o755)
	// Remove the path itself so the create is rejected, then reopen.
	_ = os.Remove(path)
	if err := lw.Reopen(); err == nil {
		// With dir mode 0500 the create should be rejected; if not, it's an env diff.
		t.Skip("reopen unexpectedly succeeded — test env permits create")
	}
	// If the old fd was preserved, Write should succeed (= the file is gone but writes still go through the fd).
	if _, err := lw.Write([]byte("after-fail\n")); err != nil {
		t.Errorf("write after failed reopen: %v", err)
	}
}
