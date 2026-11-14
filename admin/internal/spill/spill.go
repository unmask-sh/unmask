// Package spill carries across a stop of the daemon what it keeps in memory
// while the database's writes are held -- a schema update or a compaction
// run from the shell holds them, and the bans, events and audit rows of
// those minutes wait in memory for the lock.  A stop before the lock was
// free lost them without a word (review finding S5: a ban placed during the
// run was no longer in force after the restart).  At the stop each keeper
// writes what it still holds to a file of its own in the daemon's data
// directory; at the next start it reads the file back into what it keeps,
// removes it, and writes the rows once the lock is free, as it would have.
//
// The files are JSON, 0600 (an audit row names who did what, an event the
// visitor's address), written whole and renamed into place.  Each keeper
// bounds what it keeps, so a file is bounded too.
package spill

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// Save writes v as JSON to dir/name, 0600, through a temporary file renamed
// into place, so a reader finds the whole of one or nothing.
func Save(dir, name string, v any) error {
	if dir == "" {
		return errors.New("spill: no directory")
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("spill %s: %w", name, err)
	}
	f, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return fmt.Errorf("spill %s: %w", name, err)
	}
	tmp := f.Name()
	if _, err := f.Write(b); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("spill %s: %w", name, err)
	}
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return fmt.Errorf("spill %s: %w", name, err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("spill %s: %w", name, err)
	}
	if err := os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("spill %s: %w", name, err)
	}
	return nil
}

// Take reads dir/name into v and removes the file: what it held is the
// caller's from here on.  found is false when there is no such file.  A
// file that does not decode is renamed to <name>.unreadable, out of the
// next start's way and kept for a look, and reported as an error.
func Take(dir, name string, v any) (found bool, err error) {
	if dir == "" {
		return false, nil
	}
	path := filepath.Join(dir, name)
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("spill %s: %w", name, err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		_ = os.Rename(path, path+".unreadable")
		return true, fmt.Errorf("spill %s: %w (kept as %s.unreadable)", name, err, name)
	}
	if err := os.Remove(path); err != nil {
		return true, fmt.Errorf("spill %s: read, but not removed: %w", name, err)
	}
	return true, nil
}
