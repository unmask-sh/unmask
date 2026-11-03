package settings

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// TestMutateHoldsTheLockAcrossTheChange: the config file's lock is held
// from the load to the save, so another process (the CLI's upgrade-review)
// cannot write between the two.  A second descriptor's non-blocking flock
// is refused while fn runs -- flock is per open file description, so the
// probe stands for another process.
func TestMutateHoldsTheLockAcrossTheChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := Save(Settings{Server: Server{Port: 9477}}, path); err != nil {
		t.Fatal(err)
	}
	ran := false
	got, err := Mutate(path, func(s *Settings) error {
		ran = true
		f, err := os.OpenFile(path+".lock", os.O_RDWR, 0o600)
		if err != nil {
			return err
		}
		defer f.Close()
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if !errors.Is(err, syscall.EWOULDBLOCK) {
			t.Errorf("the lock is not held while fn runs: flock said %v", err)
		}
		s.Server.Port = 9478
		return nil
	})
	if err != nil || !ran {
		t.Fatalf("mutate: err=%v ran=%v", err, ran)
	}
	if got.Server.Port != 9478 {
		t.Fatalf("returned settings do not carry the change: port=%d", got.Server.Port)
	}
	back, err := Load(path)
	if err != nil || back.Server.Port != 9478 {
		t.Fatalf("saved settings: port=%d err=%v", back.Server.Port, err)
	}
	// Released after: a fresh lock is taken at once.
	f, err := os.OpenFile(path+".lock", os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("the lock was not released after Mutate: %v", err)
	}
}

// TestMutateErrorsSayWhichStep: a failed load and fn's own error are told
// apart by the caller (the daemon answers a request differently for each),
// and fn's error saves nothing.
func TestMutateErrorsSayWhichStep(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if _, err := Mutate(path, func(*Settings) error { return nil }); err == nil || !errors.Is(err, os.ErrNotExist) || err.Error()[:6] != "load: " {
		t.Fatalf("missing file: want a load error wrapping ErrNotExist, got %v", err)
	}
	if err := Save(Settings{Server: Server{Port: 1}}, path); err != nil {
		t.Fatal(err)
	}
	own := errors.New("refused")
	if _, err := Mutate(path, func(s *Settings) error { s.Server.Port = 2; return own }); !errors.Is(err, own) || err.Error() != "refused" {
		t.Fatalf("fn's error: want it as given, got %v", err)
	}
	if back, _ := Load(path); back.Server.Port != 1 {
		t.Fatalf("fn's error saved the change: port=%d", back.Server.Port)
	}
}
