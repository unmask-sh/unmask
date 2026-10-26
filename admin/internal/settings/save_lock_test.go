package settings

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Save writes through a temp file of its own name in the config's dir and
// leaves nothing but the file and the lock file behind, the file 0600.
func TestSaveLeavesOnlyTheFileAndTheLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	s := defaults()
	s.Server.BasePath = "/one"
	if err := Save(s, path); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(path)
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("config: %v, mode %v", err, st.Mode())
	}
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if strings.Join(names, ",") != "config.yml,config.yml.lock" {
		t.Errorf("the dir after a save: %v", names)
	}
	back, err := Load(path)
	if err != nil || back.Server.BasePath != "/one" {
		t.Errorf("the saved file loads as %q (%v)", back.Server.BasePath, err)
	}
}

// A Save waits for the lock another writer holds, and an Update's
// read-modify-write is whole: two writers that each add a host, run at
// once, leave both hosts in the file.
func TestSaveAndUpdateSerializeOnTheLock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yml")
	if err := Save(defaults(), path); err != nil {
		t.Fatal(err)
	}

	unlock, err := lockConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	saved := make(chan error, 1)
	go func() { saved <- Save(defaults(), path) }()
	select {
	case err := <-saved:
		t.Fatalf("a save went through while the lock was held: %v", err)
	case <-time.After(200 * time.Millisecond):
	}
	unlock()
	select {
	case err := <-saved:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the save did not go through after the lock was released")
	}

	var wg sync.WaitGroup
	for _, host := range []string{"a.example.com", "b.example.com", "c.example.com", "d.example.com"} {
		wg.Add(1)
		go func(host string) {
			defer wg.Done()
			err := Update(path, func(s *Settings) error {
				s.Nginx.AdminAllowedHosts = append(s.Nginx.AdminAllowedHosts, host)
				return nil
			})
			if err != nil {
				t.Error(err)
			}
		}(host)
	}
	wg.Wait()
	back, err := Load(path)
	if err != nil || len(back.Nginx.AdminAllowedHosts) != 4 {
		t.Errorf("after four concurrent updates the file holds %v (%v)", back.Nginx.AdminAllowedHosts, err)
	}
}
