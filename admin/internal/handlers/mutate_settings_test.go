package handlers

import (
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// Two writers whose read-modify-write overlap both land: mutateSettings
// loads, changes and saves under one lock, and UpdateSettings goes through
// it.  Most handlers used to load the file, change their copy and save it
// with only the publish locked, so of two that overlapped -- the hub's token
// write-back and an operator's save, two operators -- the one that saved
// first lost its change to the other's copy of the file.
func TestMutateSettingsKeepsOverlappingWrites(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yml")
	if err := settings.Save(settings.Settings{}, cfg); err != nil {
		t.Fatal(err)
	}
	h := &Handler{ConfigPath: cfg}
	h.SetSettings(settings.Settings{})

	const n = 40
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			ip := fmt.Sprintf("10.0.0.%d", i)
			if _, err := h.mutateSettings(func(s *settings.Settings) error {
				s.Nginx.AdminAllowedIPs = append(s.Nginx.AdminAllowedIPs, ip)
				return nil
			}); err != nil {
				t.Error(err)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < n; i++ {
			key := fmt.Sprintf("mute-%d", i)
			if err := h.UpdateSettings(func(s *settings.Settings) {
				s.CommunityBans.LocalMutes = append(s.CommunityBans.LocalMutes, key)
			}); err != nil {
				t.Error(err)
			}
		}
	}()
	wg.Wait()

	onDisk, err := settings.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	live := h.snapshotSettings()
	for name, s := range map[string]settings.Settings{"on disk": onDisk, "live": live} {
		if got := len(s.Nginx.AdminAllowedIPs); got != n {
			t.Errorf("%s: %d of the %d allowed-IP writes survived", name, got, n)
		}
		if got := len(s.CommunityBans.LocalMutes); got != n {
			t.Errorf("%s: %d of the %d mute writes survived", name, got, n)
		}
	}

	// A callback that refuses saves nothing, and its error comes back as
	// given, so the caller can tell its own "nothing to do" from a failure.
	refused := errors.New("nothing to do")
	if _, err := h.mutateSettings(func(s *settings.Settings) error {
		s.Nginx.AdminAllowedIPs = nil
		return refused
	}); !errors.Is(err, refused) {
		t.Errorf("the callback's error came back as %v", err)
	}
	after, err := settings.Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(after.Nginx.AdminAllowedIPs) != n || len(h.snapshotSettings().Nginx.AdminAllowedIPs) != n {
		t.Error("a refused mutation was saved or published")
	}
}
