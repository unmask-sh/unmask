package handlers

import (
	"sync"
	"testing"

	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// TestSettingsPointerConcurrentAccess drives the live-settings hot-swap under
// the race detector: writers publish fresh snapshots (the save-handler path)
// while many readers Load via cfg() / snapshotSettings().  Before the
// atomic.Pointer refactor this raced — the settings.Settings value field was
// assigned under settingsMu but read lock-free, so a concurrent reader could
// observe a torn struct.  `go test -race` must stay clean.
func TestSettingsPointerConcurrentAccess(t *testing.T) {
	h := &Handler{}
	h.SetSettings(settings.Settings{Secret: settings.Secret{BVSecret: "seed"}})

	stop := make(chan struct{})
	var readersWG, writersWG sync.WaitGroup

	// Readers: spin on the lock-free accessors the way live handlers do until
	// the writers are done.
	for i := 0; i < 8; i++ {
		readersWG.Add(1)
		go func() {
			defer readersWG.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				_ = h.cfg().Secret.BVSecret
				_ = h.cfg().Global.Passthrough
				snap := h.snapshotSettings()
				_ = snap.Nginx.AdminAllowedIPs
			}
		}()
	}

	// Writers: two publishers racing, mirroring concurrent saves.  settingsMu
	// inside updateSettingsInMemory serializes the read-modify-publish;
	// SetSettings is the bare atomic publish (startup / test path).
	for w := 0; w < 2; w++ {
		writersWG.Add(1)
		go func() {
			defer writersWG.Done()
			for j := 0; j < 2000; j++ {
				h.updateSettingsInMemory(func(s *settings.Settings) {
					s.Secret.BVSecret = "rotated"
					s.Global.Passthrough = !s.Global.Passthrough
				})
				h.SetSettings(settings.Settings{Secret: settings.Secret{BVSecret: "replaced"}})
			}
		}()
	}

	writersWG.Wait()
	close(stop)
	readersWG.Wait()

	// The accessor still returns a usable snapshot after the churn.
	if got := h.cfg().Secret.BVSecret; got == "" {
		t.Fatal("settings snapshot empty after concurrent churn")
	}
}
