package handlers

import (
	"testing"
	"time"

	"github.com/unmask-sh/unmask/admin/internal/nginxconf"
	"github.com/unmask-sh/unmask/admin/internal/settings"
)

// The ban guard's allowlist is built once per settings snapshot and load of
// the crawler ranges, not per ban it vets: a honeypot hit parsed some 4,700
// ranges (about 6 ms) on the access log's worker.  A save is picked up at
// once.
func TestBanBypassMatchIsBuiltOncePerSnapshot(t *testing.T) {
	h := &Handler{}
	var s settings.Settings
	s.Nginx.BypassIPs = []string{"198.51.100.7"}
	h.SetSettings(s)
	if !h.BanBypassMatch("198.51.100.7") || h.BanBypassMatch("203.0.113.9") {
		t.Fatal("the allowlist does not hold the operator's address alone")
	}
	first := banBypassM
	for i := 0; i < 100; i++ {
		h.BanBypassMatch("203.0.113.9")
	}
	if banBypassM != first {
		t.Error("the matcher was built again for the same snapshot")
	}
	// A save publishes a new snapshot: its addresses apply at once.
	s.Nginx.BypassIPs = []string{"203.0.113.9"}
	h.SetSettings(s)
	if !h.BanBypassMatch("203.0.113.9") || h.BanBypassMatch("198.51.100.7") {
		t.Error("a saved change did not reach the allowlist")
	}
	// The ranges loaded again: built again.
	before := banBypassM
	nginxconf.Reload()
	h.BanBypassMatch("203.0.113.9")
	if banBypassM == before {
		t.Error("a reload of the crawler ranges kept the old matcher")
	}
	// And at most banBypassMaxAge apart.
	banBypassBuilt = time.Now().Add(-banBypassMaxAge - time.Second)
	before = banBypassM
	h.BanBypassMatch("203.0.113.9")
	if banBypassM == before {
		t.Error("an old matcher was kept past banBypassMaxAge")
	}
}

func BenchmarkBanBypassMatch(b *testing.B) {
	h := &Handler{}
	h.SetSettings(settings.Settings{})
	for i := 0; i < b.N; i++ {
		h.BanBypassMatch("203.0.113.9")
	}
}
