package settings

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStaleBrowserFreshVsUpgradeDefault: a config that OMITS the global block
// (an existing install upgrading) must load with the tier OFF (defaults() is
// false, so no silent enable on upgrade); a config that carries the config-init
// line loads ON (fresh install opts in).
func TestStaleBrowserFreshVsUpgradeDefault(t *testing.T) {
	dir := t.TempDir()

	// Upgrade case: no global block at all.
	up := filepath.Join(dir, "upgrade.yml")
	os.WriteFile(up, []byte("secret:\n  bv_secret: deadbeef\n"), 0o600)
	if s, err := Load(up); err != nil {
		t.Fatal(err)
	} else if s.Global.StaleBrowserChallenge {
		t.Error("upgrade (no global block) must keep the stale tier OFF")
	}

	// Fresh case: the config-init line.
	fresh := filepath.Join(dir, "fresh.yml")
	os.WriteFile(fresh, []byte("secret:\n  bv_secret: deadbeef\nglobal:\n  stale_browser_challenge: true\n"), 0o600)
	if s, err := Load(fresh); err != nil {
		t.Fatal(err)
	} else if !s.Global.StaleBrowserChallenge {
		t.Error("fresh (config-init line) must have the stale tier ON")
	}
}
