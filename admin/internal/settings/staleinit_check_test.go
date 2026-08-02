package settings

import (
	"os"
	"path/filepath"
	"testing"
)

// TestStaleBrowserDefaultsOff: the stale-browser tier escalates a UA pinned to
// an outdated Chrome major to a CAPTCHA.  That signal is shared with real
// visitors who simply have not updated, so it cannot be on before an operator
// has looked at what it would catch on their own traffic -- a fresh install
// would otherwise CAPTCHA genuine people on a site that has never seen a bot.
// Off for a fresh install and off for an upgrade; the UA-filter tab is where it
// gets turned on.
func TestStaleBrowserDefaultsOff(t *testing.T) {
	dir := t.TempDir()

	// Upgrade case: no global block at all.
	up := filepath.Join(dir, "upgrade.yml")
	os.WriteFile(up, []byte("secret:\n  bv_secret: deadbeef\n"), 0o600)
	if s, err := Load(up); err != nil {
		t.Fatal(err)
	} else if s.Global.StaleBrowserChallenge {
		t.Error("upgrade (no global block) must keep the stale tier OFF")
	}

	// Fresh case: the line config-init writes.
	fresh := filepath.Join(dir, "fresh.yml")
	os.WriteFile(fresh, []byte("secret:\n  bv_secret: deadbeef\nglobal:\n  stale_browser_challenge: false\n"), 0o600)
	if s, err := Load(fresh); err != nil {
		t.Fatal(err)
	} else if s.Global.StaleBrowserChallenge {
		t.Error("fresh install must have the stale tier OFF")
	}
}

// TestStaleBrowserHonoursExplicitOn: turning it on has to survive a load, or
// the UA-filter toggle would silently do nothing.
func TestStaleBrowserHonoursExplicitOn(t *testing.T) {
	p := filepath.Join(t.TempDir(), "on.yml")
	os.WriteFile(p, []byte("secret:\n  bv_secret: deadbeef\nglobal:\n  stale_browser_challenge: true\n"), 0o600)
	if s, err := Load(p); err != nil {
		t.Fatal(err)
	} else if !s.Global.StaleBrowserChallenge {
		t.Error("an explicit true must load as ON")
	}
}
