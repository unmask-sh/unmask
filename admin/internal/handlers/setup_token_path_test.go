package handlers

import (
	"os"
	"path/filepath"
	"testing"
)

// TestSetupTokenLegacyFallback pins the /etc -> /var/lib move's upgrade
// contract: a token minted at the pre-0.1.9 path is still readable (an
// install that upgraded mid-setup can finish the wizard), the new path wins
// when both exist, and completion removes both files.
func TestSetupTokenLegacyFallback(t *testing.T) {
	dir := t.TempDir()
	oldP, oldL := SetupTokenPath, legacySetupTokenPath
	SetupTokenPath = filepath.Join(dir, "state", ".setup-token")
	legacySetupTokenPath = filepath.Join(dir, "etc", ".setup-token")
	t.Cleanup(func() { SetupTokenPath, legacySetupTokenPath = oldP, oldL })

	if err := os.MkdirAll(filepath.Dir(legacySetupTokenPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(legacySetupTokenPath, []byte("tok-legacy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readSetupToken(); got != "tok-legacy" {
		t.Errorf("legacy-only: readSetupToken() = %q, want tok-legacy", got)
	}

	if err := os.MkdirAll(filepath.Dir(SetupTokenPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(SetupTokenPath, []byte("tok-new\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := readSetupToken(); got != "tok-new" {
		t.Errorf("both present: readSetupToken() = %q, want tok-new (primary wins)", got)
	}

	removeSetupToken()
	for _, p := range []string{SetupTokenPath, legacySetupTokenPath} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Errorf("removeSetupToken must delete %s (stat err=%v)", p, err)
		}
	}
}

// TestSetSetupTokenDir pins the relocation rules: the standard /etc/unmask
// config dir keeps the /var/lib default (a package install must not drag the
// token back into /etc), while a custom config dir moves the token next to
// its config AND drops the legacy fallback (a second instance must never
// read the shared /etc token).
func TestSetSetupTokenDir(t *testing.T) {
	oldP, oldL := SetupTokenPath, legacySetupTokenPath
	t.Cleanup(func() { SetupTokenPath, legacySetupTokenPath = oldP, oldL })

	SetupTokenPath = "/var/lib/unmask/.setup-token"
	legacySetupTokenPath = "/etc/unmask/.setup-token"

	SetSetupTokenDir("")
	if SetupTokenPath != "/var/lib/unmask/.setup-token" {
		t.Errorf("empty dir must keep the default, got %s", SetupTokenPath)
	}
	SetSetupTokenDir("/etc/unmask")
	if SetupTokenPath != "/var/lib/unmask/.setup-token" {
		t.Errorf("standard config dir must keep the /var/lib default, got %s", SetupTokenPath)
	}
	if legacySetupTokenPath == "" {
		t.Error("standard config dir must keep the legacy fallback")
	}

	SetSetupTokenDir("/opt/unmask")
	if want := "/opt/unmask/.setup-token"; SetupTokenPath != want {
		t.Errorf("custom dir: SetupTokenPath = %s, want %s", SetupTokenPath, want)
	}
	if legacySetupTokenPath != "" {
		t.Error("custom dir must clear the legacy fallback")
	}
}
