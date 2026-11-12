package settings

import (
	"os"
	"path/filepath"
	"testing"
)

// A secret neither config.yml nor a sidecar supplies is generated -- once
// for the process.  Load runs inside every settings save and whenever
// config.yml changes on disk, and it used to draw a new value each time:
// where the sidecar could not be written, the first save swapped the admin's
// key and the _bv key under everyone, and the CAPTCHA key (no sidecar at
// all) moved on every load until a save wrote it down.
func TestGeneratedSecretsAreTheSameAtEveryLoad(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(cfg, []byte("server:\n  port: 19477\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	a, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Load(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if a.Secret.CaptchaSecretBase == "" || a.Secret.CaptchaSecretBase != b.Secret.CaptchaSecretBase {
		t.Errorf("captcha_secret_base moved between two loads: %q, %q", a.Secret.CaptchaSecretBase, b.Secret.CaptchaSecretBase)
	}
	// With a sidecar that can be written these two were already stable; this
	// test runs where it cannot be as well (no /var/lib/unmask, not root).
	if a.Secret.AdminSecret == "" || a.Secret.AdminSecret != b.Secret.AdminSecret {
		t.Errorf("admin_secret moved between two loads")
	}
	if a.Secret.BVSecret == "" || a.Secret.BVSecret != b.Secret.BVSecret {
		t.Errorf("bv_secret moved between two loads")
	}

	// A sidecar that cannot be written: the generated key is one per path
	// for the process, not one per call.
	missing := filepath.Join(t.TempDir(), "no-such-dir-is-a-file")
	if err := os.WriteFile(missing, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(missing, "admin_secret") // its parent is a file: MkdirAll fails
	s1, persisted, _ := loadOrCreateSidecarSecret(p)
	s2, _, _ := loadOrCreateSidecarSecret(p)
	if persisted {
		t.Fatal("the sidecar under a file was written")
	}
	if s1 == "" || s1 != s2 {
		t.Errorf("an unpersisted key changed between two calls: %q, %q", s1, s2)
	}
	other, _, _ := loadOrCreateSidecarSecret(filepath.Join(missing, "bv_secret"))
	if other == s1 {
		t.Error("two different sidecars share one generated key")
	}
}
